// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protected caller operation custody. Q persists the exact M before M may
//! cross. M and cancellation R consume one non-reusable per-key guard. Restart
//! resolves original authority; it never reconstructs a native slot or a send.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use busbar_contract::persistence::{
    Address, Candidate, Decision, Durability, ExpectedValue, Mutation, Predicate,
    PreparedCandidate, CANDIDATE_VERSION,
};
use busbar_contract::Secret;

use crate::connections::grant::{GrantKey, ValidatedGrantChange};
use crate::governance::at_rest::CallerProtectedRecords;

use super::boot_identity::WriterRetirements;
use super::commit::SubmitResult;
use super::facade::{CoreStore, DomainOwner, LogicalClaim, LogicalId};
use super::scoped::{self, ScopedStore};

mod codec;
mod recovery;

const INSTANCE: &str = "caller-connections";
const GRANT: &str = "grant-v1";
const GUARD: &str = "grant-guard-v1";
const INTENT: &str = "grant-intent-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Budget,
    Overflow,
    Invalid,
    Corrupt,
    Unavailable,
    Pending,
    Authority,
    NotReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Applied,
    NoEffect,
    Pending,
    Reconcile,
    Superseded,
}
impl Outcome {
    #[cfg(test)]
    pub(crate) fn applied(self) -> bool {
        self == Self::Applied
    }
}

struct Prepared {
    header: codec::Header,
    key: Vec<u8>,
    pending: Secret<Vec<u8>>,
    intent: Secret<Vec<u8>>,
    prepare: PreparedCandidate,
    main: PreparedCandidate,
}

struct Operation {
    origin: busbar_contract::persistence::AttemptId,
    foreground: Weak<()>,
    state: Mutex<OperationState>,
    driving: tokio::sync::Mutex<()>,
}
#[derive(Default)]
struct OperationState {
    key: Option<Vec<u8>>,
    prepared: Option<Arc<Prepared>>,
    q_applied: bool,
    outcome: Option<Outcome>,
    cancel: Option<PreparedCandidate>,
}

struct State {
    operations: HashMap<[u8; 16], Arc<Operation>>,
    ready: bool,
}

pub(crate) struct CallerIntents {
    store: Arc<CoreStore>,
    records: Arc<CallerProtectedRecords>,
    scoped: ScopedStore,
    domain: DomainOwner,
    retirements: Arc<WriterRetirements>,
    state: Mutex<State>,
    recovery: tokio::sync::Mutex<recovery::ScanState>,
}

/// One bounded reservation, allocated by the actual attachment. Its numeric
/// identity can bind a Minting row but cannot recreate this capability.
pub(crate) struct OperationDraft {
    owner: Arc<CallerIntents>,
    operation: Arc<Operation>,
    token: Arc<()>,
}

/// Non-Clone foreground custody. Only drive on this capability can return its
/// Applied result once; maintenance never constructs one.
pub(crate) struct PreparedGrantOperation {
    draft: OperationDraft,
    delivered: bool,
}

struct Observed {
    grant: Option<Secret<Vec<u8>>>,
    guard: Option<Secret<Vec<u8>>>,
    intent: Option<Secret<Vec<u8>>>,
    slot: Option<(codec::Header, codec::Phase)>,
}

fn next_generation(previous: Option<u64>) -> Result<u64, Error> {
    previous.unwrap_or(0).checked_add(1).ok_or(Error::Overflow)
}

impl CallerIntents {
    pub(crate) fn new(
        store: Arc<CoreStore>,
        records: Arc<CallerProtectedRecords>,
        retirements: Arc<WriterRetirements>,
    ) -> Result<Arc<Self>, Error> {
        if store.info().durability == Durability::Ephemeral {
            return Err(Error::Authority);
        }
        let scoped = ScopedStore::host_private(
            store.clone(),
            INSTANCE,
            [GRANT, GUARD, INTENT].map(str::to_owned),
        )
        .map_err(|_| Error::Authority)?;
        Ok(Arc::new(Self {
            domain: DomainOwner::new(store.clone()),
            store,
            records,
            scoped,
            retirements,
            state: Mutex::new(State {
                operations: HashMap::new(),
                ready: false,
            }),
            recovery: tokio::sync::Mutex::new(recovery::ScanState::default()),
        }))
    }

    pub(crate) fn begin_operation(self: &Arc<Self>) -> Result<OperationDraft, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Corrupt)?;
        if !state.ready {
            return Err(Error::NotReady);
        }
        if state.operations.len() >= self.store.limits().pending_operations {
            return Err(Error::Budget);
        }
        let origin = self.store.next_id().map_err(|_| Error::Authority)?;
        let token = Arc::new(());
        let operation = Arc::new(Operation {
            origin,
            foreground: Arc::downgrade(&token),
            state: Mutex::new(OperationState::default()),
            driving: tokio::sync::Mutex::new(()),
        });
        state.operations.try_reserve(1).map_err(|_| Error::Budget)?;
        if state.operations.contains_key(&origin.operation) {
            return Err(Error::Corrupt);
        }
        state.operations.insert(origin.operation, operation.clone());
        Ok(OperationDraft {
            owner: self.clone(),
            operation,
            token,
        })
    }

    pub(crate) async fn read_current(
        &self,
        key: &GrantKey,
    ) -> Result<Option<Secret<Vec<u8>>>, Error> {
        {
            let state = self.state.lock().map_err(|_| Error::Corrupt)?;
            if !state.ready {
                return Err(Error::NotReady);
            }
            for operation in state.operations.values() {
                let held = operation.state.lock().map_err(|_| Error::Corrupt)?;
                if held.key.as_deref() == Some(key.encoded()) && held.outcome.is_none() {
                    return Err(Error::Pending);
                }
            }
        }
        let current = self.observe(key.encoded()).await?;
        if current
            .slot
            .as_ref()
            .is_some_and(|(_, phase)| *phase == codec::Phase::Pending)
        {
            return Err(Error::Pending);
        }
        Ok(current.grant)
    }

    fn address(&self, schema: &str, key: &[u8]) -> Result<Address, Error> {
        scoped::migration_address(true, INSTANCE, schema, key).map_err(|_| Error::Invalid)
    }

    async fn observe(&self, key: &[u8]) -> Result<Observed, Error> {
        if key.len() > self.store.limits().scan_bytes.saturating_sub(4096) / 32 {
            return Err(Error::Budget);
        }
        let typed_key = GrantKey::decode(key).map_err(|_| Error::Corrupt)?;
        let mut values = self
            .scoped
            .read(&[(GRANT, key), (GUARD, key), (INTENT, key)])
            .await
            .map_err(|_| Error::Unavailable)?;
        if values.len() != 3 {
            return Err(Error::Corrupt);
        }
        // Leave separate quarters for ciphertext, opened snapshot, decoded
        // candidate/validation scratch and grant/terminal authentication work.
        let retained = values
            .iter()
            .flatten()
            .try_fold(0usize, |n, v| {
                n.checked_add(v.expose(&crate::seal::lend()).len())
            })
            .ok_or(Error::Overflow)?;
        if retained > self.store.limits().scan_bytes / 4 {
            return Err(Error::Budget);
        }
        let intent = values.pop().ok_or(Error::Corrupt)?;
        let guard = values.pop().ok_or(Error::Corrupt)?;
        let grant = values.pop().ok_or(Error::Corrupt)?;
        let slot = match (&guard, &intent) {
            (None, None) if grant.is_none() => None,
            (Some(guard), Some(intent)) => Some(codec::validate_pair(self, key, guard, intent)?),
            _ => return Err(Error::Corrupt),
        };
        if let Some((header, phase)) = &slot {
            let expected = if *phase == codec::Phase::Applied {
                Some(header.after)
            } else {
                header.before
            };
            let records = crate::connections::grant::GrantRecords::new(
                self.records.clone(),
                self.store.info().dataset.0,
                self.store.info().atomic_domain,
            )
            .map_err(|_| Error::Corrupt)?;
            let found = grant
                .as_ref()
                .map(|row| {
                    records
                        .decode(&typed_key, row)
                        .map(|snapshot| snapshot.version())
                })
                .transpose()
                .map_err(|_| Error::Corrupt)?;
            if found != expected {
                return Err(Error::Corrupt);
            }
        }
        Ok(Observed {
            grant,
            guard,
            intent,
            slot,
        })
    }

    fn make_candidate(
        &self,
        id: busbar_contract::persistence::AttemptId,
        request: scoped::Request,
    ) -> Result<PreparedCandidate, Error> {
        let rows = self
            .scoped
            .prepare_participant(&request, self.store.limits().scan_bytes)
            .map_err(|_| Error::Budget)?;
        let (predicates, mutations) = rows.into_parts(&self.store).map_err(|_| Error::Authority)?;
        PreparedCandidate::new(Candidate {
            id,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)
    }

    async fn submit(&self, candidate: &PreparedCandidate) -> Result<SubmitResult, Error> {
        let call = self.domain.call();
        let namespace = self.address(INTENT, b"")?.namespace;
        match self
            .store
            .claim_logical_owned(
                LogicalId {
                    namespace,
                    operation: candidate.candidate().id.operation,
                },
                candidate.fingerprint(),
                Some(&call),
            )
            .map_err(|_| Error::Authority)?
        {
            LogicalClaim::Prepare(permit) => permit.submit(candidate.clone()).await,
            LogicalClaim::Retained(id) => call.retry(id).await,
            LogicalClaim::Busy => return Ok(SubmitResult::Busy),
        }
        .map(|submission| submission.result)
        .map_err(|_| Error::Unavailable)
    }

    async fn classify(&self, prepared: &Prepared) -> Result<Outcome, Error> {
        let observed = self.observe(&prepared.key).await?;
        let Some((header, phase)) = observed.slot else {
            return Err(Error::Corrupt);
        };
        if header != prepared.header {
            return Ok(Outcome::Superseded);
        }
        Ok(match phase {
            codec::Phase::Pending => Outcome::Pending,
            codec::Phase::Applied => Outcome::Applied,
            codec::Phase::NoEffect => Outcome::NoEffect,
        })
    }

    async fn drive(&self, operation: &Operation, abandoned: bool) -> Result<Outcome, Error> {
        let _driver = operation.driving.lock().await;
        let (prepared, q_applied, outcome) = {
            let state = operation.state.lock().map_err(|_| Error::Corrupt)?;
            (
                state.prepared.clone().ok_or(Error::Invalid)?,
                state.q_applied,
                state.outcome,
            )
        };
        if let Some(outcome) = outcome {
            return Ok(outcome);
        }
        if !q_applied {
            let answer = self.submit(&prepared.prepare).await?;
            match answer {
                SubmitResult::Decided(decision) if matches!(*decision, Decision::Applied(_)) => {}
                SubmitResult::Decided(decision)
                    if matches!(*decision, Decision::ConditionConflict) =>
                {
                    let current = self.observe(&prepared.key).await?;
                    if current.guard.as_ref() != Some(&prepared.pending)
                        || current.intent.as_ref() != Some(&prepared.intent)
                    {
                        return self.finish(operation, Outcome::Superseded);
                    }
                }
                SubmitResult::NoEffect(_) => return self.finish(operation, Outcome::NoEffect),
                SubmitResult::Reconcile => return Ok(Outcome::Reconcile),
                SubmitResult::Uncertain | SubmitResult::Busy => return Ok(Outcome::Pending),
                _ => return Ok(Outcome::Reconcile),
            }
            operation
                .state
                .lock()
                .map_err(|_| Error::Corrupt)?
                .q_applied = true;
        }
        if abandoned {
            return self.cancel_local(operation, &prepared).await;
        }
        let result = self.submit(&prepared.main).await?;
        let outcome = match result {
            SubmitResult::Decided(decision)
                if matches!(
                    *decision,
                    Decision::Applied(_) | Decision::ConditionConflict
                ) =>
            {
                self.classify(&prepared).await?
            }
            SubmitResult::NoEffect(_) => return self.cancel_local(operation, &prepared).await,
            SubmitResult::Reconcile => Outcome::Reconcile,
            SubmitResult::Uncertain | SubmitResult::Busy => Outcome::Pending,
            _ => Outcome::Reconcile,
        };
        self.finish(operation, outcome)
    }

    fn finish(&self, operation: &Operation, outcome: Outcome) -> Result<Outcome, Error> {
        if !matches!(outcome, Outcome::Pending | Outcome::Reconcile) {
            operation.state.lock().map_err(|_| Error::Corrupt)?.outcome = Some(outcome);
        }
        Ok(outcome)
    }
}

impl OperationDraft {
    pub(crate) fn id(&self) -> [u8; 16] {
        self.operation.origin.operation
    }

    fn bind_key(&self, key: &[u8]) -> Result<(), Error> {
        if key.len() > self.owner.store.limits().scan_bytes.saturating_sub(4096) / 32 {
            return Err(Error::Budget);
        }
        let state = self.owner.state.lock().map_err(|_| Error::Corrupt)?;
        for existing in state.operations.values() {
            if Arc::ptr_eq(existing, &self.operation) {
                continue;
            }
            let held = existing.state.lock().map_err(|_| Error::Corrupt)?;
            if held.key.as_deref() == Some(key) && held.outcome.is_none() {
                return Err(Error::Pending);
            }
        }
        let mut held = self.operation.state.lock().map_err(|_| Error::Corrupt)?;
        if let Some(existing) = &held.key {
            if existing != key {
                return Err(Error::Authority);
            }
        } else {
            held.key = Some(key.to_vec());
        }
        Ok(())
    }

    /// Explicit revoke binds its local key fence before the first read await.
    /// The same draft must prepare the resulting change; it cannot switch keys.
    pub(crate) async fn read_current(
        &mut self,
        key: &GrantKey,
    ) -> Result<Option<Secret<Vec<u8>>>, Error> {
        self.bind_key(key.encoded())?;
        let current = self.owner.observe(key.encoded()).await?;
        if current
            .slot
            .is_some_and(|(_, phase)| phase == codec::Phase::Pending)
        {
            return Err(Error::Pending);
        }
        Ok(current.grant)
    }

    pub(crate) async fn prepare(
        self,
        change: ValidatedGrantChange,
    ) -> Result<PreparedGrantOperation, Error> {
        let key = change.encoded_key();
        let seal = crate::seal::lend();
        // Conservative peak budget: all retained Q/M/R, codec/envelope scratch,
        // descriptor vectors and row copies. Reserve one bounded owner slot; no
        // caller-controlled payload is copied before this aggregate check.
        let input = key
            .len()
            .checked_add(change.previous().map_or(0, |v| v.expose(&seal).len()))
            .and_then(|n| n.checked_add(change.successor().expose(&seal).len()))
            .ok_or(Error::Overflow)?;
        let peak = input
            .checked_mul(32)
            .and_then(|n| n.checked_add(4096))
            .ok_or(Error::Overflow)?;
        if peak > self.owner.store.limits().scan_bytes {
            return Err(Error::Budget);
        }
        self.bind_key(key)?;
        let current = self.owner.observe(key).await?;
        if current.grant.as_ref() != change.previous() {
            return Err(Error::Invalid);
        }
        if current
            .slot
            .as_ref()
            .is_some_and(|(_, p)| *p == codec::Phase::Pending)
        {
            return Err(Error::Pending);
        }
        let generation = next_generation(current.slot.as_ref().map(|(h, _)| h.generation))?;
        let header = codec::Header::for_change(self.operation.origin, generation, &change);
        let pending = codec::seal_guard(&self.owner, key, &header, codec::Phase::Pending)?;
        let terminal = codec::seal_guard(&self.owner, key, &header, codec::Phase::Applied)?;
        let applied = codec::seal_terminal(&self.owner, key, &header, codec::Phase::Applied)?;
        let main = self.owner.make_candidate(
            self.operation.origin,
            scoped::Request {
                op_id: self.id(),
                predicates: vec![
                    predicate(GUARD, key, Some(&pending)),
                    predicate(GRANT, key, change.previous()),
                ],
                mutations: vec![
                    put(GRANT, key, change.successor()),
                    put(GUARD, key, &terminal),
                    put(INTENT, key, &applied),
                ],
            },
        )?;
        let intent = codec::seal_prepared(&self.owner, key, &header, &main)?;
        let prepare = self.owner.make_candidate(
            self.owner.store.next_id().map_err(|_| Error::Authority)?,
            scoped::Request {
                op_id: self.id(),
                predicates: vec![
                    predicate(GUARD, key, current.guard.as_ref()),
                    predicate(INTENT, key, current.intent.as_ref()),
                    predicate(GRANT, key, change.previous()),
                ],
                mutations: vec![put(GUARD, key, &pending), put(INTENT, key, &intent)],
            },
        )?;
        self.operation
            .state
            .lock()
            .map_err(|_| Error::Corrupt)?
            .prepared = Some(Arc::new(Prepared {
            header,
            key: key.to_vec(),
            pending,
            intent,
            prepare,
            main,
        }));
        Ok(PreparedGrantOperation {
            draft: self,
            delivered: false,
        })
    }
}

impl PreparedGrantOperation {
    pub(crate) async fn drive(&mut self) -> Result<Outcome, Error> {
        if self.delivered {
            return Ok(Outcome::Superseded);
        }
        let outcome = self.draft.owner.drive(&self.draft.operation, false).await?;
        if !matches!(outcome, Outcome::Pending | Outcome::Reconcile) {
            self.delivered = true;
        }
        Ok(outcome)
    }
}

impl Drop for OperationDraft {
    fn drop(&mut self) {
        // The token is held through every crossing. Only entirely unprepared or
        // definitively settled work may leave custody when its waiter disappears.
        let _ = &self.token;
        if let Ok(mut state) = self.owner.state.lock() {
            if let Ok(operation) = self.operation.state.lock() {
                if operation.prepared.is_none() || operation.outcome.is_some() {
                    state.operations.remove(&self.id());
                }
            }
        }
    }
}

fn predicate(schema: &str, key: &[u8], value: Option<&Secret<Vec<u8>>>) -> scoped::Predicate {
    scoped::Predicate {
        schema: schema.into(),
        key: key.to_vec(),
        expected: value.map_or(scoped::Expected::Absent, |v| {
            scoped::Expected::Exact(v.clone())
        }),
    }
}
fn put(schema: &str, key: &[u8], value: &Secret<Vec<u8>>) -> scoped::Mutation {
    scoped::Mutation::Put {
        schema: schema.into(),
        key: key.to_vec(),
        value: value.clone(),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod fixture;
