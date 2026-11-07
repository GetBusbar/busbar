// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-owned single-use claims. Expiry is checked at native serialization, not
//! against a caller's clock before a queued database command executes.

use sha2::{Digest, Sha256};
use std::sync::Arc;

use busbar_contract::{
    persistence::{
        Address, Candidate, Decision, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, Scan, TimeGuard, CANDIDATE_VERSION,
    },
    Secret,
};

use super::{
    commit::SubmitResult,
    facade::{AccessError, CoreStore, LogicalClaim, LogicalId, PendingId, Submission},
    keys, partition,
};

const OWNER: NamespaceId = NamespaceId(*b"busbar.claims1\0\0");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Corrupt,
    Invalid,
    Contended,
    Access(AccessError),
    Backend(Failure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Claimed,
    AlreadyClaimed,
    Expired,
    Pending(PendingClaim),
    Reconcile(PendingClaim),
    Busy(PendingClaim),
}

/// The original expiry travels with custody; a retry cannot supply a new deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingClaim {
    id: PendingId,
    expires_at: u64,
}

fn claim_address(owner: &str, kind: &str, token: &str) -> Result<Address, Error> {
    Ok(Address {
        namespace: partition::namespace(OWNER, &[owner.as_bytes(), kind.as_bytes()]).0,
        key: keys::framed(
            b'C',
            &[
                &OWNER.0,
                owner.as_bytes(),
                kind.as_bytes(),
                token.as_bytes(),
            ],
        )
        .map_err(|_| Error::Invalid)?,
    })
}
fn claim_value(expires_at: u64) -> Secret<Vec<u8>> {
    let mut value = vec![1];
    value.extend_from_slice(&expires_at.to_be_bytes());
    Secret::new(value)
}
type MigrationRows = Vec<(Address, Secret<Vec<u8>>)>;

pub(super) fn migration_rows(
    owner: &str,
    kind: &str,
    token: &str,
    expires_at: u64,
) -> Result<MigrationRows, Error> {
    Ok(vec![(
        claim_address(owner, kind, token)?,
        claim_value(expires_at),
    )])
}
pub(super) fn migration_authorizes(owner: &str, kind: &str, address: &Address) -> bool {
    let Ok(parts) = keys::components(&address.key, b'C') else {
        return false;
    };
    if parts.len() != 4
        || parts[0] != OWNER.0
        || parts[1] != owner.as_bytes()
        || parts[2] != kind.as_bytes()
    {
        return false;
    }
    let Ok(token) = std::str::from_utf8(parts[3]) else {
        return false;
    };
    claim_address(owner, kind, token).is_ok_and(|expected| expected == *address)
}

/// Host-only authority binding. The caller authorizes the owner and claim kind;
/// neither strings nor physical keys are accepted directly from plugin input.
pub(crate) struct Claims<'a> {
    store: &'a CoreStore,
    owner: &'a str,
    kind: &'a str,
}

impl<'a> Claims<'a> {
    pub(crate) fn authorized(store: &'a CoreStore, owner: &'a str, kind: &'a str) -> Self {
        Self { store, owner, kind }
    }

    /// Start a fresh maintenance pass at the beginning of this authorized scope.
    /// The owner schedules calls;
    /// this cursor does no background work and is not an authorization decision.
    pub(crate) fn sweep(&self) -> Result<Sweep<'a>, Error> {
        build_sweep(SweepStore::Borrowed(self.store), self.owner, self.kind)
    }

    fn address(&self, token: &str) -> Result<Address, Error> {
        claim_address(self.owner, self.kind, token)
    }

    /// The existing expiry boundary is inclusive: expiry == native now is live.
    /// A lapsed claim may be replaced, but only while both old and new temporal
    /// conditions still hold in the same transaction as the replacement.
    pub(crate) async fn redeem(&self, token: &str, expires_at: u64) -> Result<Outcome, Error> {
        let at = self.address(token)?;
        let mut hash = Sha256::new();
        hash.update(b"busbar.claim-attempt.v1");
        for part in [
            self.owner.as_bytes(),
            self.kind.as_bytes(),
            token.as_bytes(),
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.update(expires_at.to_be_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        let operation = digest[..16].try_into().map_err(|_| Error::Invalid)?;
        for _ in 0..=self.store.limits().conflict_retries {
            // Bind planning to the logical claim before any native crossing. A
            // cancelled submit is rediscovered by the same owner/kind/token/expiry.
            let permit = match self
                .store
                .claim_logical(
                    LogicalId {
                        namespace: OWNER.0,
                        operation,
                    },
                    digest,
                )
                .map_err(Error::Access)?
            {
                LogicalClaim::Prepare(permit) => permit,
                LogicalClaim::Retained(id) => {
                    return self.retry(PendingClaim { id, expires_at }).await
                }
                LogicalClaim::Busy => return Err(Error::Contended),
            };
            let time = TimeGuard {
                not_before: None,
                before: expires_at.checked_add(1),
            };
            let observed = self
                .store
                .backend()
                .read(Arc::new(Read {
                    dataset: self.store.info().dataset,
                    addresses: vec![at.clone()],
                    time: Some(time),
                }))
                .await
                .map_err(Error::Backend)?;
            let (observed_at, mut values) = match observed {
                ReadResult::Values {
                    observed_at,
                    values,
                } => (observed_at, values),
                ReadResult::TimeGuardFailed { observed_at } => {
                    if observed_at.authority != self.store.info().clock_authority
                        || time.permits(observed_at.unix_seconds)
                    {
                        return Err(Error::Corrupt);
                    }
                    return Ok(Outcome::Expired);
                }
            };
            if observed_at.authority != self.store.info().clock_authority
                || !time.permits(observed_at.unix_seconds)
                || values.len() != 1
            {
                return Err(Error::Corrupt);
            }
            let previous = values.pop().ok_or(Error::Corrupt)?;
            let lower = if let Some(value) = &previous {
                let bytes = value.expose(&crate::seal::lend());
                if bytes.len() != 9 || bytes[0] != 1 {
                    return Err(Error::Corrupt);
                }
                let expiry = u64::from_be_bytes(bytes[1..].try_into().map_err(|_| Error::Corrupt)?);
                if expiry >= observed_at.unix_seconds {
                    return Ok(Outcome::AlreadyClaimed);
                }
                Some(expiry.checked_add(1).ok_or(Error::Corrupt)?)
            } else {
                None
            };
            let candidate = PreparedCandidate::new(Candidate {
                id: self.store.next_id().map_err(Error::Access)?,
                codec: CANDIDATE_VERSION,
                predicates: vec![Predicate {
                    address: at.clone(),
                    expected: previous.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
                }],
                mutations: vec![Mutation::Put {
                    address: at.clone(),
                    value: claim_value(expires_at),
                }],
                time: Some(TimeGuard {
                    not_before: lower,
                    ..time
                }),
                result: Secret::new(vec![1]),
            })
            .map_err(|_| Error::Invalid)?;
            if let Some(outcome) = outcome(
                permit.submit(candidate).await.map_err(Error::Access)?,
                expires_at,
            )? {
                return Ok(outcome);
            }
        }
        Err(Error::Contended)
    }

    /// Resolves only the original attempt. A failed guard after an earlier unknown
    /// is reconciliation, not proof that the token was never consumed.
    pub(crate) async fn retry(&self, claim: PendingClaim) -> Result<Outcome, Error> {
        outcome(
            self.store.retry(claim.id).await.map_err(Error::Access)?,
            claim.expires_at,
        )?
        .ok_or(Error::Contended)
    }
}

/// One pass uses advancing keys, not a pinned scan generation: deleting a page
/// itself changes membership. Inserts behind the cursor belong to the next pass.
/// Live rows cannot repeatedly hide expired rows farther along the key range.
pub struct Sweep<'a> {
    store: SweepStore<'a>,
    state: SweepState,
}

pub(super) struct SweepState {
    namespace: NamespaceId,
    prefix: Vec<u8>,
    after: Option<Vec<u8>>,
    complete: bool,
    pending: Option<SweepPage>,
}
impl SweepState {
    fn new(owner: &str, kind: &str) -> Result<Self, Error> {
        Ok(Self {
            namespace: partition::namespace(OWNER, &[owner.as_bytes(), kind.as_bytes()]),
            prefix: keys::framed(b'C', &[&OWNER.0, owner.as_bytes(), kind.as_bytes()])
                .map_err(|_| Error::Invalid)?,
            after: None,
            complete: false,
            pending: None,
        })
    }
}

enum SweepStore<'a> {
    Borrowed(&'a CoreStore),
    Owned(Arc<CoreStore>),
}
impl std::ops::Deref for SweepStore<'_> {
    type Target = CoreStore;
    fn deref(&self) -> &CoreStore {
        match self {
            Self::Borrowed(store) => store,
            Self::Owned(store) => store,
        }
    }
}
fn build_sweep<'a>(store: SweepStore<'a>, owner: &str, kind: &str) -> Result<Sweep<'a>, Error> {
    Ok(Sweep {
        store,
        state: SweepState::new(owner, kind)?,
    })
}
pub(super) fn owned_sweep(
    store: Arc<CoreStore>,
    owner: &str,
    kind: &str,
) -> Result<Sweep<'static>, Error> {
    build_sweep(SweepStore::Owned(store), owner, kind)
}

struct SweepPage {
    candidate: PreparedCandidate,
    registered: bool,
    next: Option<Vec<u8>>,
    scanned: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepOutcome {
    Page {
        scanned: usize,
        deleted: usize,
        complete: bool,
    },
    Complete,
    /// The page changed concurrently; it will be reconsidered on the next pass.
    Contended,
    ClockRewound,
    Pending(PendingId),
    Reconcile(PendingId),
    Busy(PendingId),
}

impl Sweep<'_> {
    /// Advance one bounded page while retaining original pending custody.
    pub async fn advance(&mut self) -> Result<SweepOutcome, Error> {
        self.state.advance(&self.store).await
    }
}

impl SweepState {
    /// At most one bounded SCAN, one coherent READ and one COMMIT per call.
    /// An unresolved page is retained before the crossing (including cancellation)
    /// and subsequent calls submit only its exact original candidate.
    async fn advance(&mut self, store: &CoreStore) -> Result<SweepOutcome, Error> {
        if self.complete {
            return Ok(SweepOutcome::Complete);
        }
        if self.pending.is_none() {
            let limits = store.limits();
            let page = store
                .backend()
                .scan(Arc::new(Scan {
                    dataset: store.info().dataset,
                    namespace: self.namespace,
                    prefix: self.prefix.clone(),
                    after: self.after.clone(),
                    generation: None,
                    // Discovery only: the subsequent coherent read and exact
                    // delete predicates establish authority, not scan membership.
                    allow_change: true,
                    max_items: limits.scan_items,
                    max_bytes: limits.scan_bytes,
                }))
                .await
                .map_err(Error::Backend)?;
            if page.rows.len() > limits.scan_items {
                return Err(Error::Corrupt);
            }
            let mut previous = self.after.as_ref();
            let mut bytes = 0usize;
            for (address, value) in &page.rows {
                bytes = bytes
                    .checked_add(address.key.len())
                    .and_then(|n| n.checked_add(value.expose(&crate::seal::lend()).len()))
                    .ok_or(Error::Corrupt)?;
                if bytes > limits.scan_bytes {
                    return Err(Error::Corrupt);
                }
                if address.namespace != self.namespace.0
                    || !address.key.starts_with(&self.prefix)
                    || previous.is_some_and(|previous| previous >= &address.key)
                    || keys::components(&address.key, b'C')
                        .map_err(|_| Error::Corrupt)?
                        .len()
                        != 4
                {
                    return Err(Error::Corrupt);
                }
                previous = Some(&address.key);
            }
            if page
                .next
                .as_ref()
                .is_some_and(|next| page.rows.last().map(|(address, _)| &address.key) != Some(next))
            {
                return Err(Error::Corrupt);
            }
            let scanned = page.rows.len();
            if scanned == 0 {
                self.complete = true;
                return Ok(SweepOutcome::Complete);
            }
            // SCAN has no time observation. Re-read this bounded address group
            // so expiry and current values share the native serialization clock.
            let addresses: Vec<_> = page.rows.into_iter().map(|(address, _)| address).collect();
            let read = store
                .backend()
                .read(Arc::new(Read {
                    dataset: store.info().dataset,
                    addresses: addresses.clone(),
                    time: None,
                }))
                .await
                .map_err(Error::Backend)?;
            let ReadResult::Values {
                observed_at,
                values,
            } = read
            else {
                return Err(Error::Corrupt);
            };
            if observed_at.authority != store.info().clock_authority || values.len() != scanned {
                return Err(Error::Corrupt);
            }
            let mut predicates = Vec::new();
            let mut mutations = Vec::new();
            for (address, value) in addresses.into_iter().zip(values) {
                let Some(value) = value else { continue };
                let encoded = value.expose(&crate::seal::lend());
                if encoded.len() != 9 || encoded[0] != 1 {
                    return Err(Error::Corrupt);
                }
                let expiry =
                    u64::from_be_bytes(encoded[1..].try_into().map_err(|_| Error::Corrupt)?);
                if expiry < observed_at.unix_seconds {
                    predicates.push(Predicate {
                        address: address.clone(),
                        expected: ExpectedValue::Exact(value),
                    });
                    mutations.push(Mutation::Delete(address));
                }
            }
            if mutations.is_empty() {
                self.complete = page.next.is_none();
                self.after = page.next;
                return Ok(SweepOutcome::Page {
                    scanned,
                    deleted: 0,
                    complete: self.complete,
                });
            }
            self.pending = Some(SweepPage {
                candidate: PreparedCandidate::new(Candidate {
                    id: store.next_id().map_err(Error::Access)?,
                    codec: CANDIDATE_VERSION,
                    predicates,
                    mutations,
                    // Every selected expiry is strictly less than this native
                    // observation. Refuse any rewind before deleting live bytes.
                    time: Some(TimeGuard {
                        not_before: Some(observed_at.unix_seconds),
                        before: None,
                    }),
                    result: Secret::new(vec![1]),
                })
                .map_err(|_| Error::Invalid)?,
                next: page.next,
                scanned,
                registered: false,
            });
        }
        let pending = self.pending.as_mut().ok_or(Error::Corrupt)?;
        let submission = if pending.registered {
            store
                .retry(PendingId(pending.candidate.candidate().id.operation))
                .await
                .map_err(Error::Access)?
        } else {
            // Registration is synchronous before submit's first native await.
            // Set custody first so a cancelled waiter resumes through retry,
            // which remains available after shutdown closes new admission.
            pending.registered = true;
            match store.submit(pending.candidate.clone()).await {
                Ok(submission) => submission,
                Err(error) => {
                    if matches!(error, AccessError::Closed | AccessError::Authority) {
                        // Registration refused before a crossing. A promoted
                        // execution epoch cannot admit this old preparation;
                        // reconsider the page under current authority next tick.
                        self.pending = None;
                    } else if error == AccessError::Overloaded {
                        pending.registered = false;
                    }
                    return Err(Error::Access(error));
                }
            }
        };
        match submission.result {
            SubmitResult::Uncertain => Ok(SweepOutcome::Pending(submission.id)),
            SubmitResult::Reconcile => Ok(SweepOutcome::Reconcile(submission.id)),
            SubmitResult::Busy => Ok(SweepOutcome::Busy(submission.id)),
            SubmitResult::NoEffect(failure) => {
                self.pending = None;
                Err(Error::Backend(failure))
            }
            SubmitResult::Decided(decision) => {
                let pending = self.pending.take().ok_or(Error::Corrupt)?;
                match decision.as_ref() {
                    Decision::Applied(_) | Decision::ConditionConflict => {
                        self.complete = pending.next.is_none();
                        self.after = pending.next;
                        if matches!(decision.as_ref(), Decision::ConditionConflict) {
                            Ok(SweepOutcome::Contended)
                        } else {
                            Ok(SweepOutcome::Page {
                                scanned: pending.scanned,
                                deleted: pending.candidate.candidate().mutations.len(),
                                complete: self.complete,
                            })
                        }
                    }
                    Decision::TimeGuardFailed { .. } => Ok(SweepOutcome::ClockRewound),
                    Decision::ExpiredUnknown => {
                        self.pending = Some(pending);
                        Ok(SweepOutcome::Reconcile(submission.id))
                    }
                    Decision::OpIdConflict => Err(Error::Access(AccessError::OperationConflict)),
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct Maintenance {
    scopes: std::collections::HashSet<(String, String)>,
    queue: std::collections::VecDeque<((String, String), SweepState)>,
}

struct MaintenancePass<'a> {
    store: &'a CoreStore,
    scope: (String, String),
    state: Option<SweepState>,
}
impl Drop for MaintenancePass<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            self.store
                .claim_maintenance
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .queue
                .push_back((self.scope.clone(), state));
        }
    }
}
impl CoreStore {
    /// Register a trusted claim namespace for shared bounded maintenance. This
    /// declares ownership only; it performs no native call or background work.
    pub fn register_claim_scope(&self, owner: &str, kind: &str) -> Result<(), Error> {
        let mut maintenance = self
            .claim_maintenance
            .lock()
            .map_err(|_| Error::Access(AccessError::Corrupt))?;
        let scope = (owner.to_string(), kind.to_string());
        if maintenance.scopes.contains(&scope) {
            return Ok(());
        }
        let state = SweepState::new(owner, kind)?;
        maintenance.scopes.insert(scope.clone());
        maintenance.queue.push_back((scope, state));
        Ok(())
    }
    /// Advance one registered scope in round-robin order. The same state machine
    /// backs explicit owned cursors; no CoreStore Arc is retained by its registry.
    /// Cancellation returns the original cursor and pending candidate to custody.
    pub async fn sweep_claim_scope(&self) -> Result<Option<SweepOutcome>, Error> {
        let selected = self
            .claim_maintenance
            .lock()
            .map_err(|_| Error::Access(AccessError::Corrupt))?
            .queue
            .pop_front();
        let Some((scope, state)) = selected else {
            return Ok(None);
        };
        let mut pass = MaintenancePass {
            store: self,
            scope,
            state: Some(state),
        };
        let result = pass
            .state
            .as_mut()
            .ok_or(Error::Corrupt)?
            .advance(self)
            .await?;
        if matches!(
            result,
            SweepOutcome::Complete | SweepOutcome::Page { complete: true, .. }
        ) {
            pass.state = Some(SweepState::new(&pass.scope.0, &pass.scope.1)?);
        }
        Ok(Some(result))
    }
}

fn outcome(submission: Submission, expires_at: u64) -> Result<Option<Outcome>, Error> {
    let claim = PendingClaim {
        id: submission.id,
        expires_at,
    };
    Ok(Some(match submission.result {
        SubmitResult::Decided(decision) => match decision.as_ref() {
            Decision::Applied(_) => Outcome::Claimed,
            Decision::ConditionConflict => return Ok(None),
            Decision::TimeGuardFailed { observed_at } => {
                if observed_at.unix_seconds > expires_at {
                    Outcome::Expired
                } else {
                    Outcome::AlreadyClaimed
                }
            }
            Decision::ExpiredUnknown => Outcome::Reconcile(claim),
            Decision::OpIdConflict => return Err(Error::Access(AccessError::OperationConflict)),
        },
        SubmitResult::NoEffect(failure) => return Err(Error::Backend(failure)),
        SubmitResult::Uncertain => Outcome::Pending(claim),
        SubmitResult::Reconcile => Outcome::Reconcile(claim),
        SubmitResult::Busy => Outcome::Busy(claim),
    }))
}

#[cfg(test)]
#[path = "claims_tests.rs"]
mod tests;
