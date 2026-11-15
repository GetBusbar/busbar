// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot-owned node allocation and deployment keys. A host lease never transfers a
//! journal: a new owner receives a fresh node even when a previous lease expired.
use std::sync::{Arc, Mutex};

use busbar_contract::Secret;

use super::{
    facade::CoreStore,
    scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore},
};

pub const INSTANCE: &str = "busbar.boot";
pub const NODE_SCHEMA: &str = "busbar.node.v1";
pub const KEYSET_SCHEMA: &str = "busbar.keyset.v1";
const KEYSET_KEY: &[u8] = b"deployment";
/// The keep-once deployment identity row (ADMIN-API-1.6 4.1): not the secret keyset row.
pub const DEPLOYMENT_SCHEMA: &str = "busbar.deployment.v1";
const DEPLOYMENT_KEY: &[u8] = b"id";
const ASSIGNMENT_MAGIC: &[u8; 8] = b"BBNODE01";
const ID_ATTEMPTS: usize = 16;
const JOURNAL_INVENTORY_PREFIX: &[u8] = b"journal:";

pub const LEASE_TTL_MS: u64 = 9_000;

pub(crate) enum WriterRetirement {
    Live { retry_at_ms: u64 },
    Pending,
    Retired(Vec<busbar_contract::persistence::Predicate>),
}

pub use super::undrained::{
    undrained_records, ObservedBy, RecordLedger, UndrainedWriter, UNDRAINED_RECORDS,
};

type Target = super::undrained::Target;

/// This instance's own attempts and its own observed closes of open writers.
#[derive(Default)]
struct RetireState {
    /// `Some(seen)` iff the close was built from a control row that still admitted the epoch
    /// (an open writer): its decision is the one moment its record is offered.
    pending: std::collections::BTreeMap<
        Target,
        (
            busbar_contract::persistence::PreparedCandidate,
            Option<UndrainedWriter>,
        ),
    >,
    closed_open: std::collections::BTreeSet<Target>,
}

/// Domain custody survives cancellation and Unknown. The CoreStore retains the
/// native Attempt, while this owner retains its exact target and candidate.
#[derive(Default)]
pub struct WriterRetirements {
    gate: tokio::sync::Mutex<()>,
    state: Mutex<RetireState>,
    #[cfg(test)]
    hooks: RetireHooks,
}

/// Test-only: one held step. `reached` is notified when the step is reached; `release` lets it go.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHold {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
impl TestHold {
    pub(crate) async fn pass(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

/// Test-only: what one `settle` retry answered (SHUTDOWN-HANG 8.15).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettleAnswer {
    Decided,
    NoEffect,
    Busy,
    Unresolved,
    /// The retry was refused (`UnknownOperation`: another driver collected the decision).
    Unknown,
    /// After `Unknown`, `gate` was free: the entry was removed as lost.
    Lost,
}

#[cfg(test)]
impl SettleAnswer {
    fn of(result: &super::commit::SubmitResult) -> Self {
        use super::commit::SubmitResult as R;
        match result {
            R::Decided(_) => Self::Decided,
            R::NoEffect(_) => Self::NoEffect,
            R::Busy => Self::Busy,
            R::Uncertain | R::Reconcile => Self::Unresolved,
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct RetireHooks {
    decision: Mutex<Option<Arc<TestHold>>>,
    settle: Mutex<Vec<SettleAnswer>>,
}

#[cfg(test)]
impl WriterRetirements {
    /// Holds the next `retire_after` whose submit returns, after the CoreStore's decision and
    /// before `take_decided`.
    pub(crate) fn hold_decision(&self, hold: Arc<TestHold>) {
        *self
            .hooks
            .decision
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(hold);
    }

    fn armed_decision(&self) -> Option<Arc<TestHold>> {
        self.hooks
            .decision
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    async fn decision_reached(&self) {
        if let Some(hold) = self.armed_decision() {
            hold.pass().await;
        }
    }

    fn note(&self, answer: SettleAnswer) {
        self.hooks
            .settle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(answer);
    }

    /// Every `settle` retry answer so far, in order.
    pub(crate) fn settle_answers(&self) -> Vec<SettleAnswer> {
        self.hooks
            .settle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}
impl WriterRetirements {
    fn state(&self) -> std::sync::MutexGuard<'_, RetireState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `retire_after` with no margin and no record (the recovery tests' shape).
    #[cfg(test)]
    pub(crate) async fn retire(
        &self,
        core: &CoreStore,
        epoch: u64,
        writer: [u8; 16],
    ) -> Result<WriterRetirement, String> {
        self.retire_after(core, epoch, writer, 0, None).await
    }

    /// The one closer of a writer that is not this process's (SHUTDOWN-HANG F5 "The close").
    /// `grace_ms` moves exactly two expressions: the liveness check and the store's own time
    /// guard. With `seen`, an applied close of an open writer offers its
    /// `shutdown.drain_incomplete` record the moment this instance observes the decision.
    pub(crate) async fn retire_after(
        &self,
        core: &CoreStore,
        epoch: u64,
        writer: [u8; 16],
        grace_ms: u64,
        seen: Option<UndrainedWriter>,
    ) -> Result<WriterRetirement, String> {
        use super::{commit::SubmitResult, facade::PendingId};
        use busbar_contract::persistence::{self as native, control};
        let _gate = self.gate.lock().await;
        let target = (epoch, writer);
        let retained = self
            .state()
            .pending
            .get(&target)
            .map(|(candidate, _)| candidate.clone());
        if let Some(candidate) = retained {
            let submission = core
                .retry(PendingId(candidate.candidate().id.operation))
                .await
                .map_err(error)?;
            match submission.result {
                SubmitResult::Decided(decision) => {
                    self.take_decided(target, matches!(*decision, native::Decision::Applied(_)));
                }
                SubmitResult::NoEffect(_) => self.take_decided(target, false),
                SubmitResult::Uncertain | SubmitResult::Busy => {
                    return Ok(WriterRetirement::Pending);
                }
                SubmitResult::Reconcile => {
                    return Err("writer retirement retains unresolved original attempt".into());
                }
            }
        }
        let root_address = native::Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        };
        let control_address = native::Address {
            namespace: control::NAMESPACE.0,
            key: control::writer_key(writer).to_vec(),
        };
        let lease_address = super::scoped::migration_address(
            true,
            INSTANCE,
            NODE_SCHEMA,
            &writer_lease_key(epoch, writer),
        )
        .map_err(error)?;
        let observed = core
            .backend()
            .read(Arc::new(native::Read {
                dataset: core.info().dataset,
                addresses: vec![
                    root_address.clone(),
                    control_address.clone(),
                    lease_address.clone(),
                ],
                time: None,
            }))
            .await
            .map_err(error)?;
        let native::ReadResult::Values {
            observed_at,
            mut values,
        } = observed
        else {
            return Err("unexpected writer retirement observation".into());
        };
        if values.len() != 3 || observed_at.authority != core.info().clock_authority {
            return Err("invalid writer retirement observation".into());
        }
        let lease = values.pop().flatten();
        let control_raw = values.pop().flatten();
        let root_raw = values
            .pop()
            .flatten()
            .ok_or("writer retirement dataset missing")?;
        let root = control::Dataset::decode(root_raw.expose(&crate::seal::lend()))
            .ok_or("invalid writer retirement dataset")?;
        if epoch == 0
            || writer == [0; 16]
            || root.id != core.info().dataset
            || root.writer_epoch < epoch
        {
            return Err("writer retirement identity differs".into());
        }
        let root_guard = native::Predicate {
            address: root_address,
            expected: native::ExpectedValue::Exact(root_raw),
        };
        if root.writer_epoch > epoch {
            return Ok(WriterRetirement::Retired(vec![root_guard]));
        }
        let control_raw = control_raw.ok_or("writer retirement control missing")?;
        let old = control::Writer::decode(control_raw.expose(&crate::seal::lend()))
            .ok_or("invalid writer retirement control")?;
        let permanently_closed = control::Writer {
            retired_through: u64::MAX,
            admitted_through: u64::MAX,
        };
        if old == permanently_closed {
            return Ok(WriterRetirement::Retired(vec![
                root_guard,
                native::Predicate {
                    address: control_address,
                    expected: native::ExpectedValue::Exact(control_raw),
                },
            ]));
        }
        if core.authority().map_err(error)?.writer == writer {
            return Err("cannot retire current writer".into());
        }
        let lease = lease.ok_or("current journal owner has no durable writer lease")?;
        let lease_row = LeaseRow::parse(lease.expose(&crate::seal::lend()))?;
        let now_ms = observed_at
            .unix_seconds
            .checked_mul(1000)
            .ok_or("writer retirement clock overflow")?;
        let closable_ms = lease_row
            .expires_ms
            .checked_add(grace_ms)
            .ok_or("writer retirement grace overflow")?;
        if now_ms < closable_ms {
            return Ok(WriterRetirement::Live {
                retry_at_ms: closable_ms,
            });
        }
        let fence = super::fences::writer(
            core.next_id().map_err(error)?,
            writer,
            Some(old),
            permanently_closed,
        )
        .map_err(error)?;
        let body = fence.candidate();
        let candidate = native::PreparedCandidate::new(native::Candidate {
            id: body.id,
            codec: body.codec,
            predicates: vec![
                root_guard,
                native::Predicate {
                    address: control_address.clone(),
                    expected: native::ExpectedValue::Exact(control_raw),
                },
                native::Predicate {
                    address: lease_address,
                    expected: native::ExpectedValue::Exact(lease),
                },
            ],
            mutations: vec![native::Mutation::Put {
                address: control_address,
                value: Secret::new(
                    permanently_closed
                        .encode()
                        .ok_or("invalid permanent fence")?
                        .to_vec(),
                ),
            }],
            time: Some(native::TimeGuard {
                not_before: Some(closable_ms.div_ceil(1000)),
                before: None,
            }),
            result: Secret::default(),
        })
        .map_err(error)?;
        // A record is owed only for a writer that never retired: its row still has a live
        // execution epoch. `epoch` is the dataset's writer epoch, not one of the row's execution
        // epochs, so `admits(epoch)` would miss a writer that rolled its epoch and died (#258).
        let seen = seen.filter(|_| !old.live().is_empty());
        {
            let mut state = self.state();
            if let Some(seen) = &seen {
                undrained_records().retain(seen);
            }
            state.pending.insert(target, (candidate.clone(), seen));
        }
        let submission = match core.submit(candidate).await {
            Ok(submission) => submission,
            Err(cause) => {
                // Nothing crossed: drop the target with no record.
                self.take_decided(target, false);
                return Err(error(cause));
            }
        };
        #[cfg(test)]
        self.decision_reached().await;
        match submission.result {
            SubmitResult::Decided(decision) => {
                self.take_decided(target, matches!(*decision, native::Decision::Applied(_)));
                // Only a subsequent coherent permanent-fence read grants proof.
                Ok(WriterRetirement::Pending)
            }
            SubmitResult::NoEffect(_) => {
                self.take_decided(target, false);
                Ok(WriterRetirement::Pending)
            }
            SubmitResult::Uncertain | SubmitResult::Busy => Ok(WriterRetirement::Pending),
            SubmitResult::Reconcile => {
                Err("writer retirement retains unresolved original attempt".into())
            }
        }
    }

    /// The only place a decided attempt leaves `pending`: one removal under `state`, so a
    /// decision is offered to the record ledger at most once whoever reaches it.
    fn take_decided(&self, target: Target, applied: bool) {
        let refused = {
            let mut state = self.state();
            let Some((_, seen)) = state.pending.remove(&target) else {
                return;
            };
            let Some(seen) = seen else {
                return;
            };
            if applied {
                state.closed_open.insert(target);
            }
            undrained_records()
                .decided(&seen, applied)
                .map(|error| (seen, error))
        };
        if let Some((seen, error)) = refused {
            crate::diag_error!(crate::diagnostics::SHUTDOWN_DRAIN_INCOMPLETE_UNRECORDED,
                epoch = seen.epoch, writer = %hex::encode(seen.writer),
                node = ?seen.node, host = seen.host.as_deref().unwrap_or("none"),
                observed_by = seen.observed_by.as_str(), %error,
                "the close of a writer that never retired applied, but its shutdown.drain_incomplete record could not be queued; retried, and listed at exit");
            undrained_records().ensure_retry_task();
        }
    }

    /// Whether this instance's close of an open writer applied since the last call (the
    /// caller's in-RAM follow-ups only; the record is already offered).
    pub fn take_closed_open(&self, epoch: u64, writer: [u8; 16]) -> bool {
        self.state().closed_open.remove(&(epoch, writer))
    }

    /// Targets this instance still retains.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.state().pending.len()
    }

    /// The shutdown seal phase's fence settle: re-drives retained attempts and submits nothing
    /// new. It never awaits `gate`: a `Busy` retry (another drive in flight) waits 50 ms; an
    /// `UnknownOperation` leaves the entry to the driver that holds the decision, unless no
    /// driver is in flight (`gate` free), when the decision is lost to this process and the
    /// target is listed at exit, unrecorded. Returns when nothing is retained.
    pub async fn settle(&self, core: &CoreStore) {
        use super::{commit::SubmitResult, facade::PendingId};
        use busbar_contract::persistence as native;
        loop {
            let retained: Vec<(Target, busbar_contract::persistence::PreparedCandidate)> = self
                .state()
                .pending
                .iter()
                .map(|(t, (c, _))| (*t, c.clone()))
                .collect();
            if retained.is_empty() {
                return;
            }
            for (target, candidate) in retained {
                match core
                    .retry(PendingId(candidate.candidate().id.operation))
                    .await
                {
                    Ok(submission) => {
                        #[cfg(test)]
                        self.note(SettleAnswer::of(&submission.result));
                        match submission.result {
                            SubmitResult::Decided(decision) => self.take_decided(
                                target,
                                matches!(*decision, native::Decision::Applied(_)),
                            ),
                            SubmitResult::NoEffect(_) => self.take_decided(target, false),
                            SubmitResult::Uncertain
                            | SubmitResult::Busy
                            | SubmitResult::Reconcile => {}
                        }
                    }
                    Err(_) => {
                        #[cfg(test)]
                        self.note(SettleAnswer::Unknown);
                        // Decided by another driver. If none is in flight, nobody holds it.
                        if let Ok(_free) = self.gate.try_lock() {
                            #[cfg(test)]
                            self.note(SettleAnswer::Lost);
                            let lost = self.state().pending.remove(&target);
                            if let Some((_, Some(seen))) = lost {
                                undrained_records().lost(&seen);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

pub(crate) fn error(error: impl std::fmt::Debug) -> String {
    format!("boot persistence: {error:?}")
}

/// The policy owner retains the exact logical request before its first crossing.
/// Cancellation releases the async gate, but cannot discard an uncertain body.
pub(crate) struct BootRecords {
    pub(crate) records: ScopedStore,
    pub(crate) gate: tokio::sync::Mutex<()>,
    pending: Mutex<Option<Arc<Request>>>,
}
impl BootRecords {
    pub(crate) fn new(core: Arc<CoreStore>, schemas: &[&str]) -> Result<Self, String> {
        Ok(Self {
            records: ScopedStore::host_private(core, INSTANCE, schemas.iter().map(|s| (*s).into()))
                .map_err(error)?,
            gate: tokio::sync::Mutex::new(()),
            pending: Mutex::new(None),
        })
    }

    pub(crate) async fn resume(&self) -> Result<Option<bool>, String> {
        let request = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let Some(request) = request else {
            return Ok(None);
        };
        loop {
            let outcome = match self.records.conditional_native(&request).await {
                Ok(outcome) => outcome,
                Err(super::host_records::Error::Backend(
                    busbar_contract::persistence::Failure::Unavailable
                    | busbar_contract::persistence::Failure::Overloaded,
                ))
                | Err(super::host_records::Error::Access(super::facade::AccessError::Overloaded))
                | Err(super::host_records::Error::Access(super::facade::AccessError::Backend(
                    busbar_contract::persistence::Failure::Unavailable
                    | busbar_contract::persistence::Failure::Overloaded,
                ))) => {
                    // The original request remains owned, including the allocated node
                    // and lease result in the suspended caller. Never reenter allocation.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(cause) => return Err(error(cause)),
            };
            match outcome {
                outcome @ (Outcome::Applied | Outcome::ConditionConflict) => {
                    *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = None;
                    return Ok(Some(matches!(outcome, Outcome::Applied)));
                }
                Outcome::Pending(_) | Outcome::Busy(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                outcome => return Err(format!("boot mutation remains retained: {outcome:?}")),
            }
        }
    }

    pub(crate) async fn decide(
        &self,
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
    ) -> Result<bool, String> {
        let request = Arc::new(Request {
            op_id: crate::door::op_id().0,
            predicates,
            mutations,
        });
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if pending.is_some() {
                return Err("a prior boot mutation is still unresolved".into());
            }
            *pending = Some(request);
        }
        self.resume()
            .await?
            .ok_or_else(|| "boot mutation disappeared".into())
    }
}

fn expected(value: Option<Secret<Vec<u8>>>) -> Expected {
    value.map_or(Expected::Absent, Expected::Exact)
}
fn predicate(schema: &str, key: Vec<u8>, value: Option<Secret<Vec<u8>>>) -> Predicate {
    Predicate {
        schema: schema.into(),
        key,
        expected: expected(value),
    }
}
fn put(schema: &str, key: Vec<u8>, bytes: Vec<u8>) -> Mutation {
    Mutation::Put {
        schema: schema.into(),
        key,
        value: Secret::new(bytes),
    }
}
fn host_key(host: &str) -> Vec<u8> {
    [b"host:".as_slice(), host.as_bytes()].concat()
}
fn lease_key(host: &str) -> Vec<u8> {
    [b"lease:".as_slice(), host.as_bytes()].concat()
}
fn writer_lease_key(epoch: u64, writer: [u8; 16]) -> Vec<u8> {
    [b"writer:".as_slice(), &epoch.to_be_bytes(), &writer].concat()
}
fn archive_key(host: &str, id: u64) -> Vec<u8> {
    let mut key = host_key(host);
    key.push(0);
    key.extend_from_slice(format!("{id:016x}").as_bytes());
    key
}
fn id_key(id: u64) -> Vec<u8> {
    [b"id:".as_slice(), &id.to_be_bytes()].concat()
}
/// The start time (unix ms) of the node `id`, written once with its assignment.
fn born_key(id: u64) -> Vec<u8> {
    [b"born:".as_slice(), &id.to_be_bytes()].concat()
}
/// The time (unix ms) the node `id` released its lease: written once, on a clean stop.
fn stop_key(id: u64) -> Vec<u8> {
    [b"stop:".as_slice(), &id.to_be_bytes()].concat()
}
fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    busbar_contract::crypto::fill(&mut bytes).map_err(error)?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct Assignment {
    id: u64,
    epoch: u64,
    writer: [u8; 16],
}
impl Assignment {
    fn bytes(self) -> Vec<u8> {
        [
            ASSIGNMENT_MAGIC.as_slice(),
            &self.id.to_be_bytes(),
            &self.epoch.to_be_bytes(),
            &self.writer,
        ]
        .concat()
    }
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 40 || &bytes[..8] != ASSIGNMENT_MAGIC {
            return Err("malformed node assignment".into());
        }
        let value = Self {
            id: u64::from_be_bytes(bytes[8..16].try_into().map_err(error)?),
            epoch: u64::from_be_bytes(bytes[16..24].try_into().map_err(error)?),
            writer: bytes[24..].try_into().map_err(error)?,
        };
        if value.id == 0 || value.epoch == 0 || value.writer == [0; 16] {
            return Err("invalid node assignment".into());
        }
        Ok(value)
    }
}
fn node_id(bytes: &[u8]) -> Result<u64, String> {
    let id = if bytes.len() == 8 {
        u64::from_be_bytes(bytes.try_into().map_err(error)?)
    } else {
        Assignment::parse(bytes)?.id
    };
    if id == 0 {
        Err("zero node identity".into())
    } else {
        Ok(id)
    }
}
#[derive(Clone, Copy)]
struct LeaseRow {
    holder: [u8; 16],
    expires_ms: u64,
}
impl LeaseRow {
    fn bytes(self) -> Vec<u8> {
        [&self.holder[..], &self.expires_ms.to_be_bytes()].concat()
    }
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 24 {
            return Err("malformed node lease".into());
        }
        Ok(Self {
            holder: bytes[..16].try_into().map_err(error)?,
            expires_ms: u64::from_be_bytes(bytes[16..].try_into().map_err(error)?),
        })
    }
}

pub struct BootIdentity {
    core: Arc<CoreStore>,
    records: BootRecords,
    holder: [u8; 16],
}
impl BootIdentity {
    pub fn new(core: Arc<CoreStore>) -> Result<Self, String> {
        Ok(Self {
            records: BootRecords::new(
                core.clone(),
                &[NODE_SCHEMA, KEYSET_SCHEMA, DEPLOYMENT_SCHEMA],
            )?,
            core,
            holder: random()?,
        })
    }
    async fn now_ms(&self) -> Result<u64, String> {
        let now = self
            .core
            .backend()
            .clock(self.core.info().dataset)
            .await
            .map_err(error)?;
        if now.authority != self.core.info().clock_authority {
            return Err("node lease clock authority changed".into());
        }
        now.unix_seconds
            .checked_mul(1_000)
            .ok_or_else(|| "node lease clock overflow".into())
    }
    pub async fn registered(&self) -> Result<Vec<(String, u64)>, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        self.registered_locked().await
    }

    async fn registered_locked(&self) -> Result<Vec<(String, u64)>, String> {
        let mut cursor = None;
        let mut nodes = Vec::new();
        loop {
            // One generation-checked scan covers both assignments and readonly
            // imports; two prefix scans could observe different inventories.
            let page = self
                .records
                .records
                .page(NODE_SCHEMA, b"", cursor.as_ref())
                .await
                .map_err(error)?;
            for (key, value) in page.rows {
                if let Some(host) = key.strip_prefix(b"host:") {
                    let host = std::str::from_utf8(host).map_err(error)?.to_string();
                    let id = node_id(value.expose(&crate::seal::lend()))?;
                    nodes.push((host, id));
                } else if key.starts_with(JOURNAL_INVENTORY_PREFIX) {
                    return Err(
                        "store carries a journal inventory written by an unreleased \
                         1.6.0-dev import; upgrade from 1.5.5"
                            .into(),
                    );
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(nodes),
            }
        }
    }
    pub async fn take_node(self: &Arc<Self>, host: &str) -> Result<TakenNode, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        for _ in 0..ID_ATTEMPTS {
            let key = host_key(host);
            let lease_at = lease_key(host);
            let mut observation = self
                .records
                .records
                .read(&[(NODE_SCHEMA, &key), (NODE_SCHEMA, &lease_at)])
                .await
                .map_err(error)?
                .into_iter();
            let previous = observation.next().ok_or("node observation missing")?;
            let lease = observation.next().ok_or("lease observation missing")?;
            let now = self.now_ms().await?;
            let lease_row = lease
                .as_ref()
                .map(|v| LeaseRow::parse(v.expose(&crate::seal::lend())))
                .transpose()?;
            let authority = self.core.authority().map_err(error)?;
            let writer_key = writer_lease_key(authority.writer_epoch, authority.writer);
            let writer_lease = self
                .records
                .records
                .get(NODE_SCHEMA, &writer_key)
                .await
                .map_err(error)?;
            let writer_row = writer_lease
                .as_ref()
                .map(|value| LeaseRow::parse(value.expose(&crate::seal::lend())))
                .transpose()?;
            let previous_id = previous
                .as_ref()
                .map(|v| node_id(v.expose(&crate::seal::lend())))
                .transpose()?;
            if let Some(bytes) = previous.as_ref() {
                if let Ok(assignment) = Assignment::parse(bytes.expose(&crate::seal::lend())) {
                    if assignment.epoch == authority.writer_epoch
                        && assignment.writer == authority.writer
                        && lease_row.is_some_and(|lease| {
                            lease.holder == self.holder && lease.expires_ms != 0
                        })
                    {
                        return Ok(TakenNode {
                            id: assignment.id,
                            lease: Some(NodeLease {
                                owner: self.clone(),
                                host: host.into(),
                                id: assignment.id,
                                assignment_key: key,
                                primary: true,
                                released: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                            }),
                        });
                    }
                }
            }
            let taken = self.registered_locked().await?;
            let id = u64::from_be_bytes(random()?);
            if id == 0 || taken.iter().any(|(_, taken)| *taken == id) {
                continue;
            }
            let assignment = Assignment {
                id,
                epoch: authority.writer_epoch,
                writer: authority.writer,
            }
            .bytes();
            let primary = lease_row.is_none_or(|lease| lease.expires_ms <= now);
            let target = if primary {
                key.clone()
            } else {
                archive_key(host, id)
            };
            let reservation = id_key(id);
            let mut predicates = vec![predicate(NODE_SCHEMA, reservation.clone(), None)];
            let mut mutations = vec![put(NODE_SCHEMA, reservation, assignment.clone())];
            mutations.push(put(NODE_SCHEMA, born_key(id), now.to_be_bytes().to_vec()));
            predicates.push(predicate(NODE_SCHEMA, writer_key.clone(), writer_lease));
            mutations.push(put(
                NODE_SCHEMA,
                writer_key,
                LeaseRow {
                    holder: writer_row.map_or(self.holder, |row| row.holder),
                    expires_ms: now
                        .checked_add(LEASE_TTL_MS)
                        .ok_or("writer lease expiry overflow")?,
                }
                .bytes(),
            ));
            if primary {
                predicates.push(predicate(NODE_SCHEMA, key, previous.clone()));
                predicates.push(predicate(NODE_SCHEMA, lease_at.clone(), lease));
                if let Some(old) = previous_id {
                    let archive = archive_key(host, old);
                    let held = self
                        .records
                        .records
                        .get(NODE_SCHEMA, &archive)
                        .await
                        .map_err(error)?;
                    if let Some(value) = held.as_ref() {
                        if node_id(value.expose(&crate::seal::lend()))? != old {
                            return Err("archived node identity conflict".into());
                        }
                    } else {
                        predicates.push(predicate(NODE_SCHEMA, archive.clone(), None));
                        mutations.push(Mutation::Put {
                            schema: NODE_SCHEMA.into(),
                            key: archive,
                            value: previous.clone().ok_or("archived identity missing")?,
                        });
                    }
                }
                mutations.push(put(
                    NODE_SCHEMA,
                    lease_at,
                    LeaseRow {
                        holder: self.holder,
                        expires_ms: now
                            .checked_add(LEASE_TTL_MS)
                            .ok_or("node lease expiry overflow")?,
                    }
                    .bytes(),
                ));
            } else {
                predicates.push(predicate(NODE_SCHEMA, target.clone(), None));
            }
            mutations.push(put(NODE_SCHEMA, target.clone(), assignment));
            if self.records.decide(predicates, mutations).await? {
                return Ok(TakenNode {
                    id,
                    lease: Some(NodeLease {
                        owner: self.clone(),
                        host: host.into(),
                        id,
                        assignment_key: target,
                        primary,
                        released: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    }),
                });
            }
        }
        Err("node allocation exhausted its conflict/randomness budget".into())
    }
    pub async fn stored_keyset(&self) -> Result<Option<String>, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        self.stored_keyset_locked().await
    }

    async fn stored_keyset_locked(&self) -> Result<Option<String>, String> {
        self.records
            .records
            .get(KEYSET_SCHEMA, KEYSET_KEY)
            .await
            .map_err(error)?
            .map(|v| String::from_utf8(v.expose(&crate::seal::lend()).clone()).map_err(error))
            .transpose()
    }
    pub async fn keep_keyset(&self, seed_hex: &str) -> Result<String, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        if let Some(held) = self.stored_keyset_locked().await? {
            return Ok(held);
        }
        self.records
            .decide(
                vec![predicate(KEYSET_SCHEMA, KEYSET_KEY.into(), None)],
                vec![put(
                    KEYSET_SCHEMA,
                    KEYSET_KEY.into(),
                    seed_hex.as_bytes().to_vec(),
                )],
            )
            .await?;
        self.stored_keyset_locked()
            .await?
            .ok_or_else(|| "deployment keyset was not kept".into())
    }

    /// The deployment identity (`dep_` + 32 hex): the same 16 random bytes for the life of the
    /// store. Kept once, by the first process that asks, in its own row (not the secret keyset
    /// row), so every node and every restart reads the one value.
    pub async fn keep_deployment_id(&self) -> Result<String, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        loop {
            if let Some(held) = self
                .records
                .records
                .get(DEPLOYMENT_SCHEMA, DEPLOYMENT_KEY)
                .await
                .map_err(error)?
            {
                let bytes = held.expose(&crate::seal::lend());
                return match <[u8; 16]>::try_from(bytes.as_slice()) {
                    Ok(id) => Ok(format!("dep_{}", hex::encode(id))),
                    Err(_) => Err("malformed deployment identity row".into()),
                };
            }
            let id: [u8; 16] = random()?;
            self.records
                .decide(
                    vec![predicate(DEPLOYMENT_SCHEMA, DEPLOYMENT_KEY.into(), None)],
                    vec![put(DEPLOYMENT_SCHEMA, DEPLOYMENT_KEY.into(), id.to_vec())],
                )
                .await?;
        }
    }

    /// Every node the store holds a lease row for, lowest id first: the `/info.nodes` read.
    /// `live`: its lease is unexpired by the store's clock; `lost`: it expired without release;
    /// `stopped`: it was released, or its writer's lease row was closed. `writer` marks the node
    /// this store's current writer authority runs; every other node is a `replica`.
    pub async fn nodes(&self) -> Result<Vec<NodeRow>, String> {
        use std::collections::BTreeMap;
        let now_ms = self.now_ms().await?;
        let own = self.core.authority().map_err(error)?;
        let mut assignments: Vec<(bool, String, Assignment)> = Vec::new();
        let mut host_leases: BTreeMap<String, LeaseRow> = BTreeMap::new();
        let mut writer_leases: BTreeMap<(u64, [u8; 16]), LeaseRow> = BTreeMap::new();
        let mut born: BTreeMap<u64, u64> = BTreeMap::new();
        let mut stopped: BTreeMap<u64, u64> = BTreeMap::new();
        let mut cursor = None;
        loop {
            let page = {
                let _gate = self.records.gate.lock().await;
                self.records.resume().await?;
                self.records
                    .records
                    .page(NODE_SCHEMA, b"", cursor.as_ref())
                    .await
                    .map_err(error)?
            };
            for (key, value) in page.rows {
                let bytes = value.expose(&crate::seal::lend());
                if let Some(rest) = key.strip_prefix(b"host:") {
                    if bytes.len() != 40 {
                        // A 1.5.5-shaped node id names no writer and holds no lease.
                        continue;
                    }
                    let primary = !rest.contains(&0);
                    let host = rest.split(|b| *b == 0).next().unwrap_or_default();
                    let host = String::from_utf8_lossy(host).into_owned();
                    assignments.push((primary, host, Assignment::parse(bytes)?));
                } else if let Some(host) = key.strip_prefix(b"lease:") {
                    let host = String::from_utf8_lossy(host).into_owned();
                    host_leases.insert(host, LeaseRow::parse(bytes)?);
                } else if let Some(rest) = key.strip_prefix(b"writer:") {
                    if rest.len() == 24 {
                        let epoch = u64::from_be_bytes(rest[..8].try_into().map_err(error)?);
                        let writer: [u8; 16] = rest[8..].try_into().map_err(error)?;
                        writer_leases.insert((epoch, writer), LeaseRow::parse(bytes)?);
                    }
                } else if let Some(id) = key.strip_prefix(b"stop:") {
                    if let (Ok(id), Ok(at)) = (
                        <[u8; 8]>::try_from(id),
                        <[u8; 8]>::try_from(bytes.as_slice()),
                    ) {
                        stopped.insert(u64::from_be_bytes(id), u64::from_be_bytes(at));
                    }
                } else if let Some(id) = key.strip_prefix(b"born:") {
                    if let (Ok(id), Ok(at)) = (
                        <[u8; 8]>::try_from(id),
                        <[u8; 8]>::try_from(bytes.as_slice()),
                    ) {
                        born.insert(u64::from_be_bytes(id), u64::from_be_bytes(at));
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let mut nodes = Vec::new();
        for (primary, host, assignment) in assignments {
            let lease = if primary {
                host_leases.get(&host)
            } else {
                writer_leases.get(&(assignment.epoch, assignment.writer))
            };
            let expires_ms = lease.map_or(0, |row| row.expires_ms);
            let released_ms = stopped.get(&assignment.id).copied();
            let state = if released_ms.is_some() || expires_ms == 0 {
                "stopped"
            } else if expires_ms > now_ms {
                "live"
            } else {
                "lost"
            };
            let last_seen_ms = if let Some(released) = released_ms {
                released
            } else if expires_ms == 0 {
                born.get(&assignment.id).copied().unwrap_or(0)
            } else {
                expires_ms.saturating_sub(LEASE_TTL_MS)
            };
            let started_ms = born.get(&assignment.id).copied().unwrap_or(last_seen_ms);
            let runs_here = assignment.epoch == own.writer_epoch && assignment.writer == own.writer;
            nodes.push((
                assignment.id,
                NodeRow {
                    node_id: format!("node_{:016x}", assignment.id),
                    started_at: started_ms / 1_000,
                    last_seen_at: last_seen_ms.max(started_ms) / 1_000,
                    state,
                    role: if runs_here && state == "live" {
                        "writer"
                    } else {
                        "replica"
                    },
                },
            ));
        }
        nodes.sort_by_key(|(id, _)| *id);
        nodes.dedup_by_key(|(id, _)| *id);
        Ok(nodes.into_iter().map(|(_, row)| row).collect())
    }
}

/// One node of `/info.nodes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRow {
    pub node_id: String,
    pub started_at: u64,
    pub last_seen_at: u64,
    pub state: &'static str,
    pub role: &'static str,
}

/// This process's identity as the admin surface serves it: published once at boot.
pub struct LiveIdentity {
    owner: Arc<BootIdentity>,
    node: u64,
    deployment_id: String,
}
impl LiveIdentity {
    pub fn node_id(&self) -> String {
        format!("node_{:016x}", self.node)
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub async fn nodes(&self) -> Result<Vec<NodeRow>, String> {
        self.owner.nodes().await
    }
}
static LIVE: std::sync::OnceLock<LiveIdentity> = std::sync::OnceLock::new();
/// Publishes this process's node and deployment identity (boot, once).
pub fn publish_live(owner: Arc<BootIdentity>, node: u64, deployment_id: String) {
    let _ = LIVE.set(LiveIdentity {
        owner,
        node,
        deployment_id,
    });
}
/// The published identity, `None` before boot has taken a node.
pub fn live() -> Option<&'static LiveIdentity> {
    LIVE.get()
}

/// A scanned writer lease: its target, key, exact bytes and expiry.
type ScannedLease = (Target, Vec<u8>, Secret<Vec<u8>>, u64);

/// One writer whose lease expired at least the grace ago (SHUTDOWN-HANG F5 "The scan").
#[derive(Clone, Debug)]
pub struct ExpiredWriter {
    pub epoch: u64,
    pub writer: [u8; 16],
    /// `(host, node)` assignments under this writer, lowest node first.
    pub nodes: Vec<(String, u64)>,
    lease_key: Vec<u8>,
    lease: Secret<Vec<u8>>,
}

/// One scan's inventory: up to `max` rows, the count left beyond it, and the rows that did not
/// decode (never closed, reported once per start).
#[derive(Debug, Default)]
pub struct ExpiredWriters {
    pub rows: Vec<ExpiredWriter>,
    pub remaining: usize,
    pub invalid: usize,
}

impl BootIdentity {
    /// Every writer lease that expired at least `grace_ms` ago by the store's clock, oldest
    /// epoch first, excluding this process's own writer. The gate is taken once per page, so
    /// this process's own lease refresh waits at most one page. The scan is an inventory, not
    /// a proof: every close is re-checked by the store.
    pub async fn expired_writers(
        &self,
        grace_ms: u64,
        max: usize,
    ) -> Result<ExpiredWriters, String> {
        let now_ms = self.now_ms().await?;
        let own = self.core.authority().map_err(error)?;
        let mut assignments: std::collections::BTreeMap<Target, Vec<(String, u64)>> =
            std::collections::BTreeMap::new();
        let mut leases: Vec<ScannedLease> = Vec::new();
        let mut invalid = 0;
        let mut cursor = None;
        loop {
            let page = {
                let _gate = self.records.gate.lock().await;
                self.records.resume().await?;
                self.records
                    .records
                    .page(NODE_SCHEMA, b"", cursor.as_ref())
                    .await
                    .map_err(error)?
            };
            for (key, value) in page.rows {
                let bytes = value.expose(&crate::seal::lend());
                if let Some(rest) = key.strip_prefix(b"writer:") {
                    let parsed = (rest.len() == 24)
                        .then(|| {
                            let epoch = u64::from_be_bytes(rest[..8].try_into().ok()?);
                            let writer: [u8; 16] = rest[8..].try_into().ok()?;
                            Some((epoch, writer))
                        })
                        .flatten();
                    match (parsed, LeaseRow::parse(bytes)) {
                        (Some(target), Ok(row)) => {
                            leases.push((target, key.clone(), value.clone(), row.expires_ms));
                        }
                        _ => {
                            invalid += 1;
                            crate::diag_warn!(crate::diagnostics::EXPIRED_WRITER_ROW_INVALID,
                                key_hex = %hex::encode(&key),
                                "a writer lease row does not decode; it is never closed");
                        }
                    }
                } else if let Some(rest) = key.strip_prefix(b"host:") {
                    let host = rest.split(|b| *b == 0).next().unwrap_or_default();
                    let host = String::from_utf8_lossy(host).into_owned();
                    if bytes.len() == 8 {
                        // A 1.5.5-shaped node id names no writer.
                        continue;
                    }
                    match Assignment::parse(bytes) {
                        Ok(assignment) => {
                            let nodes = assignments
                                .entry((assignment.epoch, assignment.writer))
                                .or_default();
                            if !nodes.iter().any(|(_, id)| *id == assignment.id) {
                                nodes.push((host, assignment.id));
                            }
                        }
                        Err(_) => {
                            invalid += 1;
                            crate::diag_warn!(crate::diagnostics::EXPIRED_WRITER_ROW_INVALID,
                                key_hex = %hex::encode(&key),
                                "a host assignment row does not decode; it is never closed");
                        }
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let mut out = ExpiredWriters {
            invalid,
            ..ExpiredWriters::default()
        };
        for (target, lease_key, lease, expires_ms) in leases {
            if target == (own.writer_epoch, own.writer)
                || now_ms < expires_ms.saturating_add(grace_ms)
            {
                continue;
            }
            if out.rows.len() >= max {
                out.remaining += 1;
                continue;
            }
            let mut nodes = assignments.remove(&target).unwrap_or_default();
            nodes.sort_by_key(|(_, id)| *id);
            out.rows.push(ExpiredWriter {
                epoch: target.0,
                writer: target.1,
                nodes,
                lease_key,
                lease,
            });
        }
        Ok(out)
    }

    /// Deletes a closed writer's lease row, guarded by the exact bytes scanned. A row another
    /// process deleted or changed first makes this a no-op.
    pub async fn delete_writer_lease(&self, row: &ExpiredWriter) -> Result<bool, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        self.records
            .decide(
                vec![predicate(
                    NODE_SCHEMA,
                    row.lease_key.clone(),
                    Some(row.lease.clone()),
                )],
                vec![Mutation::Delete {
                    schema: NODE_SCHEMA.into(),
                    key: row.lease_key.clone(),
                }],
            )
            .await
    }
}

/// At most this many writers closed per start; the next start continues.
pub const EXPIRED_PASS_MAX: usize = 256;

/// The start-up predecessor task's owner (SEALING-FIX §3.6.2; this design ships its F5 step and
/// its fence settle). Its own `WriterRetirements` records into the process-wide ledger.
pub struct PredecessorFence {
    core: Arc<CoreStore>,
    identity: Arc<BootIdentity>,
    host: String,
    retirements: WriterRetirements,
}

/// What one F5 pass did, for its Info line.
#[derive(Clone, Debug, Default)]
pub struct ExpiredPass {
    pub closed: usize,
    pub skipped_live: usize,
    pub invalid: usize,
    pub remaining: usize,
    pub records: super::undrained::PassCounts,
}

impl PredecessorFence {
    pub fn new(core: Arc<CoreStore>, host: &str) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            identity: Arc::new(BootIdentity::new(core.clone())?),
            core,
            host: host.into(),
            retirements: WriterRetirements::default(),
        }))
    }

    /// SHUTDOWN-HANG F5: close every writer whose lease expired at least one TTL ago, on any
    /// host, through the one closer; delete each closed writer's lease row; then one bounded
    /// "Records" pass on the ledger, the Info line, and no loop. `stop` (the first shutdown
    /// broadcast) ends it at the next step boundary.
    pub async fn run(&self, stop: tokio::sync::watch::Receiver<bool>) -> ExpiredPass {
        let stopped = || *stop.borrow();
        let mut pass = ExpiredPass::default();
        let scan = match self
            .identity
            .expired_writers(LEASE_TTL_MS, EXPIRED_PASS_MAX)
            .await
        {
            Ok(scan) => scan,
            Err(error) => {
                crate::diag_warn!(crate::diagnostics::EXPIRED_WRITER_CLOSE_FAILED,
                    %error, "the expired-writer scan failed; the next start retries");
                return pass;
            }
        };
        pass.invalid = scan.invalid;
        pass.remaining = scan.remaining;
        'writers: for row in &scan.rows {
            if stopped() {
                break;
            }
            let (node, host) = row
                .nodes
                .first()
                .map_or((None, None), |(host, id)| (Some(*id), Some(host.clone())));
            let seen = UndrainedWriter {
                node,
                other_nodes: row.nodes.iter().skip(1).map(|(_, id)| *id).collect(),
                epoch: row.epoch,
                writer: row.writer,
                observed_by: if host.as_deref() == Some(self.host.as_str()) {
                    ObservedBy::Successor
                } else {
                    ObservedBy::ExpiredLeasePass
                },
                host,
            };
            loop {
                match self
                    .retirements
                    .retire_after(
                        &self.core,
                        row.epoch,
                        row.writer,
                        LEASE_TTL_MS,
                        Some(seen.clone()),
                    )
                    .await
                {
                    Ok(WriterRetirement::Live { .. }) => {
                        pass.skipped_live += 1;
                        continue 'writers;
                    }
                    Ok(WriterRetirement::Pending) => {
                        if stopped() {
                            break 'writers;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Ok(WriterRetirement::Retired(_)) => {
                        if self.retirements.take_closed_open(row.epoch, row.writer) {
                            tracing::info!(
                                writer = %hex::encode(row.writer),
                                epoch = row.epoch,
                                "closed a writer that never retired; its shutdown.drain_incomplete record is offered"
                            );
                        }
                        pass.closed += 1;
                        if let Err(error) = self.identity.delete_writer_lease(row).await {
                            crate::diag_warn!(crate::diagnostics::EXPIRED_WRITER_CLOSE_FAILED,
                                epoch = row.epoch, writer = %hex::encode(row.writer), %error,
                                "a closed writer's lease row was not deleted; the next start retries");
                        }
                        continue 'writers;
                    }
                    Err(error) => {
                        crate::diag_warn!(crate::diagnostics::EXPIRED_WRITER_CLOSE_FAILED,
                            epoch = row.epoch, writer = %hex::encode(row.writer), %error,
                            "an expired writer was not closed; the next start retries");
                        continue 'writers;
                    }
                }
            }
        }
        if pass.remaining > 0 {
            crate::diag_warn!(
                crate::diagnostics::EXPIRED_WRITERS_REMAINING,
                n = pass.remaining,
                "more expired writers remain than one start closes; the next start continues"
            );
        }
        if !stopped() {
            pass.records = undrained_records()
                .settle_pass(super::undrained::Retrier::Owner)
                .await;
            if !pass.records.clean() {
                undrained_records().ensure_retry_task();
            }
        }
        let refused: Vec<String> = pass
            .records
            .record_failed
            .iter()
            .map(UndrainedWriter::resource)
            .collect();
        tracing::info!(
            closed = pass.closed,
            recorded = pass.records.recorded,
            record_failed = pass.records.record_failed.len(),
            flush_failed = pass.records.flush_failed,
            skipped_live = pass.skipped_live,
            invalid = pass.invalid,
            remaining = pass.remaining,
            refused = %refused.join("; "),
            "expired_writers"
        );
        pass
    }

    /// The seal phase's fence settle: re-drives what this task left retained, submits nothing.
    pub async fn settle(&self) {
        self.retirements.settle(&self.core).await;
    }

    /// Attempts this task still retains.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.retirements.retained()
    }
}

pub struct TakenNode {
    pub id: u64,
    pub lease: Option<NodeLease>,
}
#[derive(Clone)]
pub struct NodeLease {
    owner: Arc<BootIdentity>,
    host: String,
    id: u64,
    assignment_key: Vec<u8>,
    primary: bool,
    released: Arc<std::sync::atomic::AtomicBool>,
}
impl NodeLease {
    pub async fn refresh(&self) -> Result<bool, String> {
        self.change(false).await
    }
    pub async fn release(&self) -> Result<(), String> {
        self.change(true).await.map(|_| ())
    }
    async fn change(&self, release: bool) -> Result<bool, String> {
        use std::sync::atomic::Ordering;
        if self.released.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let owner = &self.owner;
        let _gate = owner.records.gate.lock().await;
        owner.records.resume().await?;
        loop {
            let host = self.assignment_key.clone();
            let key = lease_key(&self.host);
            let authority = owner.core.authority().map_err(error)?;
            let writer_key = writer_lease_key(authority.writer_epoch, authority.writer);
            let mut values = owner
                .records
                .records
                .read(&[
                    (NODE_SCHEMA, &host),
                    (NODE_SCHEMA, &key),
                    (NODE_SCHEMA, &writer_key),
                ])
                .await
                .map_err(error)?
                .into_iter();
            let assignment = values.next().ok_or("node observation missing")?;
            let lease = values.next().ok_or("lease observation missing")?;
            let writer_lease = values.next().ok_or("writer lease observation missing")?;
            let Some(bytes) = assignment.as_ref() else {
                return Ok(false);
            };
            let assignment_row = Assignment::parse(bytes.expose(&crate::seal::lend()))?;
            if assignment_row.id != self.id
                || assignment_row.epoch != authority.writer_epoch
                || assignment_row.writer != authority.writer
            {
                return Ok(false);
            }
            if self.primary {
                let Some(bytes) = lease.as_ref() else {
                    return Ok(false);
                };
                let row = LeaseRow::parse(bytes.expose(&crate::seal::lend()))?;
                if row.holder != owner.holder || row.expires_ms == 0 {
                    return Ok(false);
                }
            }
            let Some(writer_bytes) = writer_lease.as_ref() else {
                return Ok(false);
            };
            let writer_row = LeaseRow::parse(writer_bytes.expose(&crate::seal::lend()))?;
            let stopped_ms = if release { owner.now_ms().await? } else { 0 };
            let expires_ms = if release {
                0
            } else {
                owner
                    .now_ms()
                    .await?
                    .checked_add(LEASE_TTL_MS)
                    .ok_or("node lease expiry overflow")?
            };
            let mut predicates = vec![
                predicate(NODE_SCHEMA, host, assignment),
                predicate(NODE_SCHEMA, writer_key.clone(), writer_lease),
            ];
            let mut mutations = Vec::new();
            if self.primary {
                predicates.push(predicate(NODE_SCHEMA, key.clone(), lease));
                mutations.push(put(
                    NODE_SCHEMA,
                    key,
                    LeaseRow {
                        holder: owner.holder,
                        expires_ms,
                    }
                    .bytes(),
                ));
                if release {
                    mutations.push(put(
                        NODE_SCHEMA,
                        stop_key(self.id),
                        stopped_ms.to_be_bytes().to_vec(),
                    ));
                }
            }
            if !release {
                mutations.push(put(
                    NODE_SCHEMA,
                    writer_key,
                    LeaseRow {
                        holder: writer_row.holder,
                        expires_ms,
                    }
                    .bytes(),
                ));
            } else if !self.primary {
                // Keep the shared lease live for other nodes. A secondary has
                // no host lease to release; its assignment is immutable history.
                self.released.store(true, Ordering::SeqCst);
                return Ok(true);
            }
            if owner.records.decide(predicates, mutations).await? {
                if release {
                    self.released.store(true, Ordering::SeqCst);
                }
                return Ok(true);
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/boot_identity_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/expired_writers_tests.rs"]
mod expired_writers_tests;

#[cfg(test)]
#[path = "tests/fence_settle_tests.rs"]
mod fence_settle_tests;
