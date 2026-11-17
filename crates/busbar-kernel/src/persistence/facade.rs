// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only attachment and pending-operation ownership. Business modules receive
//! this facade; the raw backend stays private to core persistence coordination.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::persistence::{
    control, Address, AttemptId, BackendInfo, Failure, PersistenceBackend, PreparedCandidate, Read,
    ReadResult, MAX_SLOTS,
};

use super::commit::{Attempt, NoEffectCause, State, SubmitResult};

/// At most this many in-doubt attempts are resubmitted per settle tick.
pub const SETTLE_PER_TICK: usize = 64;

/// How the queue's `pending_operations` slots are held right now; the states add up
/// to the queue capacity (`busbar_store_slots`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlotStates {
    pub free: usize,
    pub in_flight: usize,
    pub in_doubt: usize,
    pub resolved_uncollected: usize,
    pub reconcile: usize,
}

#[path = "logical.rs"]
mod logical;
pub(crate) use logical::{LogicalClaim, LogicalId, LogicalPermit};

#[path = "domain.rs"]
mod domain;
pub(crate) use domain::{DomainCall, DomainOwner};

/// An already registered writer incarnation. Attachment validates these facts
/// against one coherent backend observation; it does not mint a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterAuthority {
    pub writer_epoch: u64,
    pub writer: [u8; 16],
    pub execution_epoch: u64,
}

/// Opaque operation identity for the facade's retained unresolved work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PendingId(pub [u8; 16]);

/// Admission, attachment or observation failed without discarding pending work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    Authority,
    InvalidLimits,
    Corrupt,
    Entropy,
    Overloaded,
    Closed,
    UnknownOperation,
    OperationConflict,
    Backend(Failure),
}

/// One attempted crossing and its retained identity. An unresolved result is not
/// durable acceptance; its domain must persist protected intent before promising
/// crash recovery. This facade itself makes no filesystem or journal writes.
#[derive(Debug)]
pub struct Submission {
    pub id: PendingId,
    pub result: SubmitResult,
}

struct Pending {
    authority: WriterAuthority,
    accepting: bool,
    attempts: HashMap<PendingId, PendingEntry>,
    logical: HashMap<LogicalId, logical::Entry>,
    /// Free queue slots, LIFO; slot 0 is leased first so hot slots stay low.
    free: Vec<u32>,
    /// The next lease sequence; 0 means "never used" at the store.
    next_seq: u64,
    /// Round-robin position of the settle pass, as a slot number.
    settle_cursor: u32,
}

struct PendingEntry {
    attempt: Arc<Attempt>,
    driving: bool,
    logical: Option<LogicalId>,
    identity_owned: bool,
    domain: Option<domain::Entry>,
    /// The queue slot this entry holds for its whole lifetime.
    slot: u32,
}

/// Explicit host resource and contention policy; page limits bound each crossing,
/// not the total collection size. No pending operation is evicted to make room.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub pending_operations: usize,
    pub conflict_retries: usize,
    pub scan_items: usize,
    pub scan_bytes: usize,
}

/// One core-owned persistence attachment shared by all host domain services.
pub struct CoreStore {
    backend: Arc<dyn PersistenceBackend>,
    info: BackendInfo,
    limits: Limits,
    pending: Mutex<Pending>,
    /// Set while every queue slot is held; read lock-free on arrival.
    exhausted: AtomicBool,
    pub(super) claim_maintenance: Mutex<super::claims::Maintenance>,
    pub(super) first_start: std::sync::OnceLock<Arc<super::first_start::FirstStart>>,
}

impl CoreStore {
    /// Attach only to authority already established by initialization/registration.
    /// Resource admission is explicit, never an eviction policy for uncertainty.
    pub(crate) async fn attach(
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        limits: Limits,
    ) -> Result<Self, AccessError> {
        if authority.writer == [0; 16]
            || authority.writer_epoch == 0
            || authority.execution_epoch == 0
        {
            return Err(AccessError::Authority);
        }
        if limits.pending_operations == 0
            || limits.pending_operations > MAX_SLOTS as usize
            || limits.scan_items == 0
            || limits.scan_bytes == 0
        {
            return Err(AccessError::InvalidLimits);
        }
        let mut free = Vec::new();
        free.try_reserve_exact(limits.pending_operations)
            .map_err(|_| AccessError::Overloaded)?;
        free.extend((0..limits.pending_operations as u32).rev());
        let info = backend.info();
        if info.dataset.0 == [0; 16]
            || info.clock_authority == [0; 16]
            || info.atomic_domain == [0; 16]
        {
            return Err(AccessError::Authority);
        }
        let observed = backend
            .read(Arc::new(Read {
                dataset: info.dataset,
                addresses: vec![
                    Address {
                        namespace: control::NAMESPACE.0,
                        key: control::DATASET_KEY.to_vec(),
                    },
                    Address {
                        namespace: control::NAMESPACE.0,
                        key: control::writer_key(authority.writer).to_vec(),
                    },
                ],
                time: None,
            }))
            .await
            .map_err(AccessError::Backend)?;
        let ReadResult::Values {
            observed_at,
            values,
        } = observed
        else {
            return Err(AccessError::Corrupt);
        };
        if observed_at.authority != info.clock_authority || values.len() != 2 {
            return Err(AccessError::Corrupt);
        }
        let seal = crate::seal::lend();
        let root = values[0].as_ref().ok_or(AccessError::Authority)?;
        let writer = values[1].as_ref().ok_or(AccessError::Authority)?;
        let root = control::Dataset::decode(root.expose(&seal)).ok_or(AccessError::Corrupt)?;
        let writer = control::Writer::decode(writer.expose(&seal)).ok_or(AccessError::Corrupt)?;
        if root.id != info.dataset {
            return Err(AccessError::Corrupt);
        }
        if root.writer_epoch != authority.writer_epoch || !writer.admits(authority.execution_epoch)
        {
            return Err(AccessError::Authority);
        }
        Ok(Self {
            backend,
            info,
            limits,
            claim_maintenance: Mutex::default(),
            first_start: std::sync::OnceLock::new(),
            exhausted: AtomicBool::new(false),
            pending: Mutex::new(Pending {
                authority,
                accepting: true,
                attempts: HashMap::new(),
                logical: HashMap::new(),
                free,
                next_seq: 1,
                settle_cursor: 0,
            }),
        })
    }

    /// Whether every queue slot is held. One relaxed load; no lock.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }

    /// The `busbar_store_slots` breakdown; its states add up to `pending_operations`.
    pub fn slot_states(&self) -> Result<SlotStates, AccessError> {
        let pending = self.lock()?;
        let mut states = SlotStates {
            free: pending.free.len(),
            ..SlotStates::default()
        };
        for entry in pending.attempts.values() {
            match entry.attempt.state() {
                State::Prepared | State::InFlight => states.in_flight += 1,
                State::Uncertain => states.in_doubt += 1,
                State::Resolved => states.resolved_uncollected += 1,
                State::Reconcile => states.reconcile += 1,
            }
        }
        Ok(states)
    }

    /// Resubmit at most `limit` in-doubt attempts that no waiter is driving, round-robin
    /// by slot. Entries are not removed: their owners collect the cached decision
    /// through `retry`, which pops the entry and its slot. Returns how many were sent.
    pub async fn settle_in_doubt(&self, limit: usize) -> Result<usize, AccessError> {
        let batch = {
            let mut pending = self.lock()?;
            let mut doubt = Vec::new();
            doubt
                .try_reserve(pending.attempts.len())
                .map_err(|_| AccessError::Overloaded)?;
            doubt.extend(
                pending
                    .attempts
                    .values()
                    .filter(|entry| !entry.driving && entry.attempt.state() == State::Uncertain)
                    .map(|entry| (entry.slot, entry.attempt.clone())),
            );
            doubt.sort_by_key(|(slot, _)| *slot);
            let start = doubt.partition_point(|(slot, _)| *slot < pending.settle_cursor);
            let take = limit.min(doubt.len());
            let mut batch = Vec::new();
            batch
                .try_reserve_exact(take)
                .map_err(|_| AccessError::Overloaded)?;
            batch.extend(
                doubt
                    .iter()
                    .cycle()
                    .skip(start)
                    .take(take)
                    .map(|(_, attempt)| attempt.clone()),
            );
            if let Some((slot, _)) = doubt.iter().cycle().skip(start).nth(take) {
                pending.settle_cursor = *slot;
            }
            batch
        };
        let sent = batch.len();
        for attempt in batch {
            // Busy means a waiter took it in the meantime: skip it.
            let _ = attempt.submit().await;
        }
        Ok(sent)
    }

    fn exhaustion(&self, pending: &Pending, starts: bool) {
        let mut states = SlotStates::default();
        for entry in pending.attempts.values() {
            match entry.attempt.state() {
                State::Uncertain => states.in_doubt += 1,
                State::Resolved => states.resolved_uncollected += 1,
                State::Reconcile => states.reconcile += 1,
                State::Prepared | State::InFlight => states.in_flight += 1,
            }
        }
        crate::diag_warn!(
            crate::diagnostics::STORE_INFLIGHT_EXHAUSTED,
            starts,
            in_doubt = states.in_doubt,
            resolved_uncollected = states.resolved_uncollected,
            reconcile = states.reconcile,
            "store in-flight queue exhausted"
        );
    }

    #[must_use]
    pub fn info(&self) -> BackendInfo {
        self.info
    }

    /// A native initial-namespace proof exists only while Startup owns unfinished
    /// first publication. Retained stores without that durable marker grant nothing.
    pub fn first_start(&self) -> Option<Arc<super::first_start::FirstStart>> {
        self.first_start.get().cloned()
    }

    pub fn authority(&self) -> Result<WriterAuthority, AccessError> {
        Ok(self.lock()?.authority)
    }

    /// Startup calls this only after the registrar's native grant is Applied.
    /// Registration shares this lock, so a prepared old candidate cannot cross
    /// after promotion. Existing attempts keep their original replay authority.
    pub(crate) fn promote_authority(&self, next: WriterAuthority) -> Result<(), AccessError> {
        let mut pending = self.lock()?;
        let current = pending.authority;
        if next.writer != current.writer
            || next.writer_epoch != current.writer_epoch
            || current.execution_epoch.checked_add(1) != Some(next.execution_epoch)
        {
            return Err(AccessError::Authority);
        }
        pending.authority = next;
        // In particular, promotion never reopens shutdown admission.
        Ok(())
    }

    /// Once promoted, no new registration can add work at or below this epoch.
    pub(crate) fn epoch_drained(&self, through: u64) -> Result<bool, AccessError> {
        let pending = self.lock()?;
        if through >= pending.authority.execution_epoch {
            return Err(AccessError::Authority);
        }
        Ok(!pending
            .attempts
            .values()
            .any(|entry| entry.attempt.candidate().candidate().id.execution_epoch <= through))
    }

    /// Conservative domain publication barrier while any retained operation can
    /// still affect this namespace. No operation is resolved or discarded here.
    pub(crate) fn has_pending_namespace(
        &self,
        namespace: busbar_contract::persistence::NamespaceId,
    ) -> Result<bool, AccessError> {
        Ok(self.lock()?.attempts.values().any(|entry| {
            entry
                .attempt
                .candidate()
                .candidate()
                .mutations
                .iter()
                .any(|mutation| {
                    let address = match mutation {
                        busbar_contract::persistence::Mutation::Put { address, .. } => address,
                        busbar_contract::persistence::Mutation::Delete(address) => address,
                        busbar_contract::persistence::Mutation::DeleteRange {
                            namespace: affected,
                            ..
                        } => return *affected == namespace,
                    };
                    address.namespace == namespace.0
                })
        }))
    }

    /// Uncertain or cancelled namespace work; actively driven operations can
    /// proceed concurrently under their domain's exact predicates.
    pub(crate) fn has_unresolved_namespace(
        &self,
        namespace: busbar_contract::persistence::NamespaceId,
    ) -> Result<bool, AccessError> {
        Ok(self
            .lock()?
            .attempts
            .values()
            .filter(|entry| !entry.driving)
            .any(|entry| {
                entry.attempt.candidate().candidate().mutations.iter().any(
                    |mutation| match mutation {
                        busbar_contract::persistence::Mutation::Put { address, .. }
                        | busbar_contract::persistence::Mutation::Delete(address) => {
                            address.namespace == namespace.0
                        }
                        busbar_contract::persistence::Mutation::DeleteRange {
                            namespace: affected,
                            ..
                        } => *affected == namespace,
                    },
                )
            }))
    }

    /// Let a core domain classify retained uncertainty using its own opaque
    /// address/value vocabulary. The closure performs no backend calls.
    pub(crate) fn unresolved_matches(
        &self,
        matches: impl Fn(&busbar_contract::persistence::Candidate) -> bool,
    ) -> Result<bool, AccessError> {
        Ok(self
            .lock()?
            .attempts
            .values()
            .filter(|entry| !entry.driving)
            .any(|entry| matches(entry.attempt.candidate().candidate())))
    }

    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    /// Allocate an independent attempt identity, never from wall time or a label:
    /// the per-boot `node8 ‖ counter8` of `door::op_id`, unique across restarts,
    /// nodes and every CoreStore in this process.
    pub(crate) fn next_id(&self) -> Result<AttemptId, AccessError> {
        let authority = {
            let pending = self.lock()?;
            if !pending.accepting {
                return Err(AccessError::Closed);
            }
            pending.authority
        };
        let operation = crate::door::op_id().0;
        if operation == [0; 16] {
            return Err(AccessError::Entropy);
        }
        Ok(AttemptId {
            dataset: self.info.dataset,
            writer_epoch: authority.writer_epoch,
            writer: authority.writer,
            execution_epoch: authority.execution_epoch,
            operation,
        })
    }

    /// Core domain access only. Plugin callers cannot obtain a raw Store through
    /// the public host service interface or the CoreStore public API.
    pub(crate) fn backend(&self) -> &dyn PersistenceBackend {
        self.backend.as_ref()
    }

    /// Register ownership before the first crossing. Cancellation leaves the map
    /// and exact attempt intact; callers subsequently use `retry` with its ID.
    pub(crate) async fn submit(
        &self,
        candidate: PreparedCandidate,
    ) -> Result<Submission, AccessError> {
        let (id, attempt) = self.register(candidate, None)?;
        self.drive(id, attempt).await
    }

    /// [`CoreStore::submit`], also answering why a [`SubmitResult::NoEffect`] applied nothing
    /// (#319 r4 §7.1): the record-format driver may shrink a page only for a backend refusal of a
    /// send with no earlier uncertainty, never for a fence or a slot invariant the facade reports
    /// as the same `Failure::Refused`.
    pub(crate) async fn submit_traced(
        &self,
        candidate: PreparedCandidate,
    ) -> Result<(Submission, Option<NoEffectCause>), AccessError> {
        let (id, attempt) = self.register(candidate, None)?;
        let submission = self.drive(id, attempt.clone()).await?;
        let cause = match submission.result {
            SubmitResult::NoEffect(_) => attempt.no_effect_cause(),
            _ => None,
        };
        Ok((submission, cause))
    }

    /// [`CoreStore::submit`] for a plain write made under `domain`: the attempt is registered
    /// with the domain's owner and this call's foreground reservation before the first crossing,
    /// so a canceled caller leaves it discoverable to that owner's maintenance, exactly as a
    /// logical (conditional) write does.
    pub(crate) async fn submit_in(
        &self,
        candidate: PreparedCandidate,
        domain: Option<&DomainCall>,
    ) -> Result<Submission, AccessError> {
        let (id, attempt) = self.register_owned(candidate, None, false, domain)?;
        self.drive_with(id, attempt, domain.map(|call| &call.foreground))
            .await
    }

    /// Identity's canonical owner marks custody before its first native crossing.
    pub(crate) async fn submit_identity(
        &self,
        candidate: PreparedCandidate,
    ) -> Result<Submission, AccessError> {
        let (id, attempt) = self.register_owned(candidate, None, true, None)?;
        self.drive(id, attempt).await
    }

    /// Settle only inactive attempts registered by the canonical identity owner.
    /// This delivers no projected mutation result: publication must read a fresh
    /// coherent identity snapshot, including after definitive no-effect decisions.
    pub(crate) async fn settle_identity_pending(&self) -> Result<bool, AccessError> {
        let attempts = {
            let pending = self.lock()?;
            let mut attempts = Vec::new();
            attempts
                .try_reserve(pending.attempts.len())
                .map_err(|_| AccessError::Overloaded)?;
            attempts.extend(
                pending
                    .attempts
                    .iter()
                    .filter(|(_, entry)| entry.identity_owned && !entry.driving)
                    .map(|(id, entry)| (*id, entry.attempt.clone())),
            );
            attempts
        };
        for (id, attempt) in attempts {
            match self.drive(id, attempt).await {
                Ok(_) | Err(AccessError::UnknownOperation) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(!self
            .lock()?
            .attempts
            .values()
            .any(|entry| entry.identity_owned))
    }

    fn register(
        &self,
        candidate: PreparedCandidate,
        logical: Option<&LogicalPermit<'_>>,
    ) -> Result<(PendingId, Arc<Attempt>), AccessError> {
        self.register_owned(candidate, logical, false, None)
    }

    fn register_owned(
        &self,
        candidate: PreparedCandidate,
        logical: Option<&LogicalPermit<'_>>,
        identity_owned: bool,
        domain: Option<&DomainCall>,
    ) -> Result<(PendingId, Arc<Attempt>), AccessError> {
        // The owning domain: a logical permit carries its own; a plain write names it directly.
        let owned_by = logical.and_then(|permit| permit.domain.as_ref()).or(domain);
        if owned_by.is_some_and(|call| !call.belongs_to(self)) {
            return Err(AccessError::Authority);
        }
        let id = candidate.candidate().id;
        let pending_id = PendingId(id.operation);
        let attempt = {
            let mut pending = self.lock()?;
            if !pending.accepting {
                return Err(AccessError::Closed);
            }
            if id.dataset != self.info.dataset
                || id.writer_epoch != pending.authority.writer_epoch
                || id.writer != pending.authority.writer
                || (id.execution_epoch != pending.authority.execution_epoch
                    && !pending.attempts.contains_key(&pending_id))
            {
                return Err(AccessError::Authority);
            }
            if let Some(permit) = logical {
                let entry = pending
                    .logical
                    .get(&permit.id)
                    .ok_or(AccessError::UnknownOperation)?;
                if !Arc::ptr_eq(&entry.token, &permit.token) || entry.pending.is_some() {
                    return Err(AccessError::OperationConflict);
                }
            }
            let attempt = if let Some(held) = pending.attempts.get(&pending_id) {
                if held.attempt.candidate().fingerprint() != candidate.fingerprint()
                    || held.logical != logical.map(|permit| permit.id)
                    || held.identity_owned != identity_owned
                    || !domain::same_owner(
                        held.domain.as_ref().map(|entry| &entry.owner),
                        owned_by.map(|call| &call.owner.id),
                    )
                {
                    return Err(AccessError::OperationConflict);
                }
                held.attempt.clone()
            } else {
                // Push: lease a slot in the same critical section that inserts the
                // entry. An empty free list is exactly a full map.
                let Some(slot) = pending.free.pop() else {
                    if !self.exhausted.swap(true, Ordering::Relaxed) {
                        self.exhaustion(&pending, true);
                    }
                    return Err(AccessError::Overloaded);
                };
                if pending.attempts.try_reserve(1).is_err() {
                    pending.free.push(slot);
                    return Err(AccessError::Overloaded);
                }
                let seq = pending.next_seq;
                let key = super::slot_seal::slotted(slot, seq).ok_or(AccessError::Corrupt);
                let attempt = key.and_then(|key| {
                    Attempt::slotted(candidate, key, self.backend.clone())
                        .map_err(|_| AccessError::Authority)
                });
                let attempt = match attempt {
                    Ok(attempt) => Arc::new(attempt),
                    Err(error) => {
                        pending.free.push(slot);
                        return Err(error);
                    }
                };
                pending.next_seq = seq.checked_add(1).ok_or(AccessError::Corrupt)?;
                pending.attempts.insert(
                    pending_id,
                    PendingEntry {
                        attempt: attempt.clone(),
                        driving: false,
                        logical: logical.map(|permit| permit.id),
                        identity_owned,
                        domain: owned_by.map(|call| domain::Entry {
                            owner: call.owner.id.clone(),
                            foreground: Arc::downgrade(&call.foreground),
                        }),
                        slot,
                    },
                );
                attempt
            };
            if let Some(permit) = logical {
                // Registration and logical binding share the lock: even a retry
                // already knowing the pending ID cannot cross before custody binds.
                pending
                    .logical
                    .get_mut(&permit.id)
                    .ok_or(AccessError::UnknownOperation)?
                    .pending = Some(pending_id);
            }
            attempt
        };
        Ok((pending_id, attempt))
    }

    /// Retry retained work only. This still works after stopping new admission.
    pub async fn retry(&self, id: PendingId) -> Result<Submission, AccessError> {
        let held = self
            .lock()?
            .attempts
            .get(&id)
            .map(|entry| entry.attempt.clone())
            .ok_or(AccessError::UnknownOperation)?;
        self.drive(id, held).await
    }

    async fn drive(&self, id: PendingId, attempt: Arc<Attempt>) -> Result<Submission, AccessError> {
        self.drive_with(id, attempt, None).await
    }

    async fn drive_with(
        &self,
        id: PendingId,
        attempt: Arc<Attempt>,
        foreground: Option<&Arc<()>>,
    ) -> Result<Submission, AccessError> {
        {
            let mut pending = self.lock()?;
            let entry = pending
                .attempts
                .get_mut(&id)
                .ok_or(AccessError::UnknownOperation)?;
            if !Arc::ptr_eq(&entry.attempt, &attempt) {
                return Err(AccessError::OperationConflict);
            }
            let reserved_elsewhere = entry.domain.as_ref().is_some_and(|domain| {
                foreground.is_none_or(|held| {
                    !std::sync::Weak::ptr_eq(&domain.foreground, &Arc::downgrade(held))
                })
            });
            if entry.driving || reserved_elsewhere {
                return Ok(Submission {
                    id,
                    result: SubmitResult::Busy,
                });
            }
            entry.driving = true;
        }
        // The facade owns crossing admission as well as candidate custody. Without
        // this guard a NoEffect waiter could remove an entry while another caller
        // has already started its retry, losing ownership of an uncertain result.
        let _driving = Driving {
            store: self,
            id,
            attempt: attempt.clone(),
        };
        let result = attempt.submit().await;
        if matches!(result, SubmitResult::Decided(_) | SubmitResult::NoEffect(_)) {
            let mut pending = self.lock()?;
            // A resolved older waiter must never remove a different operation owner.
            if pending
                .attempts
                .get(&id)
                .is_some_and(|held| Arc::ptr_eq(&held.attempt, &attempt))
            {
                if let Some(entry) = pending.attempts.remove(&id) {
                    // Pop: the slot returns in the same critical section that removes
                    // the entry. Its next lease carries a larger seq.
                    pending.free.push(entry.slot);
                    if self.exhausted.swap(false, Ordering::Relaxed) {
                        self.exhaustion(&pending, false);
                    }
                    if let Some(logical) = entry.logical {
                        if pending
                            .logical
                            .get(&logical)
                            .is_some_and(|entry| entry.pending == Some(id))
                        {
                            pending.logical.remove(&logical);
                        }
                    }
                }
            }
        }
        Ok(Submission { id, result })
    }

    /// Observe physical attempts and planners that have not yet bound an attempt.
    /// This does not close admission or grant retry authority for a planner.
    pub fn pending_operations(&self) -> Result<usize, AccessError> {
        let pending = self.lock()?;
        pending
            .attempts
            .len()
            .checked_add(
                pending
                    .logical
                    .values()
                    .filter(|entry| entry.pending.is_none())
                    .count(),
            )
            .ok_or(AccessError::Overloaded)
    }

    /// Stop new operations and report every retained identity, without discarding
    /// debt or claiming the backend is quiescent. Shutdown owns reconciliation.
    pub fn stop_admission(&self) -> Result<Vec<PendingId>, AccessError> {
        let mut pending = self.lock()?;
        pending.accepting = false;
        let mut ids = Vec::new();
        ids.try_reserve_exact(pending.attempts.len())
            .map_err(|_| AccessError::Overloaded)?;
        ids.extend(pending.attempts.keys().copied());
        Ok(ids)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Pending>, AccessError> {
        self.pending.lock().map_err(|_| AccessError::Corrupt)
    }
}

struct Driving<'a> {
    store: &'a CoreStore,
    id: PendingId,
    attempt: Arc<Attempt>,
}

impl Drop for Driving<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.store.pending.lock() {
            if let Some(entry) = pending.attempts.get_mut(&self.id) {
                if Arc::ptr_eq(&entry.attempt, &self.attempt) {
                    entry.driving = false;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "facade_tests.rs"]
mod tests;
