// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only attachment and pending-operation ownership. Business modules receive
//! this facade; the raw backend stays private to core persistence coordination.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::persistence::{
    control, Address, AttemptId, BackendInfo, Failure, PersistenceBackend, PreparedCandidate, Read,
    ReadResult,
};

use super::commit::{Attempt, SubmitResult};

#[path = "logical.rs"]
mod logical;
pub(crate) use logical::{LogicalClaim, LogicalId, LogicalPermit};

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
}

struct PendingEntry {
    attempt: Arc<Attempt>,
    driving: bool,
    logical: Option<LogicalId>,
    identity_owned: bool,
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
    pub(super) claim_maintenance: Mutex<super::claims::Maintenance>,
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
        if limits.pending_operations == 0 || limits.scan_items == 0 || limits.scan_bytes == 0 {
            return Err(AccessError::InvalidLimits);
        }
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
            pending: Mutex::new(Pending {
                authority,
                accepting: true,
                attempts: HashMap::new(),
                logical: HashMap::new(),
            }),
        })
    }

    #[must_use]
    pub fn info(&self) -> BackendInfo {
        self.info
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

    /// Allocate an independent attempt identity, never from wall time or a label.
    pub(crate) fn next_id(&self) -> Result<AttemptId, AccessError> {
        let authority = {
            let pending = self.lock()?;
            if !pending.accepting {
                return Err(AccessError::Closed);
            }
            pending.authority
        };
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).map_err(|_| AccessError::Entropy)?;
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

    /// Identity's canonical owner marks custody before its first native crossing.
    pub(crate) async fn submit_identity(
        &self,
        candidate: PreparedCandidate,
    ) -> Result<Submission, AccessError> {
        let (id, attempt) = self.register_owned(candidate, None, true)?;
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
        self.register_owned(candidate, logical, false)
    }

    fn register_owned(
        &self,
        candidate: PreparedCandidate,
        logical: Option<&LogicalPermit<'_>>,
        identity_owned: bool,
    ) -> Result<(PendingId, Arc<Attempt>), AccessError> {
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
                {
                    return Err(AccessError::OperationConflict);
                }
                held.attempt.clone()
            } else {
                if pending.attempts.len() >= self.limits.pending_operations {
                    return Err(AccessError::Overloaded);
                }
                pending
                    .attempts
                    .try_reserve(1)
                    .map_err(|_| AccessError::Overloaded)?;
                let attempt = Arc::new(
                    Attempt::new(candidate, self.backend.clone())
                        .map_err(|_| AccessError::Authority)?,
                );
                pending.attempts.insert(
                    pending_id,
                    PendingEntry {
                        attempt: attempt.clone(),
                        driving: false,
                        logical: logical.map(|permit| permit.id),
                        identity_owned,
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
        {
            let mut pending = self.lock()?;
            let entry = pending
                .attempts
                .get_mut(&id)
                .ok_or(AccessError::UnknownOperation)?;
            if !Arc::ptr_eq(&entry.attempt, &attempt) {
                return Err(AccessError::OperationConflict);
            }
            if entry.driving {
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
                if let Some(logical) = pending.attempts.remove(&id).and_then(|entry| entry.logical)
                {
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
