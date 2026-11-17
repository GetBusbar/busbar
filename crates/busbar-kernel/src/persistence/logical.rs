// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! In-process logical planning ownership. Durable logical receipts remain domain
//! records committed with effects; this map is neither a journal nor a receipt.

use super::{domain, AccessError, CoreStore, DomainCall, PendingId, PreparedCandidate, Submission};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LogicalId {
    pub namespace: [u8; 16],
    pub operation: [u8; 16],
}

pub(super) struct Entry {
    pub digest: [u8; 32],
    pub token: Arc<()>,
    pub pending: Option<PendingId>,
    pub domain: Option<Arc<()>>,
}

pub(crate) enum LogicalClaim<'a> {
    Prepare(LogicalPermit<'a>),
    Retained(PendingId),
    Busy,
}

/// A single planner owns a logical operation until it either abandons its reads
/// or binds an immutable native attempt. No mutex is held across an await.
pub(crate) struct LogicalPermit<'a> {
    store: &'a CoreStore,
    pub(super) id: LogicalId,
    pub(super) token: Arc<()>,
    pub(super) domain: Option<DomainCall>,
}

impl CoreStore {
    pub(crate) fn claim_logical(
        &self,
        id: LogicalId,
        digest: [u8; 32],
    ) -> Result<LogicalClaim<'_>, AccessError> {
        self.claim_logical_owned(id, digest, None)
    }

    pub(crate) fn claim_logical_owned(
        &self,
        id: LogicalId,
        digest: [u8; 32],
        domain: Option<&DomainCall>,
    ) -> Result<LogicalClaim<'_>, AccessError> {
        if domain.is_some_and(|call| !call.belongs_to(self)) {
            return Err(AccessError::Authority);
        }
        let mut pending = self.lock()?;
        if let Some(entry) = pending.logical.get(&id) {
            if entry.digest != digest
                || !domain::same_owner(entry.domain.as_ref(), domain.map(|call| &call.owner.id))
            {
                return Err(AccessError::OperationConflict);
            }
            return Ok(match entry.pending {
                Some(id) => {
                    if let Some(call) = domain {
                        let held = pending.attempts.get_mut(&id).ok_or(AccessError::Corrupt)?;
                        let owner = held.domain.as_mut().ok_or(AccessError::Corrupt)?;
                        if !Arc::ptr_eq(&owner.owner, &call.owner.id) {
                            return Err(AccessError::Corrupt);
                        }
                        if owner
                            .foreground
                            .upgrade()
                            .is_some_and(|active| !Arc::ptr_eq(&active, &call.foreground))
                        {
                            return Ok(LogicalClaim::Busy);
                        }
                        owner.foreground = Arc::downgrade(&call.foreground);
                    }
                    LogicalClaim::Retained(id)
                }
                None => LogicalClaim::Busy,
            });
        }
        // Closing admission refuses new planning, while retained attempts keep
        // their original retry authority after a caller cancellation.
        if !pending.accepting {
            return Err(AccessError::Closed);
        }
        if pending.logical.len() >= self.limits.pending_operations {
            return Err(AccessError::Overloaded);
        }
        pending
            .logical
            .try_reserve(1)
            .map_err(|_| AccessError::Overloaded)?;
        let token = Arc::new(());
        pending.logical.insert(
            id,
            Entry {
                digest,
                token: token.clone(),
                pending: None,
                domain: domain.map(|call| call.owner.id.clone()),
            },
        );
        Ok(LogicalClaim::Prepare(LogicalPermit {
            store: self,
            id,
            token,
            domain: domain.cloned(),
        }))
    }
}

impl LogicalPermit<'_> {
    pub(crate) async fn submit(
        self,
        candidate: PreparedCandidate,
    ) -> Result<Submission, AccessError> {
        let (id, attempt) = self.store.register(candidate, Some(&self))?;
        self.store
            .drive_with(
                id,
                attempt,
                self.domain.as_ref().map(|call| &call.foreground),
            )
            .await
    }
}

impl Drop for LogicalPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.store.pending.lock() {
            if pending.logical.get(&self.id).is_some_and(|entry| {
                Arc::ptr_eq(&entry.token, &self.token) && entry.pending.is_none()
            }) {
                pending.logical.remove(&self.id);
            }
        }
    }
}
