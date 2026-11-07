// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! In-process logical planning ownership. Durable logical receipts remain domain
//! records committed with effects; this map is neither a journal nor a receipt.

use super::{AccessError, CoreStore, PendingId, PreparedCandidate, Submission};
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
}

impl CoreStore {
    pub(crate) fn claim_logical(
        &self,
        id: LogicalId,
        digest: [u8; 32],
    ) -> Result<LogicalClaim<'_>, AccessError> {
        let mut pending = self.lock()?;
        if let Some(entry) = pending.logical.get(&id) {
            if entry.digest != digest {
                return Err(AccessError::OperationConflict);
            }
            return Ok(match entry.pending {
                Some(id) => LogicalClaim::Retained(id),
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
            },
        );
        Ok(LogicalClaim::Prepare(LogicalPermit {
            store: self,
            id,
            token,
        }))
    }
}

impl LogicalPermit<'_> {
    pub(crate) async fn submit(
        self,
        candidate: PreparedCandidate,
    ) -> Result<Submission, AccessError> {
        let (id, attempt) = self.store.register(candidate, Some(&self))?;
        self.store.drive(id, attempt).await
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
