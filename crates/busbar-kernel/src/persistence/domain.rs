// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cancellation-safe domain discoverability in the facade's canonical attempt map.
//! A call holds the foreground reservation across submit and immediate retries;
//! dropping it makes retained work eligible for bounded owner maintenance.

use super::{AccessError, Attempt, CoreStore, PendingId, Submission};
use std::sync::{Arc, Weak};

pub(super) struct Entry {
    pub(super) owner: Arc<()>,
    pub(super) foreground: Weak<()>,
}

pub(super) fn same_owner(left: Option<&Arc<()>>, right: Option<&Arc<()>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

#[derive(Clone)]
pub(crate) struct DomainOwner {
    pub(super) store: Arc<CoreStore>,
    pub(super) id: Arc<()>,
}

#[derive(Clone)]
pub(crate) struct DomainCall {
    pub(super) owner: DomainOwner,
    pub(super) foreground: Arc<()>,
}

impl DomainOwner {
    pub(crate) fn new(store: Arc<CoreStore>) -> Self {
        Self {
            store,
            id: Arc::new(()),
        }
    }

    pub(crate) fn call(&self) -> DomainCall {
        DomainCall {
            owner: self.clone(),
            foreground: Arc::new(()),
        }
    }

    pub(crate) fn owns(&self, store: &CoreStore) -> bool {
        std::ptr::eq(&*self.store, store)
    }

    /// Collect only this owner's inactive candidates, including cached decisions.
    /// Reservations remain in the canonical map throughout every await. Canceling
    /// this pass drops its tokens and makes the same entries discoverable again.
    pub(crate) async fn settle(&self, limit: usize) -> Result<usize, AccessError> {
        let batch = {
            let mut pending = self.store.lock()?;
            let take = limit.min(pending.attempts.len());
            let mut batch = Vec::new();
            batch
                .try_reserve_exact(take)
                .map_err(|_| AccessError::Overloaded)?;
            for _ in 0..take {
                let next = pending
                    .attempts
                    .iter()
                    .filter_map(|(id, entry)| {
                        entry
                            .domain
                            .as_ref()
                            .filter(|domain| {
                                Arc::ptr_eq(&domain.owner, &self.id)
                                    && domain.foreground.strong_count() == 0
                                    && !entry.driving
                            })
                            .map(|_| (entry.slot, *id))
                    })
                    .min_by_key(|(slot, _)| (*slot < pending.settle_cursor, *slot));
                let Some((slot, id)) = next else { break };
                let entry = pending
                    .attempts
                    .get_mut(&id)
                    .ok_or(AccessError::UnknownOperation)?;
                let call = self.call();
                entry
                    .domain
                    .as_mut()
                    .ok_or(AccessError::Corrupt)?
                    .foreground = Arc::downgrade(&call.foreground);
                batch.push((id, entry.attempt.clone(), call));
                pending.settle_cursor = slot.saturating_add(1);
            }
            batch
        };
        for (id, attempt, call) in batch {
            match self
                .store
                .drive_with(id, attempt, Some(&call.foreground))
                .await
            {
                Ok(_) | Err(AccessError::UnknownOperation) => {}
                Err(error) => return Err(error),
            }
        }
        self.pending()
    }

    pub(crate) fn pending(&self) -> Result<usize, AccessError> {
        Ok(self
            .store
            .lock()?
            .attempts
            .values()
            .filter(|entry| {
                entry
                    .domain
                    .as_ref()
                    .is_some_and(|domain| Arc::ptr_eq(&domain.owner, &self.id))
            })
            .count())
    }
}

impl DomainCall {
    pub(crate) fn belongs_to(&self, store: &CoreStore) -> bool {
        self.owner.owns(store)
    }

    pub(crate) async fn retry(&self, id: PendingId) -> Result<Submission, AccessError> {
        let attempt: Arc<Attempt> = {
            let pending = self.owner.store.lock()?;
            let entry = pending
                .attempts
                .get(&id)
                .ok_or(AccessError::UnknownOperation)?;
            if !entry.domain.as_ref().is_some_and(|domain| {
                Arc::ptr_eq(&domain.owner, &self.owner.id)
                    && Weak::ptr_eq(&domain.foreground, &Arc::downgrade(&self.foreground))
            }) {
                return Err(AccessError::OperationConflict);
            }
            entry.attempt.clone()
        };
        self.owner
            .store
            .drive_with(id, attempt, Some(&self.foreground))
            .await
    }
}
