// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE OUTBOX: what a request hands over on its own core, for a flusher to pull.
//!
//! A request appends its record and answers. Appending takes this outbox's own lock, which only
//! the tasks of the core that owns it and that core's flusher pull ever take: no lock another
//! core holds, no thread hand-off, no signature, no hash step and no wake of anyone. The flusher
//! pulls on its own timer ([`CoreOutbox::drain`]): it swaps the held items for an empty vector, so
//! the buffer is made on the first append after a pull and released by the pull that takes it.
//!
//! Two callers may ask for an early pull and wait for the commit that holds their item: an
//! administrative change, and a metered request when the operator turned `wait_for_commit` on
//! ([`CoreOutbox::append_and_ask`], [`CoreOutbox::committed`]). Nobody else wakes the flusher.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::{watch, Notify};

/// Which append an item was: its position in this outbox, counting from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ticket(u64);

/// What one pull took: the items in append order and the ticket of the last of them.
#[derive(Debug)]
pub struct Drained<T> {
    /// The items, oldest first.
    pub items: Vec<T>,
    /// The ticket of the last item taken; every ticket at or below it is in `items` or earlier.
    pub through: u64,
}

struct Held<T> {
    items: Vec<T>,
    appended: u64,
}

/// One core's outbox. Owned by the core's listener loop and handed to every connection on it; the
/// flusher holds it while it lives.
pub struct CoreOutbox<T> {
    held: Mutex<Held<T>>,
    committed: watch::Sender<u64>,
    wake: Arc<Notify>,
}

impl<T> std::fmt::Debug for CoreOutbox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreOutbox").finish_non_exhaustive()
    }
}

impl<T> CoreOutbox<T> {
    /// An empty outbox whose early-pull requests ring `wake` (the flusher's).
    #[must_use]
    pub fn new(wake: Arc<Notify>) -> Self {
        Self {
            held: Mutex::new(Held {
                items: Vec::new(),
                appended: 0,
            }),
            committed: watch::Sender::new(0),
            wake,
        }
    }

    fn push(&self, item: T) -> Ticket {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.appended = held.appended.saturating_add(1);
        held.items.push(item);
        Ticket(held.appended)
    }

    /// Hand one record over and return at once. Wakes nobody.
    pub fn append(&self, item: T) -> Ticket {
        self.push(item)
    }

    /// Hand one record over and ask the flusher for a pull now: only an administrative change, or
    /// a metered request under `wait_for_commit`, which then awaits [`CoreOutbox::committed`].
    pub fn append_and_ask(&self, item: T) -> Ticket {
        let ticket = self.push(item);
        self.wake.notify_one();
        ticket
    }

    /// THE FLUSHER'S PULL: take every held item, leaving an empty vector (no capacity kept).
    pub fn drain(&self) -> Drained<T> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        Drained {
            items: std::mem::take(&mut held.items),
            through: held.appended,
        }
    }

    /// The flusher reports that every item through `through` is committed.
    pub fn settled(&self, through: u64) {
        self.committed.send_if_modified(|committed| {
            let moved = through > *committed;
            if moved {
                *committed = through;
            }
            moved
        });
    }

    /// Wait until the item of `ticket` is committed. The caller bounds the wait by its own
    /// deadline; a flusher that stopped is judged by the stall limit, not here.
    pub async fn committed(&self, ticket: Ticket) {
        let mut observed = self.committed.subscribe();
        let _ = observed.wait_for(|through| *through >= ticket.0).await;
    }

    /// Whether the item of `ticket` is committed now.
    #[must_use]
    pub fn is_committed(&self, ticket: Ticket) -> bool {
        *self.committed.borrow() >= ticket.0
    }

    /// Held, not yet pulled.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .len()
    }
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;
