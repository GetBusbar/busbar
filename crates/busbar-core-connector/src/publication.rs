// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Requested storage held by one datagram pairing, including storage handed to its readers.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A pair's optional limit. This accounts requested storage, not allocator retention or RSS.
#[derive(Debug)]
pub struct Memory {
    limit: Option<usize>,
    state: Mutex<State>,
    pub(crate) changed: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct State {
    used: usize,
    readers: usize,
    closed: bool,
}

impl Memory {
    /// Capture the limit once for this pairing. `None` preserves unlimited custody.
    #[must_use]
    pub fn new(limit: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::new(State::default()),
            changed: tokio::sync::Notify::new(),
        })
    }

    /// The captured configured limit.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Requested storage still in host custody.
    #[must_use]
    pub fn used(&self) -> usize {
        lock(&self.state).used
    }

    pub(crate) fn readers(&self) -> bool { lock(&self.state).readers != 0 }

    pub(crate) fn can_fit(&self, bytes: usize) -> bool {
        bytes.checked_add(std::mem::size_of::<Lease>() + 2 * std::mem::size_of::<usize>())
            .is_some_and(|bytes| self.limit.is_none_or(|limit| bytes <= limit))
    }


    /// Reserve before allocating or crossing a framer. Failed reservations allocate nothing.
    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Custody> {
        if self.limit.is_none() {
            return Some(Custody::default());
        }
        let bytes = bytes.checked_add(std::mem::size_of::<Lease>())?
            .checked_add(2 * std::mem::size_of::<usize>())?;
        {
            let mut state = lock(&self.state);
            let used = state.used.checked_add(bytes)?;
            if state.closed || self.limit.is_some_and(|limit| used > limit) {
                return None;
            }
            state.used = used;
        }
        Some(Custody(Some(Arc::new(Lease {
            memory: Arc::clone(self),
            bytes,
            previous: Custody::default(),
        }))))
    }

    /// A reservation failure may wait only while an actual reader owns releasable storage.
    pub(crate) async fn reader_progress(&self) -> bool {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let state = lock(&self.state);
            if state.closed || state.readers == 0 {
                return false;
            }
        }
        changed.await;
        !lock(&self.state).closed
    }

    pub(crate) fn close(&self) {
        lock(&self.state).closed = true;
        self.changed.notify_waiters();
    }
}

#[derive(Debug)]
struct Lease {
    memory: Arc<Memory>,
    bytes: usize,
    previous: Custody,
}

impl Drop for Lease {
    fn drop(&mut self) {
        {
            let mut state = lock(&self.memory.state);
            state.used -= self.bytes;
        }
        self.memory.changed.notify_waiters();
    }
}

/// A shared storage reservation. Moving bytes to another host owner retains this reservation.
/// Cloning custody adds a reference to the same allocation; it never copies payload storage.
#[derive(Debug, Default, Clone)]
pub struct Custody(Option<Arc<Lease>>);

// Storage identity is deliberately absent from semantic output equality.
impl PartialEq for Custody {
    fn eq(&self, _: &Self) -> bool { true }
}
impl Eq for Custody {}

impl Custody {
    /// Chain a fresh batch's reservation to older eager output without another allocation.
    pub fn prepend(&mut self, older: Self) {
        if let Some(lease) = self.0.as_mut() {
            Arc::get_mut(lease).expect("a fresh batch has exclusive reservation custody").previous = older;
        } else {
            *self = older;
        }
    }

    /// Transfer to a reader. The guard survives until actual payload consumption or teardown.
    #[must_use]
    pub fn reader(&self) -> ReaderCustody {
        let memory = self.0.as_ref().map(|lease| Arc::clone(&lease.memory));
        if let Some(memory) = &memory {
            lock(&memory.state).readers += 1;
        }
        ReaderCustody { custody: self.clone(), memory }
    }
}

/// Reader ownership of charged output. Release follows consumption, including partial reads.
#[derive(Debug)]
pub struct ReaderCustody {
    custody: Custody,
    memory: Option<Arc<Memory>>,
}

impl Drop for ReaderCustody {
    fn drop(&mut self) {
        if let Some(memory) = &self.memory {
            lock(&memory.state).readers -= 1;
            memory.changed.notify_waiters();
        }
    }
}

/// One channel message and the reservation retained through the reader's last byte.
#[derive(Debug)]
pub struct Message {
    /// The copied opaque payload.
    pub bytes: Vec<u8>,
    /// Whether its last byte ends the message.
    pub end: bool,
    /// Bytes consumed without allocating a copied suffix.
    pub consumed: usize,
    /// Storage remains charged while this message is queued or partially read.
    pub custody: ReaderCustody,
}

