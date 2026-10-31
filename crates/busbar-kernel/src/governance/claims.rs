// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-key serialization that never holds a lock across a plugin call (§11.13 M1).
//!
//! A [`ClaimSet`] serializes read-modify-write sections that share a KEY (one subject, one key id)
//! while sections with different keys run side by side. The set's own mutex is held only to check
//! and insert a key, and again to remove it; the section itself, store calls and all, runs with no
//! lock held. A contender for a key already claimed waits on the set's condvar until the holder's
//! [`Claim`] drops, so a store call that does not come back holds up only callers of its own key.
//!
//! The claim is released when its guard drops, unwinding included, so a panicking holder frees its
//! key exactly as a poisoned-and-recovered mutex used to.

use std::collections::BTreeSet;
use std::sync::{Condvar, Mutex};

/// The keys currently claimed, and the condvar their release is announced on.
pub struct ClaimSet<K> {
    held: Mutex<BTreeSet<K>>,
    freed: Condvar,
}

impl<K: Ord + Clone> ClaimSet<K> {
    /// An empty set; `const` so a process-wide set can be a plain `static`.
    pub const fn new() -> Self {
        Self {
            held: Mutex::new(BTreeSet::new()),
            freed: Condvar::new(),
        }
    }

    /// Claim `key`, waiting while another caller holds it. Blocking: call it on a blocking thread
    /// (or a plain thread), never on an async worker.
    pub fn claim(&self, key: K) -> Claim<'_, K> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        while held.contains(&key) {
            held = self.freed.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        held.insert(key.clone());
        Claim { set: self, key }
    }
}

impl<K: Ord + Clone> Default for ClaimSet<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// A held key; dropping it releases the key and wakes its contenders.
pub struct Claim<'a, K: Ord> {
    set: &'a ClaimSet<K>,
    key: K,
}

impl<K: Ord> Drop for Claim<'_, K> {
    fn drop(&mut self) {
        let mut held = self.set.held.lock().unwrap_or_else(|e| e.into_inner());
        held.remove(&self.key);
        drop(held);
        self.set.freed.notify_all();
    }
}
