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

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};

/// The keys currently claimed, and the condvar their release is announced on.
pub struct ClaimSet<K> {
    held: Mutex<BTreeMap<K, std::thread::ThreadId>>,
    freed: Condvar,
    #[cfg(test)]
    observed_waits:
        Mutex<std::collections::BTreeMap<K, std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}

impl<K: Ord + Clone> ClaimSet<K> {
    /// An empty set; `const` so a process-wide set can be a plain `static`.
    pub const fn new() -> Self {
        Self {
            held: Mutex::new(BTreeMap::new()),
            freed: Condvar::new(),
            #[cfg(test)]
            observed_waits: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Observe an actual wait for this key in this set, without changing claim arbitration.
    #[cfg(test)]
    pub(crate) fn observe_wait(&self, key: K) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.observed_waits
            .lock()
            .unwrap()
            .insert(key, observed.clone());
        observed
    }

    #[cfg(test)]
    fn record_wait(&self, key: &K) {
        if let Some(observed) = self.observed_waits.lock().unwrap().get(key) {
            observed.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// Claim `key`, waiting while another caller holds it. Blocking: call it on a blocking thread
    /// (or a plain thread), never on an async worker.
    pub fn claim(&self, key: K) -> Claim<'_, K> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        while held.contains_key(&key) {
            #[cfg(test)]
            self.record_wait(&key);
            held = self.freed.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        held.insert(key.clone(), std::thread::current().id());
        Claim { set: self, key }
    }

    /// Wait for another thread at the top level. Refuse a contended nested claim so callbacks
    /// cannot form a wait cycle with an outer claim. An available unrelated key still succeeds.
    pub fn claim_checked(&self, key: K) -> Option<Claim<'_, K>> {
        let owner = std::thread::current().id();
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        while held.contains_key(&key) {
            if held.values().any(|current| *current == owner) {
                return None;
            }
            #[cfg(test)]
            self.record_wait(&key);
            held = self.freed.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        held.insert(key.clone(), owner);
        Some(Claim { set: self, key })
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
