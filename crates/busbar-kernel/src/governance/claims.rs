// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};

pub struct ClaimSet<K> {
    held: Mutex<BTreeMap<K, std::thread::ThreadId>>,
    freed: Condvar,
    #[cfg(test)]
    observed_waits:
        Mutex<std::collections::BTreeMap<K, std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}

impl<K: Ord + Clone> ClaimSet<K> {
    pub const fn new() -> Self {
        Self {
            held: Mutex::new(BTreeMap::new()),
            freed: Condvar::new(),
            #[cfg(test)]
            observed_waits: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

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
