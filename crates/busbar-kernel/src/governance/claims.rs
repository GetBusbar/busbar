// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};

pub struct ClaimSet<K> {
    held: Mutex<BTreeMap<K, std::thread::ThreadId>>,
    freed: Condvar,
}

impl<K: Ord + Clone> ClaimSet<K> {
    pub const fn new() -> Self {
        Self {
            held: Mutex::new(BTreeMap::new()),
            freed: Condvar::new(),
        }
    }

    pub fn claim(&self, key: K) -> Claim<'_, K> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        while held.contains_key(&key) {
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

/// Keyed ownership for futures. Only held keys occupy shared memory; suspended callers
/// retain their own key and never hold a synchronous mutex or a thread identity.
pub struct AsyncClaimSet<K> {
    held: Mutex<std::collections::BTreeSet<K>>,
    freed: tokio::sync::Notify,
}

impl<K: Ord + Clone> AsyncClaimSet<K> {
    pub const fn new() -> Self {
        Self {
            held: Mutex::new(std::collections::BTreeSet::new()),
            freed: tokio::sync::Notify::const_new(),
        }
    }

    pub fn try_claim(&self, key: K) -> Option<AsyncClaim<'_, K>> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        // Construct a release guard only when ownership was acquired. An eager
        // guard on failure would drop while this mutex is held and deadlock.
        if held.insert(key.clone()) {
            Some(AsyncClaim { set: self, key })
        } else {
            None
        }
    }

    pub async fn claim_async(&self, key: K) -> AsyncClaim<'_, K> {
        loop {
            // Register before inspecting ownership so a release between the inspection
            // and suspension cannot strand this waiter.
            let released = self.freed.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            {
                let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
                if held.insert(key.clone()) {
                    return AsyncClaim { set: self, key };
                }
            }
            released.await;
        }
    }
}

impl<K: Ord + Clone> Default for AsyncClaimSet<K> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AsyncClaim<'a, K: Ord> {
    set: &'a AsyncClaimSet<K>,
    key: K,
}

impl<K: Ord> Drop for AsyncClaim<'_, K> {
    fn drop(&mut self) {
        self.set
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
        self.set.freed.notify_waiters();
    }
}

#[cfg(test)]
#[path = "tests/claims_tests.rs"]
mod async_claim_tests;
