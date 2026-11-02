// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// The neutral session identity — a stable hash of the request's session key (e.g. the `x-session-id`
/// affinity header already read for every operation at ingress). An opaque `u64`; the substrate never
/// inspects what produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey(pub u64);

pub type OwnerKey = &'static str;

const SWEEP_PER_PUT: usize = 64;

type SlotKey = (SessionKey, OwnerKey);

struct Slot {
    value: Arc<dyn Any + Send + Sync>,

    pinned: bool,

    lru_at: (u64, u64),

    expires_at_ms: Option<u64>,

    id: u64,
}

impl Slot {
    fn is_expired(&self, now_ms: u64) -> bool {
        !self.pinned && self.expires_at_ms.is_some_and(|e| now_ms >= e)
    }
}

/// The slots and the two orders over them, under one lock. `lru` holds every UNPINNED slot by
/// `(last touch, touch sequence)`; `expiry` holds every unpinned slot with a TTL by
/// `(expires at, id)`. Both are kept in step with `map` by `insert`/`take`/`touch`, so the LRU victim
/// and the next expired slot are each the front of an ordered map, never a scan of every slot.
#[derive(Default)]
struct Slots {
    map: HashMap<SlotKey, Slot>,
    lru: BTreeMap<(u64, u64), SlotKey>,
    expiry: BTreeMap<(u64, u64), SlotKey>,
    tick: u64,
}

impl Slots {
    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn insert(
        &mut self,
        key: SlotKey,
        value: Arc<dyn Any + Send + Sync>,
        pinned: bool,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) {
        self.take(&key);
        let id = self.next_tick();
        let lru_at = (now_ms, id);
        if !pinned {
            self.lru.insert(lru_at, key);
            if let Some(e) = expires_at_ms {
                self.expiry.insert((e, id), key);
            }
        }
        self.map.insert(
            key,
            Slot {
                value,
                pinned,
                lru_at,
                expires_at_ms,
                id,
            },
        );
    }

    fn take(&mut self, key: &SlotKey) -> Option<Slot> {
        let slot = self.map.remove(key)?;
        if !slot.pinned {
            self.lru.remove(&slot.lru_at);
            if let Some(e) = slot.expires_at_ms {
                self.expiry.remove(&(e, slot.id));
            }
        }
        Some(slot)
    }

    fn touch(&mut self, key: &SlotKey, now_ms: u64) -> Option<Arc<dyn Any + Send + Sync>> {
        let tick = self.next_tick();
        let slot = self.map.get_mut(key)?;
        if !slot.pinned {
            self.lru.remove(&slot.lru_at);
            slot.lru_at = (now_ms, tick);
            self.lru.insert(slot.lru_at, *key);
        }
        Some(slot.value.clone())
    }

    fn sweep_expired(&mut self, now_ms: u64, budget: usize) {
        for _ in 0..budget {
            match self.expiry.first_key_value() {
                Some((&(e, _), &key)) if now_ms >= e => {
                    self.take(&key);
                }
                _ => break,
            }
        }
    }

    fn bound(&mut self, capacity: usize) {
        while self.map.len() > capacity {
            match self.lru.first_key_value() {
                Some((_, &key)) => {
                    self.take(&key);
                }

                None => break,
            }
        }
    }
}

pub struct SessionStore {
    inner: Mutex<Slots>,

    capacity: usize,

    default_ttl_ms: Option<u64>,
}

impl SessionStore {
    pub fn new(capacity: usize, default_ttl_ms: Option<u64>) -> SessionStore {
        SessionStore {
            inner: Mutex::new(Slots::default()),
            capacity: capacity.max(1),
            default_ttl_ms,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn put<T: Any + Send + Sync>(
        &self,
        session: SessionKey,
        owner: OwnerKey,
        value: Arc<T>,
        now_ms: u64,
        pinned: bool,
        ttl_ms: Option<u64>,
    ) {
        let expires_at_ms = if pinned {
            None
        } else {
            ttl_ms
                .or(self.default_ttl_ms)
                .map(|d| now_ms.saturating_add(d))
        };
        let mut slots = self.lock();
        slots.insert((session, owner), value, pinned, now_ms, expires_at_ms);
        slots.sweep_expired(now_ms, SWEEP_PER_PUT);
        slots.bound(self.capacity);
    }

    pub fn get<T: Any + Send + Sync>(
        &self,
        session: SessionKey,
        owner: OwnerKey,
        now_ms: u64,
    ) -> Option<Arc<T>> {
        let mut slots = self.lock();
        let key = (session, owner);
        if slots.map.get(&key)?.is_expired(now_ms) {
            slots.take(&key);
            return None;
        }

        slots.touch(&key, now_ms)?.downcast::<T>().ok()
    }

    pub fn remove(&self, session: SessionKey, owner: OwnerKey) -> bool {
        self.lock().take(&(session, owner)).is_some()
    }

    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().map.is_empty()
    }
}

#[cfg(test)]
#[path = "tests/session_tests.rs"]
mod session_tests;
