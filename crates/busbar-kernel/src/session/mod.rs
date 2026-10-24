// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `session` — the neutral, protocol-blind session substrate.
//!
//! # What this is, and why it is CORE
//!
//! A `(session, owner) → opaque slot` store: core owns the **identity, lifecycle, TTL, eviction and
//! bound**; each **owner** — the neutral gate, or a plane — writes an **opaque** value core never
//! interprets. This is the *neutral mechanism + opaque payload* pattern applied to per-session state,
//! exactly like [`crate::plane`]'s type-erased plane slots but keyed by session.
//!
//! It is core (not any one plane's feature) by the decision rule — **two or more planes need it:** a
//! plane's cache-affinity and the gate's incremental-scan want an ephemeral per-session set; another
//! plane's tasks want durable per-session state (today `plane::taskstore`, a special case that folds
//! in here); a future protocol (a VPN tunnel) *is* a durable session. One substrate, many tenants; a
//! new tenant is one new [`OwnerKey`], zero substrate code.
//!
//! # In-process-first, safe degradation (owner-ruled state fork)
//!
//! This is the in-process working set: per-replica, ephemeral, bounded. Durability is a per-tenant
//! write-through the OWNER drives (a plane keeps writing through its own `PlaneStore`); it is not the
//! substrate's concern. A cold / evicted / cross-replica slot is **never wrong, only less optimized**
//! — the consumer falls back to its stateless path (full re-scan, pure-hash affinity, independent
//! metering). A Store-backed shared impl is a later drop-in behind the same API.
//!
//! # Bound is a memory-safety property
//!
//! Unbounded per-session slots would be a hole. Every slot has an optional TTL and the store has a
//! hard capacity; on overflow the least-recently-used **unpinned** slot is evicted. **Pinned** slots
//! (a durable/active tenant such as another plane's live task) are exempt from LRU and TTL — they
//! leave only by explicit removal — so eviction can never silently drop state a tenant still owns.
//!
//! Time is passed in as `now_ms` (epoch millis) rather than read here, so lifecycle is deterministic
//! and testable and the substrate takes no ambient clock.

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// The neutral session identity — a stable hash of the request's session key (e.g. the `x-session-id`
/// affinity header already read for every operation at ingress). An opaque `u64`; the substrate never
/// inspects what produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey(pub u64);

/// Which tenant owns a slot under a session — a `&'static str` the owner declares (e.g. the gate's
/// screen cache, a plane's cache-affinity, a plane's task set). Distinct owners never collide, so two
/// tenants can hold independent state for the same session.
pub type OwnerKey = &'static str;

/// The most expired slots one `put` drops. The sweep walks the expiry order from its front, so each
/// call does bounded work under the lock however many slots expired since the last one; a backlog
/// drains at this many slots per put, far faster than one put can add to it.
const SWEEP_PER_PUT: usize = 64;

type SlotKey = (SessionKey, OwnerKey);

struct Slot {
    value: Arc<dyn Any + Send + Sync>,
    /// Pinned slots are exempt from LRU and TTL — explicit-removal-only. For durable/active tenants
    /// (another plane's live tasks) so eviction cannot drop state the tenant still owns.
    pinned: bool,
    /// The slot's place in the recency order: `(last touch, touch sequence)`. Unused while `pinned`.
    lru_at: (u64, u64),
    /// Absolute expiry; `None` = no TTL. Ignored while `pinned`.
    expires_at_ms: Option<u64>,
    /// Breaks ties in the expiry order; fixed for the slot's life.
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

    /// Remove a slot and its places in both orders.
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

    /// Move a live slot to the recency front and hand back its value.
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

    /// Drop at most `budget` expired unpinned slots, earliest expiry first.
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

    /// While over `capacity`, evict the least-recently-used UNPINNED slot. Pinned slots are never in
    /// the recency order — so the store may exceed `capacity` if pinned slots alone exceed it, which
    /// is correct: pinned = a tenant still owns it.
    fn bound(&mut self, capacity: usize) {
        while self.map.len() > capacity {
            match self.lru.first_key_value() {
                Some((_, &key)) => {
                    self.take(&key);
                }
                // Only pinned slots remain; they are exempt, so stop.
                None => break,
            }
        }
    }
}

/// The neutral session substrate. Cheap to clone the handle (`Arc` internally is the caller's job if
/// shared); typically one process-global instance.
///
/// Every operation is bounded: a `get`, `put` or `remove` costs O(log n) in the slot count, plus at
/// most `SWEEP_PER_PUT` expired-slot drops per `put` — never a walk of the whole store under the
/// lock, which at the production capacity would serialise every gated request behind it.
pub struct SessionStore {
    inner: Mutex<Slots>,
    /// Hard cap on live slots — the memory-safety bound. Unpinned slots are evicted LRU on overflow.
    capacity: usize,
    /// Default TTL applied to `put` when the caller does not specify one; `None` = no default.
    default_ttl_ms: Option<u64>,
}

impl SessionStore {
    /// A substrate bounded to `capacity` slots, with an optional default TTL.
    pub fn new(capacity: usize, default_ttl_ms: Option<u64>) -> SessionStore {
        SessionStore {
            inner: Mutex::new(Slots::default()),
            capacity: capacity.max(1),
            default_ttl_ms,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slots> {
        // Poison-recovering: a panicking tenant must not wedge the substrate for every other tenant.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write an opaque value for `(session, owner)`, replacing any existing slot. `pinned` exempts it
    /// from LRU/TTL (use for durable/active tenants). Uses the default TTL unless `ttl_ms` overrides;
    /// `pinned` slots ignore TTL. Drops a bounded batch of expired slots, then evicts the LRU
    /// unpinned slot if this still pushes past capacity — so an expired slot is always dropped
    /// before a live one is evicted.
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

    /// Read the opaque value for `(session, owner)`, downcast to `T`. Touches LRU. Returns `None` if
    /// absent, expired (the expired slot is dropped), or the stored type is not `T`.
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
        // Cheap Arc<dyn Any> → Arc<T> without cloning the inner value on failure.
        slots.touch(&key, now_ms)?.downcast::<T>().ok()
    }

    /// Remove a slot regardless of pin state (the only way a pinned slot leaves).
    pub fn remove(&self, session: SessionKey, owner: OwnerKey) -> bool {
        self.lock().take(&(session, owner)).is_some()
    }

    /// Current slot count, expired slots not yet swept included (for tests/metrics).
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// Whether the substrate holds no slots.
    pub fn is_empty(&self) -> bool {
        self.lock().map.is_empty()
    }
}

#[cfg(test)]
#[path = "tests/session_tests.rs"]
mod session_tests;
