// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `session` — the neutral, protocol-blind session substrate. See
//! `docs/design/1.6.0-abi-solidification.md` (primitive A / gap G5) and
//! `docs/design/1.6.0-foundation-what-features-reveal.md` §2a.
//!
//! # What this is, and why it is CORE
//!
//! A `(session, owner) → opaque slot` store: core owns the **identity, lifecycle, TTL, eviction and
//! bound**; each **owner** — the neutral gate, or a plane — writes an **opaque** value core never
//! interprets. This is the *neutral mechanism + opaque payload* pattern applied to per-session state,
//! exactly like [`crate::plane`]'s type-erased plane slots but keyed by session.
//!
//! It is core (not an LLM feature) by the decision rule — **two or more planes need it:** LLM cache-
//! affinity and the gate's incremental-scan want an ephemeral per-session set; A2A tasks want durable
//! per-session state (today `plane::taskstore`, a special case that folds in here); a future protocol
//! (a VPN tunnel) *is* a durable session. One substrate, many tenants; a new tenant is one new
//! [`OwnerKey`], zero substrate code.
//!
//! # In-process-first, safe degradation (owner-ruled state fork)
//!
//! This is the in-process working set: per-replica, ephemeral, bounded. Durability is a per-tenant
//! write-through the OWNER drives (A2A keeps writing through its `PlaneStore`); it is not the
//! substrate's concern. A cold / evicted / cross-replica slot is **never wrong, only less optimized**
//! — the consumer falls back to its stateless path (full re-scan, pure-hash affinity, independent
//! metering). A Store-backed shared impl is a later drop-in behind the same API.
//!
//! # Bound is a memory-safety property
//!
//! Unbounded per-session slots would be a hole. Every slot has an optional TTL and the store has a
//! hard capacity; on overflow the least-recently-used **unpinned** slot is evicted. **Pinned** slots
//! (a durable/active tenant such as an A2A live task) are exempt from LRU and TTL — they leave only by
//! explicit removal — so eviction can never silently drop state a tenant still owns.
//!
//! Time is passed in as `now_ms` (epoch millis) rather than read here, so lifecycle is deterministic
//! and testable and the substrate takes no ambient clock.

use std::any::Any;
use std::collections::HashMap;
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

struct Slot {
    value: Arc<dyn Any + Send + Sync>,
    /// Pinned slots are exempt from LRU and TTL — explicit-removal-only. For durable/active tenants
    /// (A2A live tasks) so eviction cannot drop state the tenant still owns.
    pinned: bool,
    last_touch_ms: u64,
    /// Absolute expiry; `None` = no TTL. Ignored while `pinned`.
    expires_at_ms: Option<u64>,
}

impl Slot {
    fn is_expired(&self, now_ms: u64) -> bool {
        !self.pinned && self.expires_at_ms.is_some_and(|e| now_ms >= e)
    }
}

/// The neutral session substrate. Cheap to clone the handle (`Arc` internally is the caller's job if
/// shared); typically one process-global instance.
pub struct SessionStore {
    inner: Mutex<HashMap<(SessionKey, OwnerKey), Slot>>,
    /// Hard cap on live slots — the memory-safety bound. Unpinned slots are evicted LRU on overflow.
    capacity: usize,
    /// Default TTL applied to `put` when the caller does not specify one; `None` = no default.
    default_ttl_ms: Option<u64>,
}

impl SessionStore {
    /// A substrate bounded to `capacity` slots, with an optional default TTL.
    pub fn new(capacity: usize, default_ttl_ms: Option<u64>) -> SessionStore {
        SessionStore {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            default_ttl_ms,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(SessionKey, OwnerKey), Slot>> {
        // Poison-recovering: a panicking tenant must not wedge the substrate for every other tenant.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write an opaque value for `(session, owner)`, replacing any existing slot. `pinned` exempts it
    /// from LRU/TTL (use for durable/active tenants). Uses the default TTL unless `ttl_ms` overrides;
    /// `pinned` slots ignore TTL. Evicts the LRU unpinned slot if this pushes past capacity.
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
            ttl_ms.or(self.default_ttl_ms).map(|d| now_ms.saturating_add(d))
        };
        let mut map = self.lock();
        map.insert(
            (session, owner),
            Slot { value, pinned, last_touch_ms: now_ms, expires_at_ms },
        );
        Self::sweep_and_bound(&mut map, self.capacity, now_ms);
    }

    /// Read the opaque value for `(session, owner)`, downcast to `T`. Touches LRU. Returns `None` if
    /// absent, expired (the expired slot is dropped), or the stored type is not `T`.
    pub fn get<T: Any + Send + Sync>(
        &self,
        session: SessionKey,
        owner: OwnerKey,
        now_ms: u64,
    ) -> Option<Arc<T>> {
        let mut map = self.lock();
        let key = (session, owner);
        match map.get_mut(&key) {
            Some(slot) if slot.is_expired(now_ms) => {
                map.remove(&key);
                None
            }
            Some(slot) => {
                slot.last_touch_ms = now_ms;
                // Cheap Arc<dyn Any> → Arc<T> without cloning the inner value on failure.
                slot.value.clone().downcast::<T>().ok()
            }
            None => None,
        }
    }

    /// Remove a slot regardless of pin state (the only way a pinned slot leaves).
    pub fn remove(&self, session: SessionKey, owner: OwnerKey) -> bool {
        self.lock().remove(&(session, owner)).is_some()
    }

    /// Set/clear the pin on an existing slot. Pinning also clears its TTL; unpinning applies `ttl_ms`
    /// (or the default) from `now_ms`. No-op if the slot is absent; returns whether it existed.
    pub fn set_pinned(
        &self,
        session: SessionKey,
        owner: OwnerKey,
        pinned: bool,
        now_ms: u64,
        ttl_ms: Option<u64>,
    ) -> bool {
        let mut map = self.lock();
        match map.get_mut(&(session, owner)) {
            Some(slot) => {
                slot.pinned = pinned;
                slot.expires_at_ms = if pinned {
                    None
                } else {
                    ttl_ms.or(self.default_ttl_ms).map(|d| now_ms.saturating_add(d))
                };
                true
            }
            None => false,
        }
    }

    /// Current live slot count (after no sweep — for tests/metrics).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the substrate holds no slots.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Drop every expired unpinned slot, then, while still over `capacity`, evict the least-recently-
    /// used UNPINNED slot. Pinned slots are never evicted here — so the store may exceed `capacity`
    /// if pinned slots alone exceed it, which is correct: pinned = a tenant still owns it.
    fn sweep_and_bound(
        map: &mut HashMap<(SessionKey, OwnerKey), Slot>,
        capacity: usize,
        now_ms: u64,
    ) {
        map.retain(|_, slot| !slot.is_expired(now_ms));
        while map.len() > capacity {
            let victim = map
                .iter()
                .filter(|(_, s)| !s.pinned)
                .min_by_key(|(_, s)| s.last_touch_ms)
                .map(|(k, _)| *k);
            match victim {
                Some(k) => {
                    map.remove(&k);
                }
                // Only pinned slots remain; they are exempt, so stop.
                None => break,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/session_tests.rs"]
mod session_tests;
