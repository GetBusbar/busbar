// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-node, in-process idempotency-replay cache — moved verbatim from
//! `busbar-core::admin::mod` (`IDEMPOTENCY_TTL_SECS`, `IdemState`, `IdemReservation`, and the
//! create/rotate call sites' cache logic). Same TTL (600 s), same key shapes
//! (`(actor, header)` for a mint, `(actor, "rotate:{id}:{k}")` for a rotate — PB-21), same
//! semantics: no body hash, so a retry with the same key but a DIFFERENT body still replays the
//! first response (parity clause — 1.5.5 never hashed the body either).
//!
//! Generic over the cached value `V` rather than pinned to `serde_json::Value`, because this crate
//! has no serializer dependency (see the crate-level `// contract:` note in `lib.rs`): the
//! integrator's codec supplies whatever already-encoded response type it wants replayed.

use std::collections::HashMap;
use std::sync::Mutex;

/// Replay window (seconds) — 600 s, exactly `IDEMPOTENCY_TTL_SECS` in 1.5.5/1.6.0-legacy admin.
pub const IDEMPOTENCY_TTL_SECS: u64 = 600;

/// One cache slot: `(inserted_at, value)`. `value: None` is the in-flight reservation sentinel
/// (1.5.5 used `serde_json::Value::Null` for the same purpose; `None` says the same thing without
/// requiring a JSON value type).
type Slot<V> = (u64, Option<V>);

/// The cache itself. `(String, String)` is `(actor, header)` for a mint or
/// `(actor, "rotate:{id}:{k}")` for a rotate — the caller builds the key, this type only stores it.
pub struct IdempotencyCache<V> {
    slots: Mutex<HashMap<(String, String), Slot<V>>>,
}

/// The result of probing the cache before starting a mutating verb.
pub enum Probe<'a, V: Clone> {
    /// No `Idempotency-Key` header was presented; proceed and never reserve or replay for this
    /// call.
    NoKey,
    /// First time this key has been seen (or its prior reservation expired): a [`Reservation`] was
    /// inserted under the same lock hold, and the caller now owns it and must either
    /// [`Reservation::commit`] or [`Reservation::clear`]/let it drop.
    Reserved(Reservation<'a, V>),
    /// A prior call with this key already completed: replay its committed value verbatim, minting
    /// nothing new.
    Replay(V),
    /// A prior call with this key is still in flight (its reservation has not been committed or
    /// cleared yet): refuse this call rather than double-run the mutation.
    InFlight,
}

impl<V: Clone> IdempotencyCache<V> {
    /// A fresh, empty cache.
    pub fn new() -> Self {
        IdempotencyCache {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Probe (and, on a first sighting, reserve) `key` at time `now` (unix seconds). Sweeps every
    /// entry whose age exceeds [`IDEMPOTENCY_TTL_SECS`] first — bounded exactly as 1.5.5's
    /// `cache.retain(...)` call at each mint/rotate site was.
    pub fn probe(&self, key: (String, String), now: u64) -> Probe<'_, V> {
        let mut guard = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (t, _)| now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        match guard.get(&key) {
            Some((_, Some(v))) => Probe::Replay(v.clone()),
            Some((_, None)) => Probe::InFlight,
            None => {
                guard.insert(key.clone(), (now, None));
                drop(guard);
                Probe::Reserved(Reservation {
                    cache: self,
                    key,
                    live: true,
                })
            }
        }
    }
}

impl<V: Clone> Default for IdempotencyCache<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// An in-flight reservation. Exactly `IdemReservation` in 1.5.5: clears the sentinel on `Drop` (a
/// parse/validation/store failure before anything irreversible happened), unless the caller
/// explicitly [`commit`](Reservation::commit)s a real value or [`clear`](Reservation::clear)s it
/// itself (a store-confirmed failure it already knows is safe to free for retry) or
/// [`leak`](Reservation::leak)s it (the mutation was handed to an uncancellable execution path —
/// 1.5.5's `spawn_blocking` — so a caller disconnect after this point must NOT clear the sentinel,
/// or a retry could double-mint against a mutation that already landed).
pub struct Reservation<'a, V: Clone> {
    cache: &'a IdempotencyCache<V>,
    key: (String, String),
    live: bool,
}

impl<'a, V: Clone> Reservation<'a, V> {
    /// Commit the real value, replacing the sentinel. A later replay of this key returns exactly
    /// this value.
    pub fn commit(mut self, value: V, now: u64) {
        let mut guard = self.cache.slots.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(self.key.clone(), (now, Some(value)));
        self.live = false;
    }

    /// Explicitly clear the reservation (a refusal this call already knows is safe to retry).
    /// Idempotent: clears only if the slot is still this reservation's own sentinel, never a value
    /// a concurrent commit already placed there.
    pub fn clear(mut self) {
        self.clear_inner();
        self.live = false;
    }

    /// Mark the reservation as handed to an uncancellable execution path: a subsequent `Drop`
    /// (caller cancellation) must not clear it. Mirrors 1.5.5's `IdemState::InFlight` transition.
    pub fn leak(mut self) {
        self.live = false;
    }

    fn clear_inner(&self) {
        let mut guard = self.cache.slots.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(guard.get(&self.key), Some((_, None))) {
            guard.remove(&self.key);
        }
    }
}

impl<'a, V: Clone> Drop for Reservation<'a, V> {
    fn drop(&mut self) {
        if self.live {
            self.clear_inner();
        }
    }
}

#[cfg(test)]
#[path = "tests/idempotency_tests.rs"]
mod tests;
