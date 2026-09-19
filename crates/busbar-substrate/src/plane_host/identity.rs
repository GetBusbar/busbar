// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side mTLS CLIENT-IDENTITY registry — the mutual-handshake counterpart of the host-side credential registry.
//!
//! A plane presenting a client certificate on a governed hop never holds the private key. It holds an
//! OPAQUE `client_identity_ref` (a bare `u64`), and the host owns the parsed key end to end: the host
//! registers each boot-time client identity HERE ([`register`]) and hands back a ref; when the plane
//! opens an egress carrying that ref, the host RESOLVES it ([`resolve`]) and offers the identity to the
//! TLS stack at the host egress chokepoint. The key crosses the seam in NEITHER direction.
//!
//! Registered ONCE, at boot (a config generation), not per hop — a private key re-read on every tick is
//! a key crossing the resolver seam on every tick. The map is process-wide because the ref the plane
//! holds is minted from a process atomic (the same discipline the egress and credential registries
//! use); the identity is a parsed, immutable engine [`ClientIdentity`] that several hops may present
//! over a process lifetime.
//!
//! ## Generation-scoped, bounded retention (S28)
//!
//! [`register`] tags every entry with the caller's `generation` (the config generation the boot/reload
//! that minted it belongs to). A HOT RELOAD registers a fresh generation's identities WITHOUT
//! resolving the previous ones away first — the swap has to stay make-before-break so a hop mid-flight
//! on the old generation still resolves. Once [`MAX_RETAINED_GENERATIONS`] distinct generations are
//! live, [`register`] evicts every entry from the OLDEST one: dropping a [`ClientIdentity`] runs its
//! `Drop` impl, which best-effort zeroizes the private key it holds (guarded by `Arc::get_mut`, so a
//! resolve still in flight on the evicted generation is left untouched rather than raced). Without
//! this bound, a long-lived process accumulates one full identity set — private key included — per
//! config reload for its entire lifetime; a stale ref past the retained window resolves to `None`,
//! the same fail-closed posture an unknown ref already gets.

// PARTLY UNMOUNTED. `resolve` is live at the egress chokepoint today; `register` is the boot-time
// entry the plane calls when its egress call sites are flipped onto the seam (CLUSTER-3 Stage B), and
// is reached only by tests until then. The same posture `a2a::transport` records for its own
// not-yet-mounted pieces.
#![cfg_attr(not(test), allow(dead_code))]

use crate::egress::engine::ClientIdentity;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// How many distinct config generations' identities the registry retains at once. `2` covers the
/// ordinary make-before-break reload (the new generation's identities land before the old
/// generation's last in-flight hop resolves); a THIRD generation arriving evicts the oldest one
/// outright, zeroizing its key material rather than let a process accumulate one identity set per
/// reload for its whole lifetime.
const MAX_RETAINED_GENERATIONS: usize = 2;

/// One registered client identity, tagged with the config generation it was registered under —
/// what [`register`] prunes by once [`MAX_RETAINED_GENERATIONS`] is exceeded.
struct Entry {
    identity: ClientIdentity,
    generation: u64,
}

/// The client-identity map plus the distinct generations currently retained (ascending, oldest
/// first) — one lock, so the two cannot drift.
struct Registry {
    /// Live entries, keyed by the opaque `client_identity_ref` the plane holds.
    map: HashMap<u64, Entry>,
    /// Distinct generations with at least one live entry, oldest first.
    generations: Vec<u64>,
}

/// The process-wide client-identity registry, keyed by the opaque `client_identity_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        map: HashMap::new(),
        generations: Vec::new(),
    })
});

/// The next client-identity ref. `0` is the reserved "none" ref (a hop presenting no identity), so refs
/// start at `1`.
static NEXT_REF: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register a parsed client `identity` under config `generation`, returning the opaque
/// `client_identity_ref` the plane carries into `egress_open`. The ONLY thing about the identity that
/// crosses the seam is this `u64`; the parsed key stays host-side in the registry.
///
/// Bounds the registry to [`MAX_RETAINED_GENERATIONS`] distinct generations (S28): once a NEW
/// generation number is seen and that would exceed the cap, every entry from the single oldest
/// retained generation is evicted and dropped, which runs `ClientIdentity`'s `Drop` and best-effort
/// zeroizes its private key. A ref from an evicted generation then resolves to `None`, the same
/// fail-closed outcome an unknown ref already gets.
#[must_use]
pub fn register(generation: u64, identity: ClientIdentity) -> u64 {
    let client_identity_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    let mut reg = registry();
    reg.map.insert(
        client_identity_ref,
        Entry {
            identity,
            generation,
        },
    );
    if !reg.generations.contains(&generation) {
        reg.generations.push(generation);
        reg.generations.sort_unstable();
    }
    while reg.generations.len() > MAX_RETAINED_GENERATIONS {
        // Oldest first (sorted above), so this is always the single least-recent generation.
        let oldest = reg.generations.remove(0);
        // Evicted `Entry` values drop here — `ClientIdentity::drop` best-effort zeroizes the key.
        reg.map.retain(|_, entry| entry.generation != oldest);
    }
    client_identity_ref
}

/// Resolve `client_identity_ref` to its parsed client identity, or `None` when the ref is `0` (present
/// no identity), unknown, or belongs to a generation already evicted past the retained window. `None`
/// is the HONEST mTLS outcome for an unresolvable ref: the hop is made presenting no certificate, and
/// an mTLS peer closes the handshake itself rather than the host forging one — exactly the posture the
/// a2a transport takes when a registration names no identity.
#[must_use]
pub fn resolve(client_identity_ref: u64) -> Option<ClientIdentity> {
    if client_identity_ref == 0 {
        return None;
    }
    registry()
        .map
        .get(&client_identity_ref)
        .map(|entry| entry.identity.clone())
}

/// TEST ONLY: drop every entry and rewind the ref counter, so a test body starts from clean global
/// state. The registry and `NEXT_REF` are process-global, so parallel test bodies otherwise share
/// them — the identity tests hold [`tests::TEST_GUARD`] across their body and call this at entry, the
/// same discipline `plane_host::creds` uses for its own process-global map. NOT compiled into
/// production — it never mutates a live registry.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    let mut reg = registry();
    reg.map.clear();
    reg.generations.clear();
    NEXT_REF.store(1, Ordering::Relaxed);
}

/// TEST ONLY: how many distinct generations the registry currently retains — what the bounded-
/// retention tests assert against, since [`resolve`] alone can't distinguish "evicted" from
/// "never registered".
#[cfg(test)]
pub(crate) fn generation_count_for_test() -> usize {
    registry().generations.len()
}

#[cfg(test)]
#[path = "tests/identity_tests.rs"]
mod tests;
