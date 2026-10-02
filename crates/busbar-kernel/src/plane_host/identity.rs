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
//! ## Bounded retention
//!
//! [`register`]'s signature is the ABI [`super::egress_trust::PassThroughEgressTrust`] calls through —
//! it carries no config-generation tag — so this module cannot tell a fresh hot-reload's registrations
//! apart from an old one's by identity alone. What it CAN do, and what it does, is refuse to grow
//! without bound: the registry retains only the [`MAX_RETAINED_IDENTITIES`] most-recently-registered
//! entries, FIFO. Without this, a long-lived process hot-reloading its config accumulated one full
//! private-key set per reload for its entire lifetime — nothing ever evicted the previous generation's
//! entries. A ref past the retained window resolves to `None`, the same fail-closed outcome an unknown
//! ref already gets (see [`resolve`]).

// PARTLY UNMOUNTED. `resolve` is live at the egress chokepoint today; `register` is the boot-time
// entry the plane calls when its egress call sites are flipped onto the seam (CLUSTER-3 Stage B), and
// is reached only by tests until then. The same posture `a2a::transport` records for its own
// not-yet-mounted pieces.
#![cfg_attr(not(test), allow(dead_code))]

use crate::egress::engine::ClientIdentity;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// Hard cap on how many client identities the registry retains at once. `register` is called once
/// per config generation (a boot or a hot reload), never per hop, so this is comfortably above any
/// realistic single-generation identity count (an operator config registers a handful of mTLS
/// identities at most) while still being a REAL, finite ceiling — the bound this module previously
/// had none of. FIFO by registration order: once exceeded, the OLDEST live entries are evicted
/// first, so a fresh reload's identities always survive an older generation's.
const MAX_RETAINED_IDENTITIES: usize = 256;

/// The client-identity map plus the registration order it is bounded by — one lock, so the two
/// cannot drift.
struct Registry {
    /// Live entries, keyed by the opaque `client_identity_ref` the plane holds.
    map: HashMap<u64, ClientIdentity>,
    /// Refs in registration order, oldest first — what [`register`] evicts from once `map` exceeds
    /// [`MAX_RETAINED_IDENTITIES`].
    order: VecDeque<u64>,
}

/// The process-wide client-identity registry, keyed by the opaque `client_identity_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        map: HashMap::new(),
        order: VecDeque::new(),
    })
});

/// The next client-identity ref. `0` is the reserved "none" ref (a hop presenting no identity), so refs
/// start at `1`.
static NEXT_REF: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register a parsed client `identity`, returning the opaque `client_identity_ref` the plane carries
/// into `egress_open`. The ONLY thing about the identity that crosses the seam is this `u64`; the
/// parsed key stays host-side in the registry.
///
/// Bounds the registry to [`MAX_RETAINED_IDENTITIES`] live entries: once registering `identity` would
/// exceed the cap, the single oldest retained entry is evicted first (FIFO) — its `ClientIdentity`
/// drops here, releasing the private-key material it held. A ref from an evicted entry then resolves
/// to `None`, the same fail-closed outcome an unknown ref already gets.
#[must_use]
pub fn register(identity: ClientIdentity) -> u64 {
    let client_identity_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    let mut reg = registry();
    reg.map.insert(client_identity_ref, identity);
    reg.order.push_back(client_identity_ref);
    while reg.order.len() > MAX_RETAINED_IDENTITIES {
        if let Some(oldest) = reg.order.pop_front() {
            // The evicted `ClientIdentity` drops here.
            reg.map.remove(&oldest);
        }
    }
    client_identity_ref
}

/// Resolve `client_identity_ref` to its parsed client identity, or `None` when the ref is `0` (present
/// no identity), unknown, or belongs to an entry already evicted past the retained window. `None` is
/// the HONEST mTLS outcome for an unresolvable ref: the hop is made presenting no certificate, and an
/// mTLS peer closes the handshake itself rather than the host forging one — exactly the posture the
/// a2a transport takes when a registration names no identity.
#[must_use]
pub fn resolve(client_identity_ref: u64) -> Option<ClientIdentity> {
    if client_identity_ref == 0 {
        return None;
    }
    registry().map.get(&client_identity_ref).cloned()
}

/// TEST ONLY: drop every entry and rewind the ref counter, so a test body starts from clean global
/// state. The registry and `NEXT_REF` are process-global, so parallel test bodies otherwise share
/// them.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    let mut reg = registry();
    reg.map.clear();
    reg.order.clear();
    NEXT_REF.store(1, Ordering::Relaxed);
}

/// TEST ONLY: how many entries the registry currently retains — what the bounded-retention tests
/// assert against, since [`resolve`] alone can't distinguish "evicted" from "never registered".
#[cfg(test)]
pub(crate) fn live_count_for_test() -> usize {
    registry().map.len()
}

#[cfg(test)]
#[path = "tests/identity_tests.rs"]
mod tests;
