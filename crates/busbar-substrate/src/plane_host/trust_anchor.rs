// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side TRUST-ANCHOR registry — the extra-root counterpart of [`identity`](super::identity).
//!
//! A plane opening a governed hop against an upstream whose certificate chains to a private CA (a
//! test's throw-away root, a vendor's internal CA) never holds the certificate bytes. It holds an
//! OPAQUE `trust_anchor_ref` (a bare `u64`), and the host owns the parsed roots end to end: the host
//! registers each boot-time trust anchor HERE ([`register`]) and hands back a ref; when the plane
//! opens an egress carrying that ref, the host RESOLVES it ([`resolve`]) and adds those roots to the
//! pinned client at the host egress chokepoint. The certificate bytes cross the seam in NEITHER direction.
//!
//! PER-REGISTRATION, not host-wide: trust anchors are a property of ONE registration exactly as a
//! client identity is a property of one agent. The a2a `transport_pin` / `transport_tests` fixtures
//! present a `trusting_root` WITHOUT any client identity, so the extra roots cannot ride the
//! `client_identity_ref`; they get their own ref. A host-wide set would trust one registration's CA on
//! every hop — precisely the blast radius a per-registration ref avoids.
//!
//! Registered ONCE, at boot (a config generation), not per hop — a re-parse of the same PEM on every
//! tick is wasted work and a needless allocation. The map is process-wide because the ref the plane
//! holds is minted from a process atomic (the same discipline the egress, credential and identity
//! registries use); the anchors are parsed, immutable [`reqwest::Certificate`]s several hops may add
//! over a process lifetime.

// PARTLY UNMOUNTED. `resolve` is live at the egress chokepoint today; `register` is the boot-time
// entry the plane calls when its egress call sites are flipped onto the seam (the a2a `trusting_root`
// path), and is reached only by tests until then. The same posture `identity` records.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// The process-wide trust-anchor registry, keyed by the opaque `trust_anchor_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<HashMap<u64, Vec<reqwest::Certificate>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next trust-anchor ref. `0` is the reserved "none" ref (a hop adding no extra roots), so refs
/// start at `1`.
static NEXT_REF: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Vec<reqwest::Certificate>>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register a set of parsed extra-root `roots`, returning the opaque `trust_anchor_ref` the plane
/// carries on its [`EgressDesc`](busbar_plugin::hot::EgressDesc). The ONLY thing about the anchors that
/// crosses the seam is this `u64`; the parsed certificates stay host-side in the registry. Registering
/// an EMPTY set still mints a live (nonzero) ref — it simply resolves to no extra roots.
#[must_use]
pub fn register(roots: Vec<reqwest::Certificate>) -> u64 {
    let trust_anchor_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    registry().insert(trust_anchor_ref, roots);
    trust_anchor_ref
}

/// Resolve `trust_anchor_ref` to its parsed extra roots, or an EMPTY vec when the ref is `0` (add no
/// extra roots — the ordinary public-CA hop) or unknown. An empty result is the honest outcome for an
/// unknown ref: the hop is made trusting only the platform roots, exactly as a hop that named no
/// anchor at all — fail-closed (a stale ref widens trust NOWHERE).
#[must_use]
pub fn resolve(trust_anchor_ref: u64) -> Vec<reqwest::Certificate> {
    if trust_anchor_ref == 0 {
        return Vec::new();
    }
    registry()
        .get(&trust_anchor_ref)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/trust_anchor_tests.rs"]
mod tests;
