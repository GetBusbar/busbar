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
//! REGISTRATION IS GENERATION-SCOPED, exactly as it is for a client identity: the ref belongs to a
//! [`TrustAnchorGeneration`] its installer OWNS, and dropping that generation retires every ref it
//! minted (`resolve` then adds no extra roots — fail-closed). See
//! [`identity`](super::identity) for why the lifetime is the owner's and not a global "newest wins".
//!
//! Registered ONCE, at boot (a config generation), not per hop — a re-parse of the same PEM on every
//! tick is wasted work and a needless allocation. The map is process-wide because the ref the plane
//! holds is minted from a process atomic (the same discipline the egress, credential and identity
//! registries use); the anchors are parsed, immutable DER certificates (`CertificateDer`) several
//! hops may add over a process lifetime — the form the engine's `Trust::WebpkiPlus` joins to the
//! webpki store, parsed from PEM at registration so a garbage root still fails at parse time.

// PARTLY UNMOUNTED. `resolve` is live at the egress chokepoint today; `register` is the boot-time
// entry the plane calls when its egress call sites are flipped onto the seam (the a2a `trusting_root`
// path), and is reached only by tests until then. The same posture `identity` records.
#![cfg_attr(not(test), allow(dead_code))]

use rustls_pki_types::CertificateDer;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// The process-wide trust-anchor registry, keyed by the opaque `trust_anchor_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<HashMap<u64, Vec<CertificateDer<'static>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next GENERATION number — the high half of every ref, so a ref a retired generation minted can
/// never be re-minted by a later one.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// The next per-generation slot. `0` is the reserved "none" ref (a hop adding no extra roots), and a
/// ref carries a nonzero generation in its high half, so no live ref is ever `0`.
static NEXT_SLOT: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Vec<CertificateDer<'static>>>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// The generation half of a ref — what [`TrustAnchorGeneration::drop`] retires by.
const fn generation_of(trust_anchor_ref: u64) -> u64 {
    trust_anchor_ref >> 32
}

/// ONE GENERATION OF REGISTERED ANCHORS — the lifetime of the roots registered through it, and the
/// same lifecycle [`IdentityGeneration`](super::identity::IdentityGeneration) gives a generation of
/// client identities.
///
/// A registry with no removal widens nothing by itself (these are public certificates, not keys), but
/// it does keep every root a re-registration superseded resolvable through any ref that was handed
/// out — so an anchor set the operator narrowed still has a live ref naming the wider one. Retiring
/// on drop makes a superseded anchor set unreachable at the moment its owner lets go, and keeps the
/// registry's population the number of anchor sets actually in use.
pub struct TrustAnchorGeneration {
    generation: u64,
}

impl TrustAnchorGeneration {
    /// Open a fresh generation. Retires nothing by itself — a previous generation goes when its own
    /// handle is dropped.
    #[must_use]
    pub fn install() -> Self {
        TrustAnchorGeneration {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Register a set of parsed extra-root `roots` IN THIS GENERATION, returning the opaque
    /// `trust_anchor_ref` the plane carries on its [`EgressDesc`](busbar_plugin::hot::EgressDesc). The
    /// ONLY thing about the anchors that crosses the seam is this `u64`; the parsed certificates stay
    /// host-side in the registry, and only as long as this generation does. Registering an EMPTY set
    /// still mints a live (nonzero) ref — it simply resolves to no extra roots.
    #[must_use]
    pub fn register(&self, roots: Vec<CertificateDer<'static>>) -> u64 {
        let slot = NEXT_SLOT.fetch_add(1, Ordering::Relaxed) & 0xffff_ffff;
        let trust_anchor_ref = (self.generation << 32) | slot;
        registry().insert(trust_anchor_ref, roots);
        trust_anchor_ref
    }

    /// How many anchor SETS this generation is holding — generation-scoped for the same reason
    /// [`IdentityGeneration::len`](super::identity::IdentityGeneration::len) is.
    #[must_use]
    pub fn len(&self) -> usize {
        registry()
            .keys()
            .filter(|r| generation_of(**r) == self.generation)
            .count()
    }

    /// Whether this generation registered no anchor set at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for TrustAnchorGeneration {
    /// RETIRE the generation: drop every anchor set it minted. A hop still carrying one of those refs
    /// resolves to NO extra roots — fail-closed, trusting only the platform roots, exactly as a hop
    /// that named no anchor at all.
    fn drop(&mut self) {
        registry().retain(|r, _| generation_of(*r) != self.generation);
    }
}

/// Resolve `trust_anchor_ref` to its parsed extra roots, or an EMPTY vec when the ref is `0` (add no
/// extra roots — the ordinary public-CA hop) or unknown. An empty result is the honest outcome for an
/// unknown ref: the hop is made trusting only the platform roots, exactly as a hop that named no
/// anchor at all — fail-closed (a stale ref widens trust NOWHERE).
#[must_use]
pub fn resolve(trust_anchor_ref: u64) -> Vec<CertificateDer<'static>> {
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
