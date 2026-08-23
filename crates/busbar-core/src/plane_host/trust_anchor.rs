// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side TRUST-ANCHOR registry — the extra-root counterpart of [`super::identity`].
//!
//! A plane opening a governed hop against an upstream whose certificate chains to a private CA (a
//! test's throw-away root, a vendor's internal CA) never holds the certificate bytes. It holds an
//! OPAQUE `trust_anchor_ref` (a bare `u64`), and the host owns the parsed roots end to end: the host
//! registers each boot-time trust anchor HERE ([`register`]) and hands back a ref; when the plane
//! opens an egress carrying that ref, the host RESOLVES it ([`resolve`]) and adds those roots to the
//! pinned client (see [`super::egress`]). The certificate bytes cross the seam in NEITHER direction.
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
// path), and is reached only by tests until then. The same posture `super::identity` records.
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
pub(crate) fn register(roots: Vec<reqwest::Certificate>) -> u64 {
    let trust_anchor_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    registry().insert(trust_anchor_ref, roots);
    trust_anchor_ref
}

/// Resolve `trust_anchor_ref` to its parsed extra roots, or an EMPTY vec when the ref is `0` (add no
/// extra roots — the ordinary public-CA hop) or unknown. An empty result is the honest outcome for an
/// unknown ref: the hop is made trusting only the platform roots, exactly as a hop that named no
/// anchor at all — fail-closed (a stale ref widens trust NOWHERE).
#[must_use]
pub(crate) fn resolve(trust_anchor_ref: u64) -> Vec<reqwest::Certificate> {
    if trust_anchor_ref == 0 {
        return Vec::new();
    }
    registry()
        .get(&trust_anchor_ref)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed root certificate, parsed as a `reqwest::Certificate` the way the a2a boot resolver
    /// parses a `trusting_root` PEM.
    fn a_root() -> reqwest::Certificate {
        use rcgen::{CertificateParams, KeyPair};
        let kp = KeyPair::generate().expect("a key pair");
        let params = CertificateParams::new(vec!["root.test".to_string()]).expect("params");
        let cert = params.self_signed(&kp).expect("self-signed");
        reqwest::Certificate::from_pem(cert.pem().as_bytes()).expect("a usable root certificate")
    }

    #[test]
    fn register_then_resolve_returns_the_roots_and_unknown_is_empty() {
        let r = register(vec![a_root()]);
        assert_ne!(r, 0, "a live ref is nonzero");
        assert_eq!(
            resolve(r).len(),
            1,
            "the registered ref resolves to its one root"
        );
        assert!(
            resolve(0).is_empty(),
            "the reserved 0 ref adds no extra roots"
        );
        assert!(
            resolve(u64::MAX).is_empty(),
            "an unknown ref resolves to no extra roots (fail-closed)"
        );
    }

    #[test]
    fn distinct_registrations_get_distinct_refs() {
        let a = register(vec![a_root()]);
        let b = register(vec![a_root()]);
        assert_ne!(a, b, "each registration is a fresh opaque ref");
    }

    #[test]
    fn an_empty_set_still_mints_a_live_ref() {
        let r = register(Vec::new());
        assert_ne!(r, 0, "even an empty anchor set gets a nonzero ref");
        assert!(resolve(r).is_empty(), "which resolves to no extra roots");
    }
}
