// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side mTLS CLIENT-IDENTITY registry — the mutual-handshake counterpart of [`super::creds`].
//!
//! A plane presenting a client certificate on a governed hop never holds the private key. It holds an
//! OPAQUE `client_identity_ref` (a bare `u64`), and the host owns the parsed key end to end: the host
//! registers each boot-time client identity HERE ([`register`]) and hands back a ref; when the plane
//! opens an egress carrying that ref, the host RESOLVES it ([`resolve`]) and offers the identity to the
//! TLS stack (see [`super::egress`]). The key crosses the seam in NEITHER direction.
//!
//! Registered ONCE, at boot (a config generation), not per hop — a private key re-read on every tick is
//! a key crossing the resolver seam on every tick. The map is process-wide because the ref the plane
//! holds is minted from a process atomic (the same discipline the egress and credential registries
//! use); the identity is a parsed, immutable [`reqwest::Identity`] that several hops may present over a
//! process lifetime.

// PARTLY UNMOUNTED. `resolve` is live at the egress chokepoint today; `register` is the boot-time
// entry the plane calls when its egress call sites are flipped onto the seam (CLUSTER-3 Stage B), and
// is reached only by tests until then. The same posture `a2a::transport` records for its own
// not-yet-mounted pieces.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// The process-wide client-identity registry, keyed by the opaque `client_identity_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<HashMap<u64, reqwest::Identity>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next client-identity ref. `0` is the reserved "none" ref (a hop presenting no identity), so refs
/// start at `1`.
static NEXT_REF: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, reqwest::Identity>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register a parsed client `identity`, returning the opaque `client_identity_ref` the plane carries
/// into `egress_open`. The ONLY thing about the identity that crosses the seam is this `u64`; the
/// parsed key stays host-side in the registry.
#[must_use]
pub(crate) fn register(identity: reqwest::Identity) -> u64 {
    let client_identity_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    registry().insert(client_identity_ref, identity);
    client_identity_ref
}

/// Resolve `client_identity_ref` to its parsed client identity, or `None` when the ref is `0` (present
/// no identity) or unknown. `None` is the HONEST mTLS outcome for an unknown ref: the hop is made
/// presenting no certificate, and an mTLS peer closes the handshake itself rather than the host
/// forging one — exactly the posture the a2a transport takes when a registration names no identity.
#[must_use]
pub(crate) fn resolve(client_identity_ref: u64) -> Option<reqwest::Identity> {
    if client_identity_ref == 0 {
        return None;
    }
    registry().get(&client_identity_ref).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed client identity (cert + key concatenated as one PEM buffer, the single form
    /// `reqwest::Identity::from_pem` takes), built the way the a2a boot resolver builds one.
    fn an_identity() -> reqwest::Identity {
        use rcgen::{CertificateParams, KeyPair};
        let kp = KeyPair::generate().expect("a key pair");
        let params = CertificateParams::new(vec!["client.test".to_string()]).expect("params");
        let cert = params.self_signed(&kp).expect("self-signed");
        let mut pem = cert.pem().into_bytes();
        if !pem.ends_with(b"\n") {
            pem.push(b'\n');
        }
        pem.extend_from_slice(kp.serialize_pem().as_bytes());
        reqwest::Identity::from_pem(&pem).expect("a usable client identity")
    }

    #[test]
    fn register_then_resolve_returns_the_identity_and_unknown_is_none() {
        let r = register(an_identity());
        assert_ne!(r, 0, "a live ref is nonzero");
        assert!(
            resolve(r).is_some(),
            "the registered ref resolves to its identity"
        );
        assert!(
            resolve(0).is_none(),
            "the reserved 0 ref presents no identity"
        );
        assert!(
            resolve(u64::MAX).is_none(),
            "an unknown ref resolves to nothing (fail to no-cert)"
        );
    }

    #[test]
    fn distinct_registrations_get_distinct_refs() {
        let a = register(an_identity());
        let b = register(an_identity());
        assert_ne!(a, b, "each registration is a fresh opaque ref");
    }
}
