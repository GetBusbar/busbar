// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT-OWNED EGRESS-TRUST SEAM (HOST-CAPS S3, DECISIONS #26).
//!
//! The outbound trust decision — which extra trust anchors a governed hop adds, which mTLS client
//! identity it presents, and the SubjectPublicKeyInfo pin of the peer certificate a completed
//! handshake produced — lives today as three host-side primitives: [`identity`](super::identity),
//! [`trust_anchor`](super::trust_anchor) and [`spki`](super::spki). Each is already host-owned (a
//! process registry, or a pure DER walk), but nothing NAMES the three together as ONE host capability
//! a plane reaches through a trait object.
//!
//! This seam is that name. [`EgressTrustHost`] groups the three as one capability the composition root
//! installs once at boot ([`install_egress_trust_host`]); a plane reads it back through
//! [`egress_trust_host`] and calls typed methods instead of the free functions directly, so the trust
//! machinery is swappable behind a stable boundary without any call site changing. It mirrors the
//! egress fetch seam's `install_hostless_egress` / `hostless` (see `crate::egress::seam`) and the
//! `plane_host` capability-slice pattern ([`EngineHost`](super::EngineHost) and its supertraits).
//!
//! ## Additive and DORMANT
//!
//! The production capability [`PassThroughEgressTrust`] delegates to the exact free functions the
//! shipped path calls today — the pins, refs and identities it produces are BYTE-FOR-BYTE the ones
//! `identity::register`/`resolve`, `trust_anchor::register`/`resolve` and `spki::pin` produce now. And
//! NOTHING on the shipped path consults the seam yet: the egress chokepoint still calls the free
//! functions directly, so the outbound path is unchanged until a call site opts in (W2). Reading
//! [`egress_trust_host`] in a build that installed no capability returns `None`.

// The registries' `register` entry points are boot-only and reached by tests until the egress call
// sites flip onto the seam (W2) — the same not-yet-mounted posture `identity`/`trust_anchor` record.
#![cfg_attr(not(test), allow(dead_code))]

use crate::egress::engine::ClientIdentity;
use crate::plane_host::spki::SpkiError;
use rustls_pki_types::CertificateDer;

/// THE OUTBOUND EGRESS-TRUST HOST CAPABILITY, as a neutral trait a plane reaches through instead of
/// calling [`identity`](super::identity) / [`trust_anchor`](super::trust_anchor) / [`spki`](super::spki)
/// directly. Groups the three outbound trust primitives — client-identity registration/resolution,
/// extra-trust-anchor registration/resolution, and the peer-certificate SPKI pin — as one capability.
/// `Send + Sync` so the installed capability is a process-wide `&'static dyn`.
pub trait EgressTrustHost: Send + Sync {
    /// Register a parsed mTLS client `identity` at boot, returning the opaque `client_identity_ref` a
    /// hop carries. Pass-through to [`identity::register`](super::identity::register).
    fn register_client_identity(&self, identity: ClientIdentity) -> u64;

    /// Resolve a `client_identity_ref` to its parsed identity (`None` for the reserved `0` ref or an
    /// unknown one). Pass-through to [`identity::resolve`](super::identity::resolve).
    fn resolve_client_identity(&self, client_identity_ref: u64) -> Option<ClientIdentity>;

    /// Register a set of parsed extra-root `roots` at boot, returning the opaque `trust_anchor_ref` a
    /// hop carries. Pass-through to [`trust_anchor::register`](super::trust_anchor::register).
    fn register_trust_anchor(&self, roots: Vec<CertificateDer<'static>>) -> u64;

    /// Resolve a `trust_anchor_ref` to its extra roots (an EMPTY vec for the reserved `0` ref or an
    /// unknown one — fail-closed). Pass-through to
    /// [`trust_anchor::resolve`](super::trust_anchor::resolve).
    fn resolve_trust_anchor(&self, trust_anchor_ref: u64) -> Vec<CertificateDer<'static>>;

    /// The `sha256/<base64>` SPKI pin of a peer certificate a completed handshake produced. Pure DER
    /// walk; pass-through to [`spki::pin`](super::spki::pin).
    fn peer_spki_pin(&self, cert_der: &[u8]) -> Result<String, SpkiError>;
}

/// The production egress-trust capability: a BYTE-FOR-BYTE pass-through to the host-side primitives.
/// The composition root installs this today, so a call site that opts onto the seam (W2) gets exactly
/// the refs, identities and pins the free functions produce now.
pub struct PassThroughEgressTrust;

impl EgressTrustHost for PassThroughEgressTrust {
    fn register_client_identity(&self, identity: ClientIdentity) -> u64 {
        super::identity::register(identity)
    }

    fn resolve_client_identity(&self, client_identity_ref: u64) -> Option<ClientIdentity> {
        super::identity::resolve(client_identity_ref)
    }

    fn register_trust_anchor(&self, roots: Vec<CertificateDer<'static>>) -> u64 {
        super::trust_anchor::register(roots)
    }

    fn resolve_trust_anchor(&self, trust_anchor_ref: u64) -> Vec<CertificateDer<'static>> {
        super::trust_anchor::resolve(trust_anchor_ref)
    }

    fn peer_spki_pin(&self, cert_der: &[u8]) -> Result<String, SpkiError> {
        super::spki::pin(cert_der)
    }
}

/// THE PROCESS-WIDE egress-trust capability, installed once by the composition root
/// ([`install_egress_trust_host`]). A plane reads it back through [`egress_trust_host`] and gets `None`
/// in a build that installed none — the dormant default, under which the egress chokepoint calls the
/// free primitives directly and the outbound path is unchanged.
static EGRESS_TRUST: std::sync::OnceLock<&'static dyn EgressTrustHost> = std::sync::OnceLock::new();

/// Install the process egress-trust capability — the composition root's one write, at boot, before any
/// hop opens. Idempotent by `OnceLock`: a second install is a no-op (the first wins).
pub fn install_egress_trust_host(host: &'static dyn EgressTrustHost) {
    let _ = EGRESS_TRUST.set(host);
}

/// The installed egress-trust capability, or `None` when none was installed (the dormant default).
#[must_use]
pub fn egress_trust_host() -> Option<&'static dyn EgressTrustHost> {
    EGRESS_TRUST.get().copied()
}

// Test body externalised to `tests/egress_trust_tests.rs` (the sibling `identity`/`trust_anchor`
// convention) so this implementation file's length measures one thing — structure-lint:inline-tests.
#[cfg(test)]
#[path = "tests/egress_trust_tests.rs"]
mod egress_trust_tests;
