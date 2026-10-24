// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT-OWNED EGRESS-TRUST SEAM (HOST-CAPS S3, DECISIONS #26).
//!
//! The outbound trust decision — which extra trust anchors a governed hop adds, which mTLS client
//! identity it presents, and the SubjectPublicKeyInfo pin of the peer certificate a completed
//! handshake produced — lives today as three host-side primitives: [`identity`](identity),
//! [`trust_anchor`](trust_anchor) and [`spki`](spki). Each is already host-owned (a
//! process registry, or a pure DER walk), but nothing NAMES the three together as ONE host capability
//! a plane reaches through a trait object.
//!
//! This seam is that name. [`EgressTrustHost`] groups the three as one capability. A shipped build
//! holds none in a process-wide static: an engine client is handed its judge, its names and its TLS
//! on its spec, and a config commit reaches the deployment's guard through the root's rules
//! (`appbuild::RootRules::destinations_applied`). A test binary hands its own capability in
//! (`test_support::install_egress_trust`) and reads it back through
//! [`egress_trust_host`] and calls typed methods instead of the free functions directly, so the trust
//! machinery is swappable behind a stable boundary without any call site changing. It mirrors the
//! engine-host pattern ([`EngineHost`](crate::plane_driver::EngineHost)).
//!
//! ## Additive and DORMANT
//!
//! The production capability [`PassThroughEgressTrust`] delegates to the exact free functions the
//! shipped path calls today — the pins, refs and identities it produces are BYTE-FOR-BYTE the ones
//! `identity::register`/`resolve`, `trust_anchor::register`/`resolve` and `spki::pin` produce now. And
//! NOTHING on the shipped path consults the seam yet: the egress chokepoint still calls the free
//! functions directly, so the outbound path is unchanged until a call site opts in. Reading
//! [`egress_trust_host`] in a build that installed no capability returns `None`.

// The registries' `register` entry points are boot-only and reached by tests until the egress call
// sites flip onto the seam — the same not-yet-mounted posture `identity`/`trust_anchor` record.
#![cfg_attr(not(test), allow(dead_code))]

// The three primitives the seam names. Their home is the kernel's outbound surface, not the plane
// host: the egress engine, the root's connector install and the secure layer read them, and none of
// them is plane hosting (BUSBAR-1.6.0.md Part 4 Axis 3: "the kernel owns the allow-list, pin,
// breaker and meter valves").
pub mod identity;
pub mod spki;
pub mod trust_anchor;

use std::net::IpAddr;
use std::sync::Arc;

use crate::egress::engine::ClientIdentity;
use crate::host_services::DestRefusal;
use crate::secure::SecureLayer;
use busbar_kernel_egress::trust::net::Resolver;
use spki::SpkiError;

/// THE OUTBOUND EGRESS-TRUST HOST CAPABILITY, as a neutral trait a plane reaches through instead of
/// calling [`identity`](identity) / [`trust_anchor`](trust_anchor) / [`spki`](spki)
/// directly. Groups the three outbound trust primitives — client-identity registration/resolution,
/// extra-trust-anchor registration/resolution, and the peer-certificate SPKI pin — as one capability.
/// `Send + Sync` so the installed capability is a process-wide `&'static dyn`.
pub trait EgressTrustHost: Send + Sync {
    /// Register a parsed mTLS client `identity` at boot, returning the opaque `client_identity_ref` a
    /// hop carries. Pass-through to [`identity::register`](identity::register).
    fn register_client_identity(&self, identity: ClientIdentity) -> u64 {
        identity::register(identity)
    }

    /// Resolve a `client_identity_ref` to its parsed identity (`None` for the reserved `0` ref or an
    /// unknown one). Pass-through to [`identity::resolve`](identity::resolve).
    fn resolve_client_identity(&self, client_identity_ref: u64) -> Option<ClientIdentity> {
        identity::resolve(client_identity_ref)
    }

    /// Register a set of parsed extra-root `roots` at boot, returning the opaque `trust_anchor_ref` a
    /// hop carries. Pass-through to [`trust_anchor::register`](trust_anchor::register).
    fn register_trust_anchor(&self, roots: Vec<Vec<u8>>) -> u64 {
        trust_anchor::register(roots)
    }

    /// Resolve a `trust_anchor_ref` to its extra roots (an EMPTY vec for the reserved `0` ref or an
    /// unknown one — fail-closed). Pass-through to
    /// [`trust_anchor::resolve`](trust_anchor::resolve).
    fn resolve_trust_anchor(&self, trust_anchor_ref: u64) -> Vec<Vec<u8>> {
        trust_anchor::resolve(trust_anchor_ref)
    }

    /// The `sha256/<base64>` SPKI pin of a peer certificate a completed handshake produced. Pure DER
    /// walk; pass-through to [`spki::pin`](spki::pin).
    fn peer_leaf_pin(&self, cert_der: &[u8]) -> Result<String, SpkiError> {
        spki::pin(cert_der)
    }

    /// An answer the kernel's own pooled client resolved for `host`, judged whole under `class` by
    /// the deployment's destination guard (OWNER DESTINATION GUARD; the connector decides). INTERIM
    /// for the eight pooled-client builders; struck when D1-D6 move onto `conns` (Phase B).
    ///
    /// # Errors
    ///
    /// The refusal of the first refused address; with no guard behind the capability (the
    /// pass-through) every answer: FAIL CLOSED, never allowed.
    fn judge_answer(&self, host: &str, _: &[IpAddr], _: u32) -> Result<(), DestRefusal> {
        Err(DestRefusal {
            verdict: busbar_contract::abi::host::service::DEST_NO_HOST,
            reason: format!("host `{host}` was not dialled: no destination guard is installed"),
        })
    }
    /// The guard's NAME arm for a host the kernel's own pooled client is about to dial under `class`,
    /// before any resolution: an IP literal is judged as its own answer (a literal never reaches a
    /// resolver, so this is the only judgement it gets), and a cloud-metadata name, an
    /// operator-blocked name and a `localhost` name are decided here.
    ///
    /// # Errors
    ///
    /// The guard's refusal; with no guard behind the capability (the pass-through) every host: FAIL
    /// CLOSED, never allowed.
    fn judge_name(&self, host: &str, _: u32) -> Result<(), DestRefusal> {
        Err(DestRefusal {
            verdict: busbar_contract::abi::host::service::DEST_NO_HOST,
            reason: format!("host `{host}` was not dialled: no destination guard is installed"),
        })
    }

    /// THE TLS AN OUTBOUND CONNECTION IS SECURED WITH: the connector's wrap (`crate::secure`), the
    /// one TLS path (THE DESIGN: TLS stays in the connector; this crate names no TLS library). The
    /// trust anchors, the pin and the client identity above are what it applies. `None` on the
    /// pass-through, which has no TLS behind it: an https dial then fails, naming the missing wrap.
    fn secure_layer(&self) -> Option<Arc<dyn SecureLayer>> {
        None
    }

    /// THE NAME RESOLUTION a kernel dial's resolve-then-pin asks for (row 130 E2): every address
    /// `host` answers with, de-duplicated, unsorted, unfiltered (the guard judges all of them). The
    /// kernel opens no socket, a resolver's included. The pass-through has none behind it, so a
    /// production build refuses every name (FAIL CLOSED); a test build resolves through the test
    /// fixtures' system lookup.
    ///
    /// # Errors
    ///
    /// The resolution failure (not an empty answer: the two are different facts).
    fn resolve_names(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        unresolved(host)
    }
}

/// [`EgressTrustHost::resolve_names`] with no resolver behind it: a test build resolves through the
/// fixtures' system lookup; a production build refuses the name.
fn unresolved(host: &str) -> Result<Vec<IpAddr>, String> {
    #[cfg(any(test, feature = "test-support"))]
    {
        crate::egress::fixtures::system_names(host)
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        Err(format!(
            "name lookup: `{host}` was not resolved: no resolver is installed"
        ))
    }
}

/// THE RESOLVER a kernel resolve-then-pin hands the guard (`resolve_and_pin`): the installed
/// capability's [`EgressTrustHost::resolve_names`], or, with none installed, the same answer the
/// pass-through gives.
#[derive(Clone, Copy, Debug, Default)]
pub struct InstalledResolver;

impl Resolver for InstalledResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        match egress_trust_host() {
            Some(capability) => capability.resolve_names(host),
            None => unresolved(host),
        }
    }
}

/// The pass-through egress-trust capability: a BYTE-FOR-BYTE pass-through to the host-side
/// primitives, so a call site that opts onto the seam gets exactly the refs, identities and pins the
/// free functions produce now.
pub struct PassThroughEgressTrust;

impl EgressTrustHost for PassThroughEgressTrust {}

/// THE CAPABILITY A TEST BINARY HANDED IN ([`crate::test_support::install_egress_trust`]), the one
/// its engine clients fall back to where their spec hands them no judge, names or TLS. Gated to test
/// builds: a shipped build has no process-wide egress-trust capability at all.
#[cfg(any(test, feature = "test-support"))]
pub(crate) static TEST_EGRESS_TRUST: std::sync::OnceLock<Arc<dyn EgressTrustHost>> =
    std::sync::OnceLock::new();

/// The capability a test binary handed in, or `None`: always `None` in a shipped build, whose
/// engine fallbacks then fail closed (no guard admits an answer, no resolver answers a name, no TLS
/// wrap secures a connection).
#[must_use]
pub fn egress_trust_host() -> Option<&'static dyn EgressTrustHost> {
    #[cfg(any(test, feature = "test-support"))]
    {
        TEST_EGRESS_TRUST.get().map(AsRef::as_ref)
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        None
    }
}

// Test body externalised to `tests/egress_trust_tests.rs` (the sibling `identity`/`trust_anchor`
// convention) so this implementation file's length measures one thing — structure-lint:inline-tests.
#[cfg(test)]
#[path = "tests/egress_trust_tests.rs"]
mod egress_trust_tests;
