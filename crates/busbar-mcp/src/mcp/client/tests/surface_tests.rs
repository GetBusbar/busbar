// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The surface this module exposes for its (not yet built) production caller, exercised so that
//! "unused" is a compiler finding rather than a habit.
//!
//! The client direction has no production caller yet — the `tools:` config section and the admin
//! verbs are later increments. That makes dead-code warnings the only thing standing between this
//! module and a field nobody ever reads, so every accessor a caller will need is driven here. A
//! field that cannot be exercised even by a test is a field with no purpose, and finding that out
//! now is cheaper than finding it out from the wiring increment.

use crate::mcp::client::catalogue::TransportPin;
use crate::mcp::client::egress::{CallerContext, UpstreamCredential};
use crate::mcp::client::ssrf::SsrfRefusal;
use crate::mcp::client::support::key_wildcard;
use crate::mcp::client::{
    dispatch::DispatchRefusal, Endpoint, McpClientEngine, McpServerRegistration,
};
use busbar_api::Redacted;
use busbar_core::trust::PinnedArtifact as _;

#[test]
fn an_http_registration_carries_the_url_the_transport_will_post_to() {
    let reg = McpServerRegistration::new(
        crate::mcp::client::support::sid("fs"),
        Endpoint::Http {
            url: "https://fs.example/mcp".into(),
        },
    );
    // EXHAUSTIVE, and that is the point. This was an irrefutable `let` while `Endpoint` had one arm,
    // and it stopped compiling the day `Stdio` landed — which is the prompt the enum exists to give.
    // It stays a `match` with every arm named rather than becoming an `if let` with an `else`: an
    // `else` would silently keep passing for the THIRD transport.
    match &reg.endpoint {
        Endpoint::Http { url } => assert_eq!(url, "https://fs.example/mcp"),
        Endpoint::Stdio { command } => panic!("registered an HTTP endpoint, got {command:?}"),
    }
    // And the credential defaults to the fail-closed arm.
    assert!(matches!(reg.credential, UpstreamCredential::None));
}

#[test]
fn the_engine_owns_the_connection_pool() {
    let engine = McpClientEngine::new();
    // Connection pooling to upstreams is engine-owned: the pool is a field of the engine rather
    // than a global, so a second deployment in one process cannot share pinned clients with the
    // first.
    assert_eq!(engine.pool.len(), 0);
}

#[test]
fn both_pin_mechanisms_are_operator_visible_and_never_interpreted_by_the_machine() {
    let spki = TransportPin::cert_spki("sha256/AAAA");
    let mtls = TransportPin::mtls("client-cert-id");
    assert_eq!(spki.mechanism(), "cert_spki");
    assert_eq!(mtls.mechanism(), "mtls");
    assert_eq!(spki.digest(), "sha256/AAAA");
    // Two mechanisms with the same VALUE are still different pins, because equality is structural
    // and the plane — not the trust machinery — decides what identity equality means.
    assert_ne!(TransportPin::cert_spki("x"), TransportPin::mtls("x"));
}

#[test]
fn the_ssrf_refusal_reaches_the_caller_as_a_dispatch_refusal() {
    let refusal = DispatchRefusal::Ssrf(SsrfRefusal::CloudMetadata {
        host: "evil.example".into(),
        addr: "169.254.169.254".parse().unwrap(),
    });
    // The SSRF reason survives the wrapping: a dispatch refusal that flattened it to "refused" would
    // leave an operator with no way to tell an SSRF block from a grant block.
    assert!(refusal.to_string().contains("cloud-metadata"));
    assert!(refusal.to_string().contains("169.254.169.254"));
}

#[test]
fn the_caller_context_carries_the_busbar_key_so_its_absence_downstream_means_something() {
    let c = CallerContext {
        key: key_wildcard("agent"),
        busbar_key: Redacted::new("bb-sk-secret".into()),
        upstream_credential: None,
    };
    // Reachable from the request-building layer — which is exactly why the adversarial scan in
    // `no_key_passthrough_tests.rs` proves something. A field the builder could not reach would make
    // that scan a tautology.
    assert_eq!(c.busbar_key.expose_secret(), "bb-sk-secret");
    assert_eq!(c.key.id, "agent");
}
