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
use crate::mcp::client::stdio::{RestartPolicy, StdioChild};
use crate::mcp::client::support::key_wildcard;
use crate::mcp::client::{
    dispatch::DispatchRefusal, Endpoint, McpClientEngine, McpServerRegistration,
};
use crate::trust::PinnedArtifact as _;
use busbar_api::Redacted;

#[test]
fn an_http_registration_carries_the_url_the_transport_will_post_to() {
    let reg = McpServerRegistration::new(
        crate::mcp::client::support::sid("fs"),
        Endpoint::Http {
            url: "https://fs.example/mcp".into(),
        },
    );
    let Endpoint::Http { url } = &reg.endpoint else {
        panic!("expected an http endpoint");
    };
    assert_eq!(url, "https://fs.example/mcp");
    // And the credential defaults to the fail-closed arm.
    assert!(matches!(reg.credential, UpstreamCredential::None));
}

#[test]
fn the_engine_owns_the_connection_pool() {
    let engine = McpClientEngine::new();
    // Engine-owned, per §2.1: the pool is a field of the engine rather than a global, so a second
    // deployment in one process cannot share pinned clients with the first.
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
    // and the plane decides what identity equality means (§12.1).
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

/// Crash DETECTION: `exited` is the non-blocking observation that drives the `crashed` transition.
#[tokio::test]
async fn an_exited_child_is_observed_without_blocking() {
    let mut child = StdioChild::spawn(
        "/bin/sh",
        &["-c".to_string(), "exit 3".to_string()],
        RestartPolicy::default(),
    )
    .await
    .expect("spawn");
    // Give the child a moment to actually exit; `try_wait` is non-blocking, so a bounded poll is the
    // honest shape rather than one unsynchronised call.
    let mut seen = false;
    for _ in 0..200 {
        if child.exited() {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(seen, "an exited child must be observable through `exited`");
    child.supervisor.crashed(1_000);
    assert_eq!(
        child.supervisor.state(),
        crate::mcp::client::stdio::ChildState::Dead
    );
}
