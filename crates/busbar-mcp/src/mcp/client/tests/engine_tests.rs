// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine object: registration is fail-closed, and deregistration bumps the generation so an
//! already-resolved call fails its dispatch-time re-validation.

use crate::mcp::client::dispatch::{resolve, revalidate, DispatchRefusal};
use crate::mcp::client::support::{key_wildcard, sid, simple_tool};
use crate::mcp::client::{Endpoint, McpClientEngine, McpServerRegistration};
use busbar_core::trust::TrustState;

fn http_reg(id: &str) -> McpServerRegistration {
    McpServerRegistration::new(
        sid(id),
        Endpoint::Http {
            url: format!("https://{id}.example/mcp"),
        },
    )
}

/// Registration reaches no network and approves nothing — OQ8's answer, so "registered but never
/// contacted" is a real, inspectable state rather than an invisible one.
#[test]
fn registration_is_fail_closed_and_serves_nothing() {
    let engine = McpClientEngine::new();
    let reg = http_reg("fs");
    assert!(reg.pin.is_none(), "no pin until an operator supplies one");
    assert_eq!(reg.max_input_required_rounds, 1);
    assert!(!reg.grants.sampling && !reg.grants.elicitation && !reg.grants.roots);
    assert!(!reg.ssrf.allow_private);

    engine.register(reg);
    let snapshot = engine.catalogue.load();
    let sc = snapshot.server(&sid("fs")).expect("the entry exists");
    assert_eq!(sc.state(), TrustState::Pending);
    assert!(sc.served_tools().is_empty());
    assert!(snapshot.served_tools().is_empty());
}

#[test]
fn registering_the_same_id_twice_does_not_discard_its_catalogue_state() {
    let engine = McpClientEngine::new();
    engine.register(http_reg("fs"));
    engine.catalogue.apply(|servers| {
        *servers.get_mut("fs").unwrap() =
            crate::mcp::client::support::approved_server("fs", vec![simple_tool("read", "r")]);
    });
    // A re-registration (an endpoint edit, say) must not silently un-approve; the trust lifecycle
    // owns that decision through `unpin`, and it is an explicit act.
    engine.register(http_reg("fs"));
    let snapshot = engine.catalogue.load();
    assert_eq!(
        snapshot.server(&sid("fs")).unwrap().state(),
        TrustState::Approved
    );
}

/// DEREGISTRATION IS A REVOCATION, and it bites on an already-resolved call.
#[test]
fn deregistering_refuses_a_call_that_was_already_resolved() {
    let engine = McpClientEngine::new();
    let caller = key_wildcard("k");
    engine.register(http_reg("fs"));
    engine.catalogue.apply(|servers| {
        *servers.get_mut("fs").unwrap() =
            crate::mcp::client::support::approved_server("fs", vec![simple_tool("read", "r")]);
    });
    let snapshot = engine.catalogue.load();
    let resolved = resolve(&snapshot, "fs_read", &caller).expect("resolves while registered");

    engine.deregister(&sid("fs"));

    let err = revalidate(&engine.catalogue, &resolved, &caller)
        .expect_err("a deregistered server must not be dispatched to");
    assert!(
        matches!(err, DispatchRefusal::GenerationMoved { .. }),
        "got {err:?}"
    );
    assert!(engine.registration(&sid("fs")).is_none());
}

#[test]
fn the_registry_and_the_catalogue_stay_in_step() {
    let engine = McpClientEngine::new();
    for id in ["a", "b", "c"] {
        engine.register(http_reg(id));
    }
    let snapshot = engine.catalogue.load();
    let ids: Vec<String> = snapshot.servers().map(|s| s.id.to_string()).collect();
    assert_eq!(ids, vec!["a".to_string(), "b".into(), "c".into()]);
    for id in ["a", "b", "c"] {
        assert!(engine.registration(&sid(id)).is_some());
    }
    engine.deregister(&sid("b"));
    let after: Vec<String> = engine
        .catalogue
        .load()
        .servers()
        .map(|s| s.id.to_string())
        .collect();
    assert_eq!(after, vec!["a".to_string(), "c".into()]);
}
