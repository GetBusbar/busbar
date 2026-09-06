// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE PER-ROUND RE-PLAN ACTUALLY RE-READS.
//!
//! `mcp::upstream`'s header used to promise that "a grant narrowed part-way through must bite on
//! the very next round". It does not, and the gap is not in the re-plan: every round genuinely
//! re-runs `plan_credential` and re-runs the egress gate. The gap is in what that gate is handed.
//! `Authorised::caller` is an `Arc<VirtualKey>` taken once at admission and carried unchanged, so
//! each round re-asks the same question of the same frozen answer — and `REQUIRE_LIVE_KEY` is
//! `false` on this plane, so the key's liveness is not consulted at any round including the first.
//!
//! These are CHARACTERISATION cases. They pin what busbar does today so the corrected header is
//! checked rather than believed, and so the day somebody makes the caller's key bite per round they
//! find a test that says, in words, what they are changing. Nothing here is a guarantee anybody
//! should build on: read them as "this is the exposure and this is its bound", never as "this is
//! how it should be".

use crate::mcp::client::egress::plan_credential;
use crate::mcp::client::identity::{ServerId, ToolKey};

/// A caller holding exactly the two scopes one `tools/call` needs.
fn caller_with(scopes: Option<Vec<busbar_api::ScopeRef>>) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: "k-dispatching".to_string(),
        name: "k-dispatching".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: scopes,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
        ..Default::default()
    }
}

fn scope(kind: &str, value: &str) -> busbar_api::ScopeRef {
    busbar_api::ScopeRef {
        kind: kind.to_string(),
        value: value.to_string(),
    }
}

fn granted() -> busbar_api::VirtualKey {
    caller_with(Some(vec![
        scope("mcp_server", "fs"),
        scope("mcp_tool", "fs_read"),
    ]))
}

fn tool_key() -> ToolKey {
    ToolKey::new(ServerId::new("fs").expect("a legal server id"), "read").expect("a legal tool key")
}

/// THE RE-PLAN IS REAL, AND IT READS A FROZEN CALLER.
///
/// The first half is the property the header is right about: the gate runs on every round, so a
/// caller who never held the grant is refused on every round rather than on the first one only.
///
/// The second half is the property the header was wrong about. The round-two plan is handed the
/// SNAPSHOT the request was admitted with, so narrowing the caller's scopes in the registry
/// mid-dispatch changes nothing this leg sees: the frozen key still carries the scopes it had at
/// admission and the plan still succeeds. The exposure is bounded by the dispatch's own deadline
/// and round cap — it lasts one `tools/call`, never a session — and closing it means re-resolving
/// the principal from the live registry per round, which is a design change and not a doc fix.
#[test]
fn characterisation_of_the_per_round_re_plan() {
    let credential = crate::mcp::client::egress::UpstreamCredential::None;
    let called = tool_key();
    let server = ServerId::new("fs").expect("a legal server id");

    // THE GATE RUNS PER ROUND: an ungranted caller is refused, and refused again.
    let ungranted = caller_with(Some(Vec::new()));
    for round in 0..3 {
        assert!(
            plan_credential(&server, &credential, &ungranted, None, &called).is_err(),
            "the egress gate must run on EVERY round, not only the first (round {round})"
        );
    }

    // THE CALLER IS A SNAPSHOT. `admitted` is the `Arc<VirtualKey>` the request was authorised with
    // and the value every round's plan is handed; `narrowed` is what the registry now holds. The
    // dispatch keeps planning against `admitted`, which is the whole characterisation.
    let admitted = std::sync::Arc::new(granted());
    plan_credential(&server, &credential, &admitted, None, &called)
        .expect("round one: the caller holds both grants");

    let narrowed = caller_with(Some(vec![scope("mcp_server", "fs")]));
    assert!(
        plan_credential(&server, &credential, &narrowed, None, &called).is_err(),
        "the narrowed key is genuinely narrower — if it were not, the case below would prove \
         nothing about what the leg reads"
    );
    plan_credential(&server, &credential, &admitted, None, &called).expect(
        "CHARACTERISATION, NOT A GUARANTEE: the per-round plan is handed the caller snapshot taken \
         at admission, so a grant narrowed mid-dispatch does not bite until the next `tools/call`. \
         If this line now FAILS, the caller's key has been made to bite per round — which is the \
         right outcome and a design change: update `mcp::upstream`'s header, which currently says \
         it does not.",
    );

    // AND LIVENESS IS NOT CONSULTED AT ALL, on any round including the first: `REQUIRE_LIVE_KEY` is
    // `false` for this plane's egress subject. A key deleted mid-dispatch is not refused HERE — the
    // inbound authentication chain is what rejects a dead key on this path, and it ran once.
    let mut dead = granted();
    dead.enabled = false;
    dead.deleted_at = Some(1);
    plan_credential(&server, &credential, &dead, None, &called).expect(
        "CHARACTERISATION, NOT A GUARANTEE: `REQUIRE_LIVE_KEY` is false on this plane, so the \
         egress gate does not consult the caller's liveness. If this line now FAILS the const has \
         been turned on — a deliberate cross-plane decision recorded on the const itself, and the \
         headers on both planes must be brought with it.",
    );
}
