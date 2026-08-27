// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KILL-THE-UPSTREAM-MID-POOL, MCP client leg — the failover seam mounted on this plane
//! (`tool_pools:` → `failover::walk` → `upstream::call`), proven at the same front door as every
//! other battery in this directory, on OUTPUTS the caller and the two real fake peers can see.
//!
//! The claims, each an observable behaviour of this plane:
//!
//! 1. REROUTE ON TRIP: member A hard-down → the next call gets an answer FROM MEMBER B, with A's
//!    trip recorded and A untouched on the second call (its own hit counter is the witness).
//! 2. REROUTE BEFORE FIRST BYTE, WITHIN ONE CALL: a member that cannot even be connected to
//!    (nothing left busbar) is walked past inside the same request; the caller sees only B's
//!    answer.
//! 3. THE PIN RULE: two members whose approved digests differ are refused, and the second is
//!    never dispatched to.
//! 4. THE SAFETY RULE: an after-dispatch failure of an operation NOT in `repeatable:` is exactly
//!    one delivery — asserted on the upstream's own counter — and an operator-listed repeatable
//!    operation IS retried on the twin.
//! 5. DISPOSITION: a true client-fault answer (404) never penalizes the member — the next call
//!    still dispatches to it.
//!
//! Each was watched RED with the pool declaration neutralized (route built degenerate): the calls
//! then behave exactly as the un-pooled breaker unit — no twin answer, no reroute, one member.

use super::upstream_support::{call, gov_with_scopes, mcp_cfg, Behaviour, Peer};
use crate::testkit::TestAppMcpExt;
use busbar_core::test_support::TestApp;
use std::sync::Arc;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// A registration reaching `url` with NO token exchange (so a dead listener fails on the MCP wire
/// itself, not on the AS leg) and the two standard tools approved at the SAME digests as every
/// other member built from this helper — which is what makes two of them interchangeable.
fn plain_server(url: &str) -> crate::mcp::config::McpServerDefCfg {
    use crate::mcp::config::{
        McpPinMechanism, McpServerDefCfg, ServerPinCfg, ServerRequestGrants, ToolAllowCfg,
    };
    let mut tools_allow = indexmap::IndexMap::new();
    tools_allow.insert(
        "read".to_string(),
        ToolAllowCfg {
            schema_hash: Some("sha256:read".to_string()),
            description: Some("reads a file".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
            })),
            ask_caller: Vec::new(),
            ..ToolAllowCfg::default()
        },
    );
    McpServerDefCfg {
        command: None,
        sampling: None,
        args: Vec::new(),
        env: Default::default(),
        cwd: None,
        verify_ttl: None,
        timeout: None,
        url: url.to_string(),
        pin: ServerPinCfg {
            mechanism: McpPinMechanism::CertSpki,
            key: Some("sha256/PEER=".to_string()),
        },
        tools_allow,
        prompts_allow: indexmap::IndexMap::new(),
        resources_allow: indexmap::IndexMap::new(),
        resource_templates_allow: Default::default(),
        transport: None,
        aud: None,
        grants: ServerRequestGrants::default(),
        roots: Vec::new(),
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        allow_private: true,
        token_exchange: None,
        upstream_credentials: None,
        hooks: Vec::new(),
    }
}

/// The same registration with a DIFFERENT approved digest for `read` — the not-a-twin.
fn drifted_server(url: &str) -> crate::mcp::config::McpServerDefCfg {
    let mut cfg = plain_server(url);
    cfg.tools_allow
        .get_mut("read")
        .expect("the tool exists")
        .schema_hash = Some("sha256:SOMETHING-ELSE".to_string());
    cfg
}

/// Twin deployment: servers `fs-a`/`fs-b` in pool `fs`, `repeatable` as given.
fn pooled_app(
    a: crate::mcp::config::McpServerDefCfg,
    b: crate::mcp::config::McpServerDefCfg,
    repeatable: &[&str],
) -> Arc<busbar_core::state::App> {
    TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs-a", a)
        .mcp_server("fs-b", b)
        .tool_pool("fs", &["fs-a", "fs-b"], repeatable)
        .build()
}

fn gov() -> busbar_api::PlaneRequestCtx {
    gov_with_scopes(&[
        ("mcp_server", "fs-a"),
        ("mcp_tool", "fs-a_read"),
        ("mcp_server", "fs-b"),
        ("mcp_tool", "fs-b_read"),
    ])
}

fn params() -> serde_json::Value {
    serde_json::json!({ "name": "fs-a_read", "arguments": { "path": "/etc/hosts" } })
}

fn result_text(body: &serde_json::Value) -> String {
    body.pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// THE EQUALITY-CELL INSTRUMENT (`failover-reroute × mcp-client`): member A hard-down → the caller
/// gets an answer from member B, with A's trip recorded and A untouched on the second call.
#[tokio::test]
async fn a_tripped_pool_primary_reroutes_the_next_tools_call_to_its_twin_and_stays_untouched() {
    busbar_core::metrics::init();
    let peer_a = Peer::start(Behaviour::DeniesWithStatus(401), "unused").await;
    let peer_b = Peer::start(Behaviour::Result, "unused").await;
    let app = pooled_app(
        plain_server(&peer_a.mcp_url()),
        plain_server(&peer_b.mcp_url()),
        &[],
    );
    let g = gov();

    // CALL 1 reaches A (the primary), which answers a definitive 401: recorded HardDown against
    // A's OWN cell (`("tool:fs", 0)`), and — because the request had gone out and `read` is not
    // declared repeatable — NOT retried on B. Exactly one delivery, on the peers' own counters.
    let (s1, b1) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(s1, 200, "the first failure is an upstream failure: {b1}");
    assert_eq!(peer_a.mcp_hits(), 1);
    assert_eq!(
        peer_b.mcp_hits(),
        0,
        "an after-dispatch failure of a non-repeatable operation must not touch the twin"
    );
    assert!(
        matches!(
            app.plane_breakers.state_at("tool:fs", 0),
            busbar_core::store::BreakerState::Open { .. }
        ),
        "A's trip is recorded on the POOL cell at A's lane"
    );
    assert!(
        matches!(
            app.plane_breakers.state_at("tool:fs", 1),
            busbar_core::store::BreakerState::Closed
        ),
        "B's cell is untouched by A's failure"
    );

    // CALL 2: the walk refuses A's Open cell before any socket and admits B — the caller gets the
    // TWIN'S ANSWER on the same tool name it always called, and the dead member's counter proves
    // it was never touched again.
    let (s2, b2) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(s2, 200, "{b2}");
    assert_eq!(
        result_text(&b2),
        "UPSTREAM RESULT",
        "the caller gets member B's real answer: {b2}"
    );
    assert_eq!(peer_a.mcp_hits(), 1, "A untouched on the second call");
    assert_eq!(peer_b.mcp_hits(), 1);
}

/// REROUTE BEFORE FIRST BYTE, WITHIN ONE CALL: member A's listener is gone (connect refused —
/// nothing left busbar, by the transport's own classification), so the SAME request walks on to B
/// and the caller sees only B's answer.
#[tokio::test]
async fn an_unreachable_primary_is_rerouted_before_first_byte_within_one_call() {
    busbar_core::metrics::init();
    // A's endpoint is a loopback port bound and then SYNCHRONOUSLY released: a std `TcpListener`
    // closes its socket the instant it drops, so a connect to `dead_url` refuses deterministically
    // on every platform. Binding a `Peer` and dropping it instead only ABORTS its async accept task
    // — cancellation the runtime completes later — so on Windows the still-draining listener accepts
    // the connection from its backlog and then resets it AFTER the request is sent (os error 10054):
    // an after-dispatch failure, which is NOT the connect-refused-before-first-byte condition this
    // test exists to exercise (Unix closes fast enough to dodge the window, hence the flake).
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_url = format!("http://{}/mcp", dead.local_addr().unwrap());
    drop(dead);
    let peer_b = Peer::start(Behaviour::Result, "unused").await;
    let app = pooled_app(
        plain_server(&dead_url),
        plain_server(&peer_b.mcp_url()),
        &[],
    );
    let g = gov();

    let (status, body) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        result_text(&body),
        "UPSTREAM RESULT",
        "one call, one answer, from the twin: {body}"
    );
    assert_eq!(peer_b.mcp_hits(), 1);
}

/// THE PIN RULE: a member whose approved digest differs is NOT interchangeable — refused by name,
/// never dispatched to. (A is tripped first so the walk actually reaches B's pin check.)
#[tokio::test]
async fn a_member_with_a_different_approved_digest_is_refused_never_dispatched() {
    busbar_core::metrics::init();
    let peer_a = Peer::start(Behaviour::DeniesWithStatus(401), "unused").await;
    let peer_b = Peer::start(Behaviour::Result, "unused").await;
    let app = pooled_app(
        plain_server(&peer_a.mcp_url()),
        drifted_server(&peer_b.mcp_url()),
        &[],
    );
    let g = gov();

    let (_, _) = call(&app, &g, "tools/call", params()).await; // trips A
    let (s2, b2) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(s2, 503, "{b2}");
    let error = b2.get("error").expect("a JSON-RPC error object");
    assert_eq!(
        error["data"]["reason"],
        busbar_substrate::audit::vocab::REASON_NOT_INTERCHANGEABLE,
        "{b2}"
    );
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("sha256:read") && message.contains("sha256:SOMETHING-ELSE"),
        "the refusal names both digests: {message}"
    );
    assert_eq!(
        peer_b.mcp_hits(),
        0,
        "nothing is dispatched to a member busbar cannot show is the same deployment"
    );
}

/// THE SAFETY RULE'S PERMITTED HALF: `read` listed in `repeatable:` → an after-dispatch transient
/// on A IS retried on B, and the caller gets B's answer.
#[tokio::test]
async fn an_operator_listed_repeatable_operation_is_retried_on_the_twin_after_dispatch() {
    busbar_core::metrics::init();
    let peer_a = Peer::start(Behaviour::DeniesWithStatus(500), "unused").await;
    let peer_b = Peer::start(Behaviour::Result, "unused").await;
    let app = pooled_app(
        plain_server(&peer_a.mcp_url()),
        plain_server(&peer_b.mcp_url()),
        &["read"],
    );
    let g = gov();

    let (status, body) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        result_text(&body),
        "UPSTREAM RESULT",
        "the operator declared `read` safe to perform twice, so the failed leg is retried on the \
         twin: {body}"
    );
    assert_eq!(peer_a.mcp_hits(), 1);
    assert_eq!(peer_b.mcp_hits(), 1);
}

/// DISPOSITION (`disposition × mcp-client`): a true 4xx is the CALLER's fault — classified
/// `ClientFault` through the one Stage-2 classifier — so it never penalizes the member: no trip,
/// and the next call still dispatches to it. The negative twin of the trip tests above.
#[tokio::test]
async fn a_client_fault_answer_never_penalizes_the_member() {
    busbar_core::metrics::init();
    let peer_a = Peer::start(Behaviour::DeniesWithStatus(404), "unused").await;
    let peer_b = Peer::start(Behaviour::Result, "unused").await;
    let app = pooled_app(
        plain_server(&peer_a.mcp_url()),
        plain_server(&peer_b.mcp_url()),
        &[],
    );
    let g = gov();

    let (_, _) = call(&app, &g, "tools/call", params()).await;
    assert!(
        matches!(
            app.plane_breakers.state_at("tool:fs", 0),
            busbar_core::store::BreakerState::Closed
        ),
        "a 404 is the request's fault, never the member's"
    );
    let (_, _) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(
        peer_a.mcp_hits(),
        2,
        "an unpenalized member keeps receiving its own traffic"
    );
    assert_eq!(peer_b.mcp_hits(), 0);
}
