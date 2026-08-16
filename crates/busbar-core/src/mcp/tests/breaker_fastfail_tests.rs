// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KILL-THE-UPSTREAM, MCP client leg — the audit's degenerate fast-fail cell, proven at the same
//! front door every other battery in this directory drives (`mcp::method::dispatch`), on BOTH of
//! this plane's transports.
//!
//! The claims are the audit's own kill-the-upstream rows ("mcp-http, no pool"), asserted on OUTPUTS a caller or the dead peer can see, never on busbar's intent:
//!
//! 1. TRIP: a hard-down answer (401) opens the ONE core breaker cell for the server.
//! 2. FAST-FAIL: the SECOND call is refused in well under a second — not after the 30s upstream
//!    timeout — and the dead peer's own hit counter proves it was never touched again.
//! 3. THE RENDERING (owner-agreed): HTTP `503` +
//!    `Retry-After` + a JSON-RPC error in the implementation-defined band with structured `data`
//!    — and NEVER an `isError` tool result, because the call never happened and `isError` would
//!    tell the model the tool ran.
//! 4. The refusal COSTS NOTHING upstream: no token-exchange round trip is spent on a call busbar
//!    already knows it will not make (asserted on the token endpoint's own hit counter).
//!
//! These were RED before the wiring: the pre-change tree relayed every failure as `Err(String)`,
//! answered `200` + `isError` on the second call, and the peer's counter read 2.

use super::upstream_support::{
    call, call_response, call_response_caps, exchanging_server, gov_with_scopes, mcp_cfg,
    Behaviour, Peer,
};
use crate::test_support::TestApp;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

fn app_for(peer: &Peer) -> Arc<crate::state::App> {
    TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(peer, SUBJECT))
        .build()
}

fn params() -> serde_json::Value {
    serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } })
}

/// The whole §3.6 "mcp-http, no pool" row in one flow: hard-down trips the core cell, the second
/// call fast-fails with the decided rendering, and the dead upstream is never touched again.
#[tokio::test]
async fn a_hard_down_http_server_trips_and_the_second_call_fast_fails_without_touching_it() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::DeniesWithStatus(401), ISSUED).await;
    let app = app_for(&peer);
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    // CALL 1 reaches the dying peer and comes back a tool-execution failure — the rendering the
    // synchronous path has always used for a call that WENT OUT and failed.
    let (s1, b1) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(s1, 200, "the first failure is an upstream failure: {b1}");
    assert_eq!(peer.mcp_hits(), 1);

    // THE TRIP, on the ONE core cell, under the plane-qualified key. 401 is Auth → HardDown: the
    // cell opens on the FIRST definitive failure, per the core classifier.
    assert!(
        matches!(
            app.plane_breakers
                .state(&crate::store::PlaneBreakers::tool_key("fs")),
            crate::store::BreakerState::Open { .. }
        ),
        "a 401 from the upstream must open the server's breaker cell"
    );
    let token_hits_after_first = peer.token_hits();

    // CALL 2: the audit's timing assertion. Refused before any socket, in milliseconds — the
    // pre-change tree paid the full upstream leg here — and rendered per the decided shape.
    let t0 = Instant::now();
    let (s2, headers, b2) = call_response(&app, &g, "test-principal", "tools/call", params()).await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "a tripped server must refuse in <1s, not after the upstream timeout; took {elapsed:?}"
    );
    assert_eq!(
        s2, 503,
        "a tripped upstream is 503 SERVICE UNAVAILABLE: {b2}"
    );
    let retry_after: u64 = headers
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("the refusal carries Retry-After, populated from the cell's own deadline");
    assert!(
        retry_after >= 1,
        "Retry-After is a real wait, got {retry_after}"
    );

    // A JSON-RPC ERROR in the implementation-defined band, with the decided structured data —
    // and NO result member: an `isError` result here would tell the model the tool ran.
    assert!(
        b2.get("result").is_none(),
        "a breaker refusal must NEVER be an isError tool result: {b2}"
    );
    let error = b2.get("error").expect("a JSON-RPC error object");
    assert_eq!(error["code"], serde_json::json!(-32030), "{b2}");
    assert_eq!(error["data"]["reason"], "upstream_unavailable", "{b2}");
    assert_eq!(
        error["data"]["server"], "fs",
        "the refusal names the server: {b2}"
    );
    assert!(
        error["data"]["retry_after_ms"].as_u64().unwrap_or(0) >= 1000,
        "{b2}"
    );

    // THE DEAD PEER WAS NEVER TOUCHED AGAIN — asserted on the upstream's own counters, and the
    // refusal spent no token-exchange round trip either.
    assert_eq!(
        peer.mcp_hits(),
        1,
        "the second call must not reach the dead upstream"
    );
    assert_eq!(
        peer.token_hits(),
        token_hits_after_first,
        "a breaker refusal must not cost a token-exchange round trip"
    );
}

/// The task path meets the SAME cell at the same pre-network position: a `tools/call` on a
/// `task_support: required` tool against a tripped server is refused with the same JSON-RPC error
/// and NO task id is minted for work busbar already knows it will not dispatch.
#[tokio::test]
async fn a_tripped_server_refuses_before_a_task_id_is_minted() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::DeniesWithStatus(401), ISSUED).await;
    let mut server = exchanging_server(&peer, SUBJECT);
    for allow in server.tools_allow.values_mut() {
        allow.task_support = crate::mcp::config::TaskSupport::Required;
    }
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", server)
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    // A caller that DECLARED the tasks extension, so `task_support: required` mints a task.
    let caps = serde_json::json!({
        "sampling": {}, "elicitation": {}, "roots": { "listChanged": true },
        "extensions": { crate::mcp::tasks::TASKS_EXTENSION_ID: {} },
    });

    // Trip the cell through the task path itself: the runner's leg meets the 401 and records it.
    let (s1, _, b1) =
        call_response_caps(&app, &g, "test-principal", "tools/call", params(), &caps).await;
    assert_eq!(s1, 200, "the first call is answered with a task: {b1}");
    // The detached runner performs the leg; wait for the recorded hard-down to land.
    for _ in 0..50 {
        if peer.mcp_hits() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..50 {
        if matches!(
            app.plane_breakers
                .state(&crate::store::PlaneBreakers::tool_key("fs")),
            crate::store::BreakerState::Open { .. }
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The create-task gate consults the same cell: the refusal is the decided JSON-RPC error, not
    // a `CreateTaskResult` for work that will never be dispatched.
    let (s2, _, b2) =
        call_response_caps(&app, &g, "test-principal", "tools/call", params(), &caps).await;
    assert_eq!(s2, 503, "{b2}");
    assert!(
        b2.get("result").is_none(),
        "no task id for refused work: {b2}"
    );
    assert_eq!(b2["error"]["code"], serde_json::json!(-32030), "{b2}");
}

/// KILL-THE-UPSTREAM, stdio transport: a child that dies on arrival records into the SAME core
/// cell through the same one send site (`Transport::mcp_wire` is the only transport branch), and
/// the second call fast-fails with the same rendering. The stdio crash-loop supervisor keeps doing
/// process supervision; the core cell's refusal arrives FIRST, at admission, before any spawn.
#[cfg(unix)]
#[tokio::test]
async fn a_dead_stdio_child_trips_the_same_core_cell_and_the_second_call_fast_fails() {
    use crate::mcp::config::{
        McpPinMechanism, McpServerDefCfg, ServerPinCfg, ServerRequestGrants, ToolAllowCfg,
        Transport,
    };
    crate::metrics::init();

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
    // A child that exits without ever speaking MCP: the wire leg fails, which is the transient
    // this plane's Stage-1 normalizer records.
    let server = McpServerDefCfg {
        url: String::new(),
        transport: Some(Transport::Stdio),
        command: Some("/bin/sh".to_string()),
        args: vec!["-c".to_string(), "exit 1".to_string()],
        env: Default::default(),
        cwd: None,
        refresh_ttl: None,
        timeout: Some("5s".to_string()),
        pin: ServerPinCfg {
            mechanism: McpPinMechanism::CertSpki,
            key: Some("sha256/CHILD=".to_string()),
        },
        tools_allow,
        prompts_allow: Default::default(),
        resources_allow: Default::default(),
        resource_templates_allow: Default::default(),
        aud: None,
        grants: ServerRequestGrants::default(),
        roots: Vec::new(),
        allow_private: false,
        token_exchange: None,
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        upstream_credentials: None,
        hooks: Vec::new(),
    };
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("sh", server)
        .build();
    let g = gov_with_scopes(&[("mcp_server", "sh"), ("mcp_tool", "sh_read")]);
    let args = serde_json::json!({ "name": "sh_read", "arguments": { "path": "/etc/hosts" } });

    // CALL 1: the child dies, the leg fails, the failure lands in the core cell (a transient — the
    // escalating cooldown suppresses the cell immediately).
    let (s1, b1) = call(&app, &g, "tools/call", args.clone()).await;
    assert_eq!(s1, 200, "the first failure is an upstream failure: {b1}");

    // CALL 2: refused at admission, in milliseconds, with the same 503 + JSON-RPC error the HTTP
    // transport gets — one breaker, one rendering, two transports.
    let t0 = Instant::now();
    let (s2, headers, b2) = call_response(&app, &g, "test-principal", "tools/call", args).await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "a suppressed stdio server must refuse in <1s; took {elapsed:?}"
    );
    assert_eq!(s2, 503, "{b2}");
    assert!(headers.get(axum::http::header::RETRY_AFTER).is_some());
    assert!(b2.get("result").is_none(), "never an isError result: {b2}");
    assert_eq!(b2["error"]["code"], serde_json::json!(-32030), "{b2}");
    assert_eq!(b2["error"]["data"]["server"], "sh", "{b2}");
}
