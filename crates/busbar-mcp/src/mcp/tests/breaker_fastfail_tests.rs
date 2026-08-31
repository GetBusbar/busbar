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
use crate::testkit::TestAppMcpExt;
use busbar_core::test_support::TestApp;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// `TripConfig::default().min_requests` — ADR-0002's floor, and the smallest number of all-error
/// outcomes inside the 30s window that can satisfy the default `error_rate >= 0.5` predicate.
/// Named once so a test that means "enough failures to trip" cannot drift away from the predicate
/// it is naming.
const TRIP_MIN_REQUESTS: usize = 5;

fn app_for(peer: &Peer) -> Arc<busbar_core::state::App> {
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
    busbar_core::metrics::init();
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
                .state(&busbar_substrate::store::tool_key("fs")),
            busbar_core::store::BreakerState::Open { .. }
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
    busbar_core::metrics::init();
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
                .state(&busbar_substrate::store::tool_key("fs")),
            busbar_core::store::BreakerState::Open { .. }
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
    busbar_core::metrics::init();

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
        verify_ttl: None,
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
        sampling: None,
    };
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("sh", server)
        .build();
    let g = gov_with_scopes(&[("mcp_server", "sh"), ("mcp_tool", "sh_read")]);
    let args = serde_json::json!({ "name": "sh_read", "arguments": { "path": "/etc/hosts" } });

    // THE TRIP, DRIVEN THE WAY THE PUBLISHED CONTRACT SAYS IT IS DRIVEN. Every call reaches a child
    // that dies, so every leg records a transient, and the cell opens on the trip predicate
    // ADR-0002 publishes: error-rate >= 0.5 over >= `min_requests` (5) outcomes in the 30s window.
    //
    // This loop used to be ONE call. That worked because a sub-threshold transient benched the cell
    // anyway — the LLM plane's "prefer a sibling" cooldown, arriving on a plane that has no sibling
    // and therefore refuses the caller instead. That was the defect this file's subject leg was
    // failing MCP conformance on; it is gone, and driving a REAL trip is what this test always
    // meant to assert (the claim in its name is "the same core cell, the same rendering, on the
    // stdio transport", not "one blip is enough").
    // BOUNDED BY THE CELL'S STATE, NOT BY A CALL COUNT, and that is forced by the transport: the
    // stdio supervisor's own restart backoff sits IN FRONT of the spawn, and a call it turns away is
    // `TransportError::Supervision`, which `mcp::upstream`'s Stage-1 normalizer deliberately does
    // NOT record against the core cell (the supervisor is doing process supervision; the upstream
    // has not said anything). So a fixed loop of five calls buys fewer than five WIRE failures. This
    // one keeps driving the front door, waiting each backoff out, until the cell has genuinely seen
    // `min_requests` of them.
    let key = busbar_substrate::store::tool_key("sh");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !matches!(
        app.plane_breakers.state(&key),
        busbar_core::store::BreakerState::Open { .. }
    ) {
        assert!(
            Instant::now() < deadline,
            "a child that dies on every spawn must trip the core cell within 20s"
        );
        let (s, b) = call(&app, &g, "tools/call", args.clone()).await;
        assert_eq!(
            s, 200,
            "every pre-trip answer is a tool result, not a refusal: {b}"
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    // THE CALL AFTER THE TRIP: refused at admission, in milliseconds, with the same 503 + JSON-RPC
    // error the HTTP transport gets — one breaker, one rendering, two transports.
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

/// ONE BLIP IS NOT A TRIP, AND THE CALLER AFTER IT IS STILL SERVED.
///
/// THE BUG THIS PINS, said plainly. ADR-0002's `TransientUpstream` rule is one sentence with two
/// halves — "drive trip evaluation ... and re-arm an exponential cooldown; **fail over** to the
/// next candidate" — and this plane ships only the first half: `docs/circuit-breaker.md` says out
/// loud that on the MCP client leg "no second candidate is tried today — a tripped target is
/// refused, never rerouted". So the sub-threshold cooldown, which on an LLM pool means "prefer a
/// sibling for 15s", meant "refuse EVERY caller of this server for 15-120s" here — minted by ONE
/// transient blip, on a cell whose own `should_trip` had just declined to trip, and announced to
/// the caller as `-32030` ... "its circuit breaker is open after repeated failures".
///
/// It is not an abstraction. The in-house MCP conformance battery went red on it for five commits:
/// one stalled upstream in an early hostile scenario refused every later scenario that dispatched
/// through the same registration, `retry_after_ms: 29000` — a 30s outage bought with one timeout.
///
/// ASSERTED ON THE PEER'S OWN HIT COUNTER, not on busbar's intent: the second call must have
/// REACHED the upstream. A 503 body proves nothing here (this peer answers 503 to everything);
/// `mcp_hits() == 2` proves the call was dispatched rather than fast-failed.
#[tokio::test]
async fn one_transient_failure_does_not_refuse_the_next_caller() {
    busbar_core::metrics::init();
    // 503 is `ServerError` → `TransientUpstream`: the disposition whose sub-threshold arm this is
    // about. (401 is `Auth` → `HardDown`, which trips on the FIRST failure by design — see the
    // first test in this file, which is unchanged.)
    let peer = Peer::start(Behaviour::DeniesWithStatus(503), ISSUED).await;
    let app = app_for(&peer);
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (s1, b1) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(
        s1, 200,
        "an upstream failure is a tool result, not a refusal: {b1}"
    );
    assert_eq!(peer.mcp_hits(), 1);

    // THE CELL IS STILL CLOSED. One outcome cannot satisfy `min_requests: 5`, so `should_trip` is
    // false — and a cell that did not trip must not behave as though it had.
    assert!(
        matches!(
            app.plane_breakers
                .state(&busbar_substrate::store::tool_key("fs")),
            busbar_core::store::BreakerState::Closed
        ),
        "one sub-threshold transient must leave the cell Closed and admitting, not benched"
    );

    let (s2, b2) = call(&app, &g, "tools/call", params()).await;
    assert_eq!(
        peer.mcp_hits(),
        2,
        "the caller after one blip must still be dispatched: it was refused before the socket"
    );
    assert_eq!(s2, 200, "{b2}");
    assert!(
        b2.get("error").is_none(),
        "an untripped server must not answer -32030 upstream_unavailable: {b2}"
    );
}

/// THE OTHER HALF OF THE SAME PROPERTY, so the fix above cannot be read as "the breaker was turned
/// off": a server that genuinely breaches the published predicate still trips and still fast-fails
/// with the decided rendering, and the dead peer stops being touched.
#[tokio::test]
async fn a_transient_server_that_breaches_the_error_rate_trips_and_then_fast_fails() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::DeniesWithStatus(503), ISSUED).await;
    let app = app_for(&peer);
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    // `min_requests` all-error outcomes inside one 30s window: count = 5, errors = 5, rate = 1.0.
    for i in 0..TRIP_MIN_REQUESTS {
        let (s, b) = call(&app, &g, "tools/call", params()).await;
        assert_eq!(
            s, 200,
            "failure {i} reaches the upstream and is a tool result: {b}"
        );
    }
    assert_eq!(
        peer.mcp_hits(),
        TRIP_MIN_REQUESTS,
        "every pre-trip call must have been dispatched"
    );
    assert!(
        matches!(
            app.plane_breakers
                .state(&busbar_substrate::store::tool_key("fs")),
            busbar_core::store::BreakerState::Open { .. }
        ),
        "an all-error window at or above min_requests must trip the cell"
    );

    let t0 = Instant::now();
    let (s, _headers, b) = call_response(&app, &g, "test-principal", "tools/call", params()).await;
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "a tripped server refuses in milliseconds, not after the upstream leg"
    );
    assert_eq!(s, 503, "{b}");
    assert!(b.get("result").is_none(), "never an isError result: {b}");
    assert_eq!(b["error"]["code"], serde_json::json!(-32030), "{b}");
    assert_eq!(b["error"]["data"]["reason"], "upstream_unavailable", "{b}");
    assert_eq!(
        peer.mcp_hits(),
        TRIP_MIN_REQUESTS,
        "the tripped peer must not be touched again"
    );
}
