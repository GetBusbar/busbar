// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S SERVED-LEG WITNESSES — `tools/call` driven through whatever runner the host has
//! registered for this plane's capability key, each witness asserting ONE capability or ONE loop
//! step on what came out.
//!
//! ## Why they live here and run elsewhere
//!
//! In a deployment `tools/call` is served by the composition root's kernel-loop rider: the root
//! registers it under [`crate::PLANE_KEY`] at boot, and `run_gauntlet` hands the plane's `drive`
//! to it. That rider lives in the binary crate, which this crate cannot link, so in THIS crate's
//! own test binary the same call runs `run_gauntlet`'s inline verify-then-`drive` fallback. The
//! witnesses below are therefore compiled under `test-support` and exported through
//! [`crate::testkit::SERVED`]: the binary crate's test build links this crate, installs its real
//! rider, runs every witness, and checks that the plane's `drive` actually ran inside the loop the
//! number of times the witness says it should. The composition root names no plane to do it — it
//! reads the table its build script generated from the manifest.
//!
//! ## What a witness returns
//!
//! The number of units it expects the served path to have carried into the plane's `drive`: every
//! `tools/call` that got past the transport's own envelope and authentication checks. A request the
//! ingress refuses before dispatch (a body that is not JSON, a caller with no credential) is not a
//! unit and is not counted — which is exactly what the caller checks, so a refusal that started
//! riding the loop, or a call that stopped riding it, both move the count.
//!
//! Every witness names its own registration (unique across this crate) because the metrics
//! recorder, the audit ring and the per-principal call chains are process-wide and the caller runs
//! the witnesses in parallel.

use super::upstream_support::{
    call_as, call_response, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::mcp::connect::connect_support::{
    approved_hash, server_cfg, wire_tool, Peer as ListingPeer,
};
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// THE HOST WALL CLOCK, in whole seconds, read through the contract's host service
/// (`busbar_contract::codec::wall_clock_now`) — the one clock a plane reads. These witnesses stand in
/// for the host, so the service is armed with the host's own system-clock reading first (first
/// install wins: a process whose real host already armed it keeps the host's clock).
pub(crate) fn host_now() -> u64 {
    busbar_contract::codec::install_wall_clock(system_clock_secs);
    busbar_contract::codec::wall_clock_now().unwrap_or_else(system_clock_secs)
}

/// Whole seconds since the Unix epoch — the reading the host installs into the wall-clock service.
fn system_clock_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One served-leg witness: drive the served path, assert, and return the number of units the
/// served path must have carried into this plane's `drive`.
pub type Witness = fn() -> Pin<Box<dyn Future<Output = u64>>>;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-served-witness";
const ISSUED: &str = "downscoped-token-the-served-witness-was-issued";

/// THE WITNESS TABLE, keyed by the loop step (`qa/teller-steps.json`) or the core capability
/// (`qa/capability-equality.json`) each one proves on the served path.
pub(crate) const WITNESSES: &[(&str, Witness)] = &[
    ("arrival", || Box::pin(a_served_call_arrives_as_one_unit())),
    ("decode", || {
        Box::pin(a_body_that_is_not_an_envelope_never_becomes_a_unit())
    }),
    ("authenticate", || {
        Box::pin(a_caller_without_a_credential_never_becomes_a_unit())
    }),
    ("verify", || {
        Box::pin(a_server_the_grant_does_not_reach_is_never_dialled())
    }),
    ("approve", || {
        Box::pin(a_grant_on_the_server_alone_does_not_reach_its_tool())
    }),
    ("admit", || {
        Box::pin(a_caller_over_its_budget_is_refused_before_the_dial())
    }),
    ("route", || {
        Box::pin(a_failed_upstream_is_answered_inside_the_unit())
    }),
    ("meter", || {
        Box::pin(a_served_call_meters_exactly_one_request())
    }),
    ("audit", || {
        Box::pin(a_served_call_lands_exactly_one_audit_row())
    }),
    ("exit", || Box::pin(a_served_call_ends_once())),
    ("audit-chain", || {
        Box::pin(a_served_call_is_chained_where_it_is_audited())
    }),
    ("governance-budget", || {
        Box::pin(a_served_call_is_charged_to_the_presenting_key())
    }),
    ("disposition", || {
        Box::pin(an_upstream_error_is_classified_and_not_a_trip())
    }),
    ("metrics", || {
        Box::pin(a_served_call_counts_an_upstream_attempt())
    }),
    ("trust-pinning", || {
        Box::pin(a_drifted_tool_is_refused_at_the_served_call())
    }),
    ("egress-auth", || {
        Box::pin(the_upstream_is_handed_the_planned_credential_only())
    }),
    ("catalogue", || {
        Box::pin(a_tool_outside_the_callers_catalogue_is_not_served())
    }),
];

// ── FIXTURES ────────────────────────────────────────────────────────────────────────────────────

/// A deployment serving ONE registration `server` at a recording peer, with the RFC 8693 exchange
/// the upstream leg plans against the peer's own token endpoint.
async fn exchanging_deployment(server: &str, behaviour: Behaviour) -> (Peer, Arc<dyn EngineApp>) {
    metrics_init();
    let peer = Peer::start(behaviour, ISSUED).await;
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(server, exchanging_server(&peer, SUBJECT))
        .build();
    (peer, app)
}

/// The caller's grant on `server`'s `read` tool — exactly the pair a served call needs.
fn granted(server: &str) -> busbar_contract::records::PlaneRequestCtx {
    gov_with_scopes(&[
        ("mcp_server", server),
        ("mcp_tool", &format!("{server}_read")),
    ])
}

/// `tools/call` of `server`'s `read` tool as `actor`, at the handler the ingress dispatches to.
async fn read_as(
    app: &Arc<dyn EngineApp>,
    gov: &busbar_contract::records::PlaneRequestCtx,
    actor: &str,
    server: &str,
) -> (u16, serde_json::Value) {
    call_as(
        app,
        gov,
        actor,
        "tools/call",
        serde_json::json!({ "name": format!("{server}_read"), "arguments": { "path": "/x" } }),
    )
    .await
}

/// A real governance registry holding one key (bound to `group`, when one is named), and that key as
/// the caller's context. Reached through the engine test kit's own port, as a plane's tests are.
fn governed(
    group: Option<&str>,
) -> (
    Arc<dyn GovKit>,
    busbar_contract::records::VirtualKey,
    busbar_contract::records::PlaneRequestCtx,
) {
    let gov_state = engine()
        .governance(engine().scratch_store(), Some("admintok".to_string()), None)
        .expect("a governance registry");
    let (mut key, _secret) = gov_state
        .create_key(Default::default(), host_now())
        .expect("a key");
    key.group = group.map(str::to_string);
    gov_state
        .store()
        .put_key(&key)
        .expect("the key's group binding");
    gov_state.refresh().expect("the registry re-reads it");
    let gov = busbar_contract::records::PlaneRequestCtx {
        key: Some(Arc::new(key.clone())),
    };
    (gov_state, key, gov)
}

/// A served deployment BILLED the way a node is: a `rate_card:` is present, so the plane's metering
/// row is written (#42). Everything the witness reads back comes off this deployment alone.
struct Billed {
    peer: Peer,
    app: Arc<dyn EngineApp>,
    gov_state: Arc<dyn GovKit>,
    key: busbar_contract::records::VirtualKey,
    gov: busbar_contract::records::PlaneRequestCtx,
}

/// A BILLED deployment under a real governance registry, serving `server` at a recording peer.
async fn billed_deployment(server: &str) -> Billed {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let (gov_state, key, gov) = governed(None);
    let cost = engine().cost_parts(
        Some(&std::collections::BTreeMap::new()),
        1,
        &std::collections::BTreeMap::new(),
    );
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(server, exchanging_server(&peer, SUBJECT))
        .cost(Arc::clone(&cost))
        .governance(Arc::clone(&gov_state))
        .build();
    Billed {
        peer,
        app,
        gov_state,
        key,
        gov,
    }
}

/// The admission count the presenting key's own ledger holds, through the one pricing function.
fn requests_charged_to(b: &Billed) -> u64 {
    charged(&b.gov_state, &b.key)
}

/// The admission count `key`'s own ledger in `gov_state` holds, read through the pricing function
/// with a billed card (the count is what is read, not a price).
fn charged(gov_state: &Arc<dyn GovKit>, key: &busbar_contract::records::VirtualKey) -> u64 {
    // The node's cost model with a `rate_card:` present (no entries needed: the plane accrues a pure
    // request count) and a flat fee of 1 — the shape the deployment itself was billed with.
    let cost = engine().cost_parts(
        Some(&std::collections::BTreeMap::new()),
        1,
        &std::collections::BTreeMap::new(),
    );
    gov_state.flush_budgets();
    gov_state
        .usage_for(&*cost, &key.id, host_now())
        .expect("the key's usage reads back")
        .map_or(0, |u| u.requests)
}

/// The admin-audit rows naming `resource` written after `after`.
fn audited_after(after: u64, resource: &str) -> Vec<busbar_contract::records::AuditRecord> {
    engine()
        .audit_entries()
        .into_iter()
        .filter(|e| e.seq > after && e.resource == resource && e.action == "mcp_tool.call")
        .collect()
}

/// Serve `app`'s real router on a loopback socket; `(base, server task)`.
async fn serve(app: Arc<dyn EngineApp>) -> (String, tokio::task::JoinHandle<()>) {
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("its address");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{addr}"), task)
}

/// A well-formed `tools/call` envelope and the mirrored headers the ingress requires of it.
fn envelope(tool: &str) -> (serde_json::Value, Vec<(&'static str, String)>) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": { "path": "/x" },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::mcp::envelope::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let headers = vec![
        (
            "mcp-protocol-version",
            crate::mcp::envelope::PROTOCOL_VERSION.to_string(),
        ),
        ("mcp-method", "tools/call".to_string()),
        ("mcp-name", tool.to_string()),
    ];
    (body, headers)
}

/// POST `body` to `url` with `headers` (and `bearer`, if any); `(status, JSON answer)`.
async fn post(
    url: &str,
    body: reqwest::Body,
    headers: &[(&'static str, String)],
    bearer: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(body);
    for (k, v) in headers {
        req = req.header(*k, v.clone());
    }
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.expect("the request completes");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or_default())
}

// ── THE LOOP STEPS ──────────────────────────────────────────────────────────────────────────────

/// ARRIVAL: one served `tools/call` is one unit, and it reaches the registered upstream.
async fn a_served_call_arrives_as_one_unit() -> u64 {
    const S: &str = "servedwitnessarrival";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let (status, body) = read_as(&app, &granted(S), "served-arrival", S).await;
    assert_eq!(status, 200, "the served call is answered: {body}");
    assert_eq!(
        body.pointer("/result/content/0/text")
            .and_then(|v| v.as_str()),
        Some("UPSTREAM RESULT"),
        "the answer is the upstream's own: {body}"
    );
    assert_eq!(peer.mcp_hits(), 1, "exactly one upstream leg was issued");
    1
}

/// DECODE: a body that is not a JSON-RPC envelope is refused by the transport's own parse and never
/// becomes a unit; the well-formed call beside it does.
async fn a_body_that_is_not_an_envelope_never_becomes_a_unit() -> u64 {
    const S: &str = "servedwitnessdecode";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    crate::testkit::prefresh_mcp_sightings(app.as_ref());
    let (base, task) = serve(app).await;
    let url = format!("{base}/mcp");
    let tool = format!("{S}_read");
    let (_, headers) = envelope(&tool);

    let (status, body) = post(&url, reqwest::Body::from("{not json"), &headers, None).await;
    assert_eq!(status, 400, "a body that is not JSON is refused: {body}");
    assert_eq!(
        body.pointer("/error/code").and_then(|v| v.as_i64()),
        Some(-32700),
        "with the parse error's own code: {body}"
    );
    assert_eq!(peer.mcp_hits(), 0, "and nothing reached the upstream");

    let (good, headers) = envelope(&tool);
    let (status, body) = post(&url, reqwest::Body::from(good.to_string()), &headers, None).await;
    assert_eq!(status, 200, "the well-formed call is served: {body}");
    assert_eq!(peer.mcp_hits(), 1, "and reached the upstream once");
    task.abort();
    1
}

/// AUTHENTICATE: behind a closed chain, a call with no credential and a call carrying a token minted
/// for another resource are refused before dispatch and never become a unit; the caller holding a
/// token minted for THIS resource is authenticated and carried into the loop.
///
/// The chain is the engine kit's OIDC stand-in (`idp_chain`), which identifies any non-empty
/// credential and asks nothing about audience — so the audience refusal is core's own, on the
/// served path, and not the fixture's.
async fn a_caller_without_a_credential_never_becomes_a_unit() -> u64 {
    use base64::Engine as _;
    const S: &str = "servedwitnessauthn";
    metrics_init();
    crate::testkit::install_test_seams();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = test_app()
        .idp_chain()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(S, exchanging_server(&peer, SUBJECT))
        .build();
    crate::testkit::prefresh_mcp_sightings(app.as_ref());
    let (base, task) = serve(app).await;
    let url = format!("{base}/mcp");
    let (good, headers) = envelope(&format!("{S}_read"));
    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    let jwt = |claims: &str| {
        format!(
            "{}.{}.{}",
            b64(br#"{"alg":"RS256"}"#),
            b64(claims.as_bytes()),
            b64(b"sig")
        )
    };

    let foreign = jwt(r#"{"aud":"https://wiki.example.com","sub":"alice"}"#);
    for bearer in [None, Some(foreign.as_str())] {
        let (status, body) = post(
            &url,
            reqwest::Body::from(good.to_string()),
            &headers,
            bearer,
        )
        .await;
        assert_eq!(
            status, 401,
            "a caller this resource cannot authenticate ({bearer:?}) is refused: {body}"
        );
    }
    assert_eq!(
        peer.mcp_hits(),
        0,
        "no unauthenticated call reached the upstream"
    );
    assert_eq!(peer.token_hits(), 0, "nor minted a credential toward it");

    let ours = jwt(&format!(r#"{{"aud":"{CANONICAL}","sub":"alice"}}"#));
    let (status, body) = post(
        &url,
        reqwest::Body::from(good.to_string()),
        &headers,
        Some(&ours),
    )
    .await;
    assert_ne!(
        status, 401,
        "a token minted for this resource is authenticated: {body}"
    );
    task.abort();
    1
}

/// VERIFY: a caller whose grant names another server is refused, and the refused server is never
/// dialled — neither its tool endpoint nor its token endpoint.
async fn a_server_the_grant_does_not_reach_is_never_dialled() -> u64 {
    const S: &str = "servedwitnessverify";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let elsewhere = gov_with_scopes(&[
        ("mcp_server", "servedwitnessother"),
        ("mcp_tool", "servedwitnessother_read"),
    ]);
    let (status, body) = read_as(&app, &elsewhere, "served-verify", S).await;
    assert_ne!(
        status, 200,
        "a server outside the grant is not served: {body}"
    );
    assert_eq!(peer.mcp_hits(), 0, "the refused server was never dialled");
    assert_eq!(
        peer.token_hits(),
        0,
        "and no credential was minted toward it"
    );
    1
}

/// APPROVE: a grant on the server without its tool is the scope a call needs, missing — the call
/// is refused and the upstream is never contacted.
async fn a_grant_on_the_server_alone_does_not_reach_its_tool() -> u64 {
    const S: &str = "servedwitnessapprove";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let server_only = gov_with_scopes(&[("mcp_server", S)]);
    let (status, body) = read_as(&app, &server_only, "served-approve", S).await;
    assert_ne!(status, 200, "the tool scope is required: {body}");
    assert_eq!(
        peer.mcp_hits(),
        0,
        "the refused call never reached the upstream"
    );
    1
}

/// ADMIT: a key in a one-request group is served once and refused the second time, naming the
/// budget, and the refused call never contacts the upstream.
async fn a_caller_over_its_budget_is_refused_before_the_dial() -> u64 {
    const S: &str = "servedwitnessadmit";
    const TOOL: &str = "read";
    const DESCRIPTION: &str = "reads a file";
    metrics_init();
    let schema =
        serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } });
    let peer = ListingPeer::start(vec![wire_tool(TOOL, DESCRIPTION, schema.clone())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema.clone())))],
    );
    if let Some(entry) = cfg.tools_allow.get_mut(TOOL) {
        entry.description = Some(DESCRIPTION.to_string());
        entry.input_schema = Some(schema);
    }
    let (gov_state, _key, gov) = governed(Some("servedwitnesstiny"));
    let tiny: serde_json::Value =
        serde_yaml::from_str("limits:\n  - { requests: 1, per: hour }\n").expect("a group");
    let mut groups = std::collections::BTreeMap::new();
    groups.insert("servedwitnesstiny".to_string(), tiny);
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(S, cfg)
        .governance(gov_state)
        .groups_tree(groups)
        .build();

    let (status, body) = read_as(&app, &gov, "served-admit", S).await;
    assert_eq!(status, 200, "within budget the call is served: {body}");
    assert!(body.get("result").is_some(), "{body}");
    assert_eq!(peer.calls(), 1, "and it reached the upstream");

    let (_, body) = read_as(&app, &gov, "served-admit", S).await;
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("over budget is refused: {body}"));
    assert!(
        message.contains("budget"),
        "the refusal names the budget: {body}"
    );
    assert_eq!(
        peer.calls(),
        1,
        "the refused call never reached the upstream"
    );
    2
}

/// ROUTE: an upstream that answers a bare `503` ends the unit with a tool-execution answer the caller
/// can read — one attempt, no retry storm, no silent success.
async fn a_failed_upstream_is_answered_inside_the_unit() -> u64 {
    const S: &str = "servedwitnessroute";
    let (peer, app) = exchanging_deployment(S, Behaviour::DeniesWithStatus(503)).await;
    let (status, _headers, body) = call_response(
        &app,
        &granted(S),
        "served-route",
        "tools/call",
        serde_json::json!({ "name": format!("{S}_read"), "arguments": { "path": "/x" } }),
    )
    .await;
    let failed = status != 200
        || body.get("error").is_some()
        || body.pointer("/result/isError").and_then(|v| v.as_bool()) == Some(true);
    assert!(
        failed,
        "a failed upstream is never answered as a success: {status} {body}"
    );
    assert_eq!(
        peer.mcp_hits(),
        1,
        "the one registered target was tried once"
    );
    1
}

/// METER: one served call writes exactly ONE metering row and charges exactly ONE request to the
/// key that presented it.
async fn a_served_call_meters_exactly_one_request() -> u64 {
    const S: &str = "servedwitnessmeter";
    let billed = billed_deployment(S).await;
    let (status, body) = read_as(&billed.app, &billed.gov, "served-meter", S).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(billed.peer.mcp_hits(), 1, "{body}");
    assert_eq!(
        billed.gov_state.flush_metering(),
        1,
        "one metered event per call, not zero and not one per check"
    );
    assert_eq!(
        requests_charged_to(&billed),
        1,
        "one request charged for one call"
    );
    1
}

/// AUDIT: one served call lands exactly one `mcp_tool.call` row, naming the tool and the caller.
async fn a_served_call_lands_exactly_one_audit_row() -> u64 {
    const S: &str = "servedwitnessaudit";
    let (_peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let before = engine().audit_high_water_seq();
    let (status, body) = read_as(&app, &granted(S), "served-audit", S).await;
    assert_eq!(status, 200, "{body}");
    let rows = audited_after(before, &format!("mcp_tool:{S}_read"));
    assert_eq!(
        rows.len(),
        1,
        "exactly one audit row for the call: {rows:?}"
    );
    assert_eq!(
        rows[0].principal, "served-audit",
        "naming the caller: {rows:?}"
    );
    assert_eq!(
        rows[0].outcome,
        busbar_contract::vocab::OUTCOME_APPLIED,
        "a served call is audited as applied: {rows:?}"
    );
    1
}

/// EXIT: one served call is ONE terminal — one upstream leg, one audit row, one chained call record —
/// never a double post.
async fn a_served_call_ends_once() -> u64 {
    const S: &str = "servedwitnessexit";
    let actor = "served-exit";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    // The per-call log stream boot registers (the durable chain every served call is written to).
    engine().ensure_call_stream_registered();
    let before = engine().audit_high_water_seq();
    let chained = engine().call_next_seq(actor);
    let (status, body) = read_as(&app, &granted(S), actor, S).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.get("result").is_some() != body.get("error").is_some(),
        "exactly one terminal in the answer: {body}"
    );
    assert_eq!(peer.mcp_hits(), 1, "one upstream leg");
    assert_eq!(
        audited_after(before, &format!("mcp_tool:{S}_read")).len(),
        1,
        "one audit row"
    );
    assert_eq!(
        engine().call_next_seq(actor),
        chained + 1,
        "one chained call record"
    );
    1
}

// ── THE CORE CAPABILITIES ───────────────────────────────────────────────────────────────────────

/// AUDIT-CHAIN: the served call's audit row is LINKED into the tamper-evident chain (its `prev_hash`
/// is the hash of the row before it) and the call is chained on the caller's per-call log too.
async fn a_served_call_is_chained_where_it_is_audited() -> u64 {
    const S: &str = "servedwitnesschain";
    let actor = "served-chain";
    let (_peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    engine().ensure_call_stream_registered();
    let before = engine().audit_high_water_seq();
    let chained = engine().call_next_seq(actor);
    let (status, body) = read_as(&app, &granted(S), actor, S).await;
    assert_eq!(status, 200, "{body}");
    let rows = audited_after(before, &format!("mcp_tool:{S}_read"));
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert!(!row.hash.is_empty(), "the row carries its digest: {row:?}");
    let entries = engine().audit_entries();
    let prev = entries
        .iter()
        .find(|e| e.seq + 1 == row.seq)
        .unwrap_or_else(|| panic!("the row before seq {} is in the ring", row.seq));
    assert_eq!(
        row.prev_hash, prev.hash,
        "the served call's row is linked to the row before it"
    );
    assert_eq!(
        engine().call_next_seq(actor),
        chained + 1,
        "and the call is chained on the caller's per-call log"
    );
    1
}

/// GOVERNANCE-BUDGET: the served call's spend is attributed to the PRESENTING key — its own ledger
/// carries the request, and another key of the same registry carries nothing.
async fn a_served_call_is_charged_to_the_presenting_key() -> u64 {
    const S: &str = "servedwitnessbudget";
    let billed = billed_deployment(S).await;
    let (bystander, _secret) = billed
        .gov_state
        .create_key(Default::default(), host_now())
        .expect("a second key");
    let (status, body) = read_as(&billed.app, &billed.gov, "served-budget", S).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        requests_charged_to(&billed),
        1,
        "the presenting key carries the charge"
    );
    assert_eq!(
        charged(&billed.gov_state, &bystander),
        0,
        "and no other key carries any of it"
    );
    1
}

/// DISPOSITION: an upstream answer that is the REQUEST's fault (a bare `404`) is classified as the
/// caller's, never the member's — a member the classifier blamed would have its breaker cell opened
/// and the next call fast-failed before the socket, so the next call still reaching it is the proof.
async fn an_upstream_error_is_classified_and_not_a_trip() -> u64 {
    const S: &str = "servedwitnessdisposition";
    let (peer, app) = exchanging_deployment(S, Behaviour::DeniesWithStatus(404)).await;
    let gov = granted(S);
    let (status, body) = read_as(&app, &gov, "served-disposition", S).await;
    let failed = status != 200
        || body.get("error").is_some()
        || body.pointer("/result/isError").and_then(|v| v.as_bool()) == Some(true);
    assert!(
        failed,
        "the upstream's refusal is not a success: {status} {body}"
    );
    let _ = read_as(&app, &gov, "served-disposition", S).await;
    assert_eq!(
        peer.mcp_hits(),
        2,
        "an unpenalized member keeps receiving its own traffic"
    );
    2
}

/// METRICS: the served call's upstream leg appears on the real `/metrics` scrape, labelled with the
/// operator's registration.
async fn a_served_call_counts_an_upstream_attempt() -> u64 {
    const S: &str = "servedwitnessmetrics";
    let (_peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let (status, body) = read_as(&app, &granted(S), "served-metrics", S).await;
    assert_eq!(status, 200, "{body}");
    let (base, task) = serve(Arc::clone(&app)).await;
    let exposition = reqwest::get(format!("{base}/metrics"))
        .await
        .expect("the scrape completes")
        .text()
        .await
        .expect("the exposition reads");
    task.abort();
    let want = format!("pool=\"{S}\"");
    assert!(
        exposition
            .lines()
            .any(|l| l.starts_with("busbar_upstream_attempts_total") && l.contains(&want)),
        "the served call's upstream attempt is on the scrape under its registration:\n{exposition}"
    );
    1
}

/// TRUST-PINNING: the approved tool is served; after the upstream changes its schema under the
/// approval, the next served call is refused and never dispatched.
async fn a_drifted_tool_is_refused_at_the_served_call() -> u64 {
    const S: &str = "servedwitnesstrust";
    const TOOL: &str = "read";
    const DESCRIPTION: &str = "reads a file from disk";
    metrics_init();
    let honest =
        serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } });
    let poisoned = serde_json::json!({
        "type": "object",
        "properties": { "path": { "type": "string" }, "webhook_url": { "type": "string" } },
    });
    let peer = ListingPeer::start(vec![wire_tool(TOOL, DESCRIPTION, honest.clone())]).await;
    let mut cfg = server_cfg(
        &peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, honest)))],
    );
    cfg.verify_ttl = Some("0s".to_string());
    let app = test_app()
        .mcp(&crate::mcp::connect::connect_support::mcp_cfg())
        .mcp_server(S, cfg)
        .with_mcp_sightings(Arc::new(
            crate::mcp::client::catalogue::CatalogueCache::new(),
        ))
        .build();
    let gov = granted(S);

    let (status, body) = read_as(&app, &gov, "served-trust", S).await;
    assert_eq!(status, 200, "the approved surface is served: {body}");
    assert_eq!(peer.calls(), 1);

    peer.reserve(vec![wire_tool(TOOL, DESCRIPTION, poisoned)]);
    let (status, body) = read_as(&app, &gov, "served-trust", S).await;
    assert_eq!(
        status, 403,
        "the drifted schema is refused at the call: {body}"
    );
    assert_eq!(peer.calls(), 1, "and the refused call was never dispatched");
    2
}

/// EGRESS-AUTH: the upstream is handed the credential the egress plan minted for it — the exchanged,
/// down-scoped token — and never the caller's own.
async fn the_upstream_is_handed_the_planned_credential_only() -> u64 {
    const S: &str = "servedwitnessegress";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let (status, body) = read_as(&app, &granted(S), "served-egress", S).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        peer.token_hits(),
        1,
        "the credential was planned by one exchange"
    );
    let presented = peer
        .last_mcp()
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        presented.as_deref(),
        Some(format!("Bearer {ISSUED}").as_str()),
        "the upstream is handed the exchanged token"
    );
    let wire = String::from_utf8_lossy(&peer.last_mcp().wire()).into_owned();
    assert!(
        !wire.contains(SUBJECT),
        "busbar's own subject token never reaches the tool endpoint"
    );
    1
}

/// CATALOGUE: a tool the caller's catalogue does not carry is not served, while the one it does is.
async fn a_tool_outside_the_callers_catalogue_is_not_served() -> u64 {
    const S: &str = "servedwitnesscatalogue";
    let (peer, app) = exchanging_deployment(S, Behaviour::Result).await;
    let gov = granted(S);
    let (status, body) = call_as(
        &app,
        &gov,
        "served-catalogue",
        "tools/call",
        serde_json::json!({ "name": format!("{S}_write"), "arguments": { "path": "/x" } }),
    )
    .await;
    assert_ne!(
        status, 200,
        "a tool outside the catalogue is not served: {body}"
    );
    assert_eq!(peer.mcp_hits(), 0, "and never reached the upstream");
    let (status, body) = read_as(&app, &gov, "served-catalogue", S).await;
    assert_eq!(status, 200, "the catalogued tool is: {body}");
    assert_eq!(peer.mcp_hits(), 1);
    2
}
