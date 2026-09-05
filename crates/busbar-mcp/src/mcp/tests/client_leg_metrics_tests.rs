// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP CLIENT LEG ON `/metrics` — the `metrics x mcp-client` cell of
//! `qa/capability-equality.json`, driven at a real peer and read back off a real scrape.
//!
//! ## The gap this closes, stated as the operator saw it
//!
//! `plane` was a FRONT-DOOR-ONLY label. All three `telemetry::request_finished` call sites are
//! inbound — `ingress::finish_inner`, `plane::observe`, `a2a::receive::invoke` — so busbar emitted a
//! per-plane series for traffic ARRIVING and nothing at all for the upstream calls it ORIGINATES.
//! There were zero `metrics::`/`counter!` uses anywhere in `mcp/` production code. A registered MCP
//! server that had stopped answering was not an under-labelled series on an operator's dashboard: it
//! was no series, and the dashboard looked exactly as it does when everything is healthy.
//!
//! ## Why this asserts the MODEL PLANE'S OWN FAMILIES and not new ones
//!
//! `busbar_upstream_attempts_total` and `busbar_upstream_failures_total` are what
//! `proxy::engine` has always emitted for the LLM client leg. Under the equality doctrine a plane
//! does not get an observability vocabulary of its own — it gets the same one with its own label
//! values — so the assertions below are written against the families and the LABEL KEYS the model
//! plane already publishes. A second family here would be green and would still leave an operator
//! unable to write one query across the gateway's egress.
//!
//! ## Why the scrape is a real HTTP GET and the traffic is a real socket
//!
//! The engine's own plane metrics battery (`plane::tests::metrics_tests`) states the rule this file follows: the failure guarded
//! against is not "the counter macro does not increment", it is "the emission is not on the path a
//! deployment runs". So the call goes through `mcp::method::dispatch` to a REAL fake peer on a real
//! loopback port, and the numbers are read out of the REAL `GET /metrics` route on a router built
//! by the engine's router (`build_router`). A test that called `telemetry::upstream_attempt_on` directly would pass
//! against an emit site no request ever reaches.
//!
//! ## The pool label is unique to this file ON PURPOSE
//!
//! The recorder is process-global and this binary runs its tests in parallel, so a sibling's traffic
//! is in the same exposition. Every registration here carries a name no other test uses, which is
//! what makes "this series exists" a statement about THIS leg.

use super::upstream_support::{call, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer};
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";
/// The registration name that IS the `pool` label. Unique in this binary — see the module header.
const SERVED: &str = "metricsclientfs";
/// A second registration, pointed at a port nothing is listening on.
const DEAD: &str = "metricsclientdead";
/// A third, likewise dead — its own name so its series is this test's alone. See the module header.
const UNREACHABLE: &str = "metricsclientunreachable";

/// Every non-comment `/metrics` line for `family` carrying `pool="<pool>"`.
fn series_for<'a>(exposition: &'a str, family: &str, pool: &str) -> Vec<&'a str> {
    let want = format!("pool=\"{pool}\"");
    exposition
        .lines()
        .filter(|l| !l.starts_with('#') && l.starts_with(family) && l.contains(&want))
        .collect()
}

/// The label KEYS of one exposition line, sorted.
fn keys_of(line: &str) -> Vec<String> {
    line.split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}'))
        .map(|(inner, _)| {
            let mut ks: Vec<String> = inner
                .split(',')
                .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string()))
                .collect();
            ks.sort();
            ks
        })
        .unwrap_or_default()
}

/// Scrape the REAL `/metrics` route on a router built exactly as production builds it.
async fn scrape(app: &std::sync::Arc<dyn EngineApp>) -> String {
    let router = build_router(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the built-in prometheus exporter must serve /metrics on this router"
    );
    let body = resp.text().await.unwrap();
    server.abort();
    body
}

/// A LOOPBACK PORT WITH NOTHING BEHIND IT. Bound and then dropped, so the address is real, is
/// certainly not in use by anything else in this binary, and refuses the connection immediately.
/// The refusal happens at CONNECT, so the transport classifies it as the pre-first-byte variant —
/// the one the reroute seam is allowed to move — and the client leg counts it as a failure all the
/// same. See `an_unreachable_leg_is_counted_as_a_failure_and_not_only_as_an_attempt`.
async fn dead_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// A `tools/call` THAT REACHES A REAL UPSTREAM produces `busbar_upstream_attempts_total` naming the
/// operator's registration, on a real `/metrics` scrape, in the model plane's own series shape.
///
/// Delete the count from `mcp::client::wire::send` and this fails on its first assertion: the MCP
/// client leg emits no metric of any kind, so there is no series to be wrong about.
#[tokio::test]
async fn a_tool_call_counts_an_upstream_attempt_naming_the_registration_it_was_issued_to() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(SERVED, exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[
        ("mcp_server", SERVED),
        ("mcp_tool", &format!("{SERVED}_read")),
    ]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": format!("{SERVED}_read"), "arguments": {} }),
    )
    .await;
    assert_eq!(status, 200, "the call must reach the upstream: {body}");
    assert_eq!(peer.mcp_hits(), 1, "exactly one leg was issued");

    let exposition = scrape(&app).await;
    let attempts = series_for(
        &exposition,
        busbar_substrate::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
        SERVED,
    );
    assert!(
        !attempts.is_empty(),
        "the MCP client leg reached a real upstream and left no `{}` series for \
         pool=\"{SERVED}\". An operator cannot see the calls busbar originates. Exposition:\n{exposition}",
        busbar_substrate::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
    );

    // THE CHANNEL IS NAMED, off the transport axis's own `name()` and not a spelling invented here.
    assert!(
        attempts.iter().any(|l| l.contains("lane=\"http\"")),
        "the leg's channel must be on the series, so a child process that keeps dying and an HTTPS \
         peer that keeps timing out are distinguishable: {attempts:?}"
    );

    // NOT A SECOND VOCABULARY. The label keys are exactly the model plane's, which is the whole
    // claim: `sum by (pool) (rate(busbar_upstream_attempts_total[5m]))` covers every client leg.
    assert_eq!(
        keys_of(attempts[0]),
        vec!["lane".to_string(), "pool".to_string()],
        "the MCP client leg invented a differently-shaped series: {}",
        attempts[0]
    );

    // A REACHABLE UPSTREAM IS NOT A FAILURE. The failure family means availability; a leg that was
    // served must not appear on it, or the panel reads an outage at a healthy peer.
    assert!(
        series_for(
            &exposition,
            busbar_substrate::telemetry::UPSTREAM_FAILURES_TOTAL,
            SERVED
        )
        .is_empty(),
        "a served leg must not be counted as an upstream failure. Exposition:\n{exposition}"
    );
}

/// AN UNREACHABLE UPSTREAM lands on `busbar_upstream_failures_total` with the MODEL PLANE'S OWN
/// disposition word, beside its attempt.
///
/// The pair is the point: an attempt with no failure and an attempt with a failure are what make a
/// per-registration error RATE computable, and a family that only ever counted successes would let a
/// dead upstream sit at 100% healthy.
#[tokio::test]
async fn an_upstream_that_cannot_be_reached_is_counted_as_a_transient_failure_beside_its_attempt() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let mut cfg = exchanging_server(&peer, SUBJECT);
    // The registration keeps the peer's live token endpoint — the exchange must SUCCEED, so the leg
    // that fails is the tool call itself and not a refusal that never reached a socket.
    cfg.url = format!("http://127.0.0.1:{}/mcp", dead_port().await);
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(DEAD, cfg)
        .build();
    let g = gov_with_scopes(&[("mcp_server", DEAD), ("mcp_tool", &format!("{DEAD}_read"))]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": format!("{DEAD}_read"), "arguments": {} }),
    )
    .await;
    // A tool call whose upstream cannot be reached is a TOOL-LEVEL error, not a protocol one: the
    // envelope is a 200 carrying `isError`. That is what the caller sees, and it is exactly why the
    // metric matters — nothing about this answer tells an operator that a registration is down.
    assert_eq!(status, 200, "the tool-level error shape: {body}");
    assert_eq!(
        body.pointer("/result/isError"),
        Some(&serde_json::Value::Bool(true)),
        "the leg must have failed at the wire: {body}"
    );

    let exposition = scrape(&app).await;
    let attempts = series_for(
        &exposition,
        busbar_substrate::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
        DEAD,
    );
    assert!(
        !attempts.is_empty(),
        "a leg busbar actually attempted must be counted even when it failed, or the error rate has \
         no denominator. Exposition:\n{exposition}"
    );
    let failures = series_for(
        &exposition,
        busbar_substrate::telemetry::UPSTREAM_FAILURES_TOTAL,
        DEAD,
    );
    assert!(
        !failures.is_empty(),
        "the upstream was unreachable and left no `{}` series for pool=\"{DEAD}\". Exposition:\n{exposition}",
        busbar_substrate::telemetry::UPSTREAM_FAILURES_TOTAL,
    );
    assert!(
        failures.iter().any(|l| l.contains(&format!(
            "disposition=\"{}\"",
            busbar_substrate::proxy::DISPOSITION_TRANSIENT
        ))),
        "the failure must carry the MODEL PLANE'S disposition word, not one of this plane's own: \
         {failures:?}"
    );
    assert_eq!(
        keys_of(failures[0]),
        vec![
            "disposition".to_string(),
            "lane".to_string(),
            "pool".to_string()
        ],
        "the MCP client leg invented a differently-shaped failure series: {}",
        failures[0]
    );
}

/// THE PRE-FIRST-BYTE FAILURE IS STILL A FAILURE — the boundary the reroute work put at risk, and
/// the reason this file has a second unreachable test rather than one.
///
/// The failover seam needed to tell a leg that NEVER LEFT BUSBAR (safe to move to a twin) from one
/// that may already have landed (a genuine retry), so the transport grew a second connect-class
/// error variant beside its existing I/O one. That distinction is about DUPLICATION SAFETY and says
/// nothing whatever about health — but a counting rule written against the old single variant
/// silently stops matching the new one, and the leg then lands on
/// `busbar_upstream_attempts_total` and on NOTHING else. The series does not disappear, which is
/// what makes it dangerous: an operator's per-registration error rate *falls toward zero* exactly
/// as a pooled upstream stops answering, because the denominator keeps climbing.
///
/// So this asserts both halves against one real refused connect, on a real scrape:
///
/// 1. the leg really took the PRE-FIRST-BYTE arm — proven by the wording the caller is answered
///    with, which only that arm renders, not by naming a variant; and
/// 2. it is on the failure family anyway, with the same transient disposition an I/O failure gets.
///
/// Restore the rule to the I/O variant alone and assertion 2 fails while assertion 1 still passes,
/// which is precisely the shape of the regression.
#[tokio::test]
async fn an_unreachable_leg_is_counted_as_a_failure_and_not_only_as_an_attempt() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let mut cfg = exchanging_server(&peer, SUBJECT);
    cfg.url = format!("http://127.0.0.1:{}/mcp", dead_port().await);
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(UNREACHABLE, cfg)
        .build();
    let g = gov_with_scopes(&[
        ("mcp_server", UNREACHABLE),
        ("mcp_tool", &format!("{UNREACHABLE}_read")),
    ]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": format!("{UNREACHABLE}_read"), "arguments": {} }),
    )
    .await;
    assert_eq!(status, 200, "the tool-level error shape: {body}");

    // (1) THE ARM. `could not be reached` is the pre-first-byte rendering and nothing else in the
    // tree produces it; the post-connect arm says `transport error` instead. Asserting the text the
    // caller is actually answered with keeps this test honest if the variants are ever renamed.
    let rendered = body.to_string();
    assert!(
        rendered.contains("could not be reached"),
        "this leg must fail at CONNECT, so the counting rule is being tested on the pre-first-byte \
         arm rather than on the ordinary I/O one: {body}"
    );

    // (2) THE COUNT. Attempt and failure, or the error rate lies in exactly the direction that
    // hides an outage.
    let exposition = scrape(&app).await;
    assert!(
        !series_for(
            &exposition,
            busbar_substrate::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
            UNREACHABLE
        )
        .is_empty(),
        "the attempt is the denominator. Exposition:\n{exposition}"
    );
    let failures = series_for(
        &exposition,
        busbar_substrate::telemetry::UPSTREAM_FAILURES_TOTAL,
        UNREACHABLE,
    );
    assert!(
        !failures.is_empty(),
        "a leg that could not reach its peer at all was counted as an ATTEMPT and not as a \
         FAILURE: pool=\"{UNREACHABLE}\" now reports a 0% error rate while answering nothing. \
         Exposition:\n{exposition}"
    );
    assert!(
        failures.iter().any(|l| l.contains(&format!(
            "disposition=\"{}\"",
            busbar_substrate::proxy::DISPOSITION_TRANSIENT
        ))),
        "an unreachable peer may come back, so it carries the same transient word an I/O failure \
         does — a second disposition here would split one outage across two panels: {failures:?}"
    );
}
