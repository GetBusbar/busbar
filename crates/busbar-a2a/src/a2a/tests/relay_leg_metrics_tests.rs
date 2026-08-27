// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A RELAY LEG ON `/metrics` — the `metrics x a2a-client` cell of
//! `qa/capability-equality.json`, driven through the real ingress and read back off a real scrape.
//!
//! ## The gap this closes
//!
//! `plane` was a FRONT-DOOR-ONLY label: all three `telemetry::request_finished` sites are inbound,
//! and there were zero `metrics::`/`counter!` uses anywhere in `a2a/` production code. So busbar
//! published a per-plane series for every task ARRIVING and nothing at all for the hops it
//! ORIGINATES at a backend agent. A registered agent that had stopped answering produced no series
//! to alert on — not a flat line, no line.
//!
//! ## The same two families the MODEL plane's client leg has always emitted
//!
//! `busbar_upstream_attempts_total` and `busbar_upstream_failures_total`, with the model plane's own
//! label keys and its own `disposition` vocabulary. Under the equality doctrine a plane gets the
//! same mechanism with its own label values, never an observability vocabulary of its own — a second
//! family here would be green and would still leave an operator unable to write one query across the
//! gateway's egress. `pool` is the operator's `agent_def` id and `lane` is the binding word off the
//! closed transport axis, so both are bounded by the config file.
//!
//! ## Why the harness and not a socket
//!
//! `relay_harness`'s own header states the rule: the SSRF guard refuses loopback with no override,
//! so a recording seam stands in for the socket and the socket half is discharged in
//! `transport_tests`. What matters for THIS claim is unchanged by that — the traffic goes through
//! `crate::build_router` and the production `a2a::receive` ingress into the production
//! `a2a::relay::relay`, and the numbers are read out of the REAL `GET /metrics` route on the same
//! router (see `scrape` for the one substitution and its argument). A test that called the emit
//! helper directly would pass against a site no task reaches.
//!
//! ## NOTHING HERE ASSERTS AN ABSENCE
//!
//! The recorder is process-global and every sibling in this harness drives the same `planner`
//! registration, so "no series for this pool" is not a statement this file can make honestly. What
//! it asserts is that a driven leg PRODUCES the series, in the model plane's shape — which is
//! exactly what fails when the emit is removed, because then nothing in the tree emits it.

use super::relay_harness::{call, harness, Harness, Outcome};

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

/// THE BYTES AN OPERATOR'S SCRAPE RECEIVES, from the production `GET /metrics` dispatcher itself.
///
/// [`crate::export::prometheus::PrometheusExport::handle_http`] is what the mounted route runs; this
/// calls it rather than issuing an HTTP GET at the harness's router because that route's declared
/// auth is `key` (`export::prometheus::route_decl`) and the only credential this harness mints is
/// AUDIENCE-BOUND to `/a2a` — presenting it at `/metrics` is correctly a `401`, which is a fact
/// about RFC 8707 audience binding and not about whether this leg is counted. The route being
/// mounted and answering a real HTTP GET is proven by
/// `crate::mcp::upstream::client_leg_metrics_tests` and by `export::tests::prometheus_tests`; what
/// is proven HERE is that a relayed hop puts a series into the exposition those two serve.
fn scrape(_h: &Harness) -> String {
    use crate::plugin_routes::PluginHttpDispatch;
    use busbar_plugin_loader::HttpEndpointRequest;
    let resp = crate::export::prometheus::PrometheusExport.handle_http(&HttpEndpointRequest {
        method: "GET".into(),
        path: "/metrics".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    });
    assert_eq!(
        resp.status, 200,
        "the built-in prometheus exporter must serve the exposition"
    );
    String::from_utf8(resp.body).expect("the exposition is UTF-8")
}

/// A RELAYED TASK produces `busbar_upstream_attempts_total` naming the operator's registration and
/// the binding the hop went out on, on a real `/metrics` scrape, in the model plane's series shape.
///
/// Delete the count from `a2a::relay::prepare` and this fails on its first assertion: the A2A relay
/// leg emits no metric of any kind, so there is no series to be wrong about.
#[tokio::test]
async fn a_relayed_task_counts_an_upstream_attempt_naming_the_agent_it_was_issued_to() {
    let h = harness(
        Outcome::AnswersCorrelated(200, super::relay_harness::backend_ok()),
        false,
    )
    .await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the task must reach the backend: {body}");
    assert_eq!(h.sent().len(), 1, "exactly one hop was relayed");

    let exposition = scrape(&h);
    let attempts = series_for(
        &exposition,
        crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
        "planner",
    );
    assert!(
        !attempts.is_empty(),
        "the A2A relay leg reached a backend agent and left no `{}` series for pool=\"planner\". \
         An operator cannot see the hops busbar originates. Exposition:\n{exposition}",
        crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
    );

    // THE BINDING IS NAMED, off the transport axis's own word and not a spelling invented here, so
    // the metric label, the plane's dialect list and a served card's `protocolBinding` stay one
    // vocabulary.
    assert!(
        attempts
            .iter()
            .any(|l| l.contains(&format!("lane=\"{}\"", crate::plane::WIRE_JSONRPC))),
        "the hop's binding must be on the series: {attempts:?}"
    );

    // NOT A SECOND VOCABULARY: exactly the model plane's label keys.
    assert_eq!(
        keys_of(attempts[0]),
        vec!["lane".to_string(), "pool".to_string()],
        "the A2A relay leg invented a differently-shaped series: {}",
        attempts[0]
    );
}

/// A BACKEND THAT CANNOT BE REACHED lands on `busbar_upstream_failures_total` under the model
/// plane's own disposition word.
///
/// The pair with the attempt above is the point: without a failure family a dead agent sits at 100%
/// healthy on any rate panel an operator can write.
#[tokio::test]
async fn a_backend_that_cannot_be_reached_is_counted_as_a_transient_upstream_failure() {
    let h = harness(
        Outcome::Fails("connection refused by the backend agent".to_string()),
        false,
    )
    .await;
    let (status, body) = call(&h).await;
    assert_ne!(
        status, 200,
        "a hop that never reached the backend must refuse: {body}"
    );

    let exposition = scrape(&h);
    let failures = series_for(
        &exposition,
        crate::metrics::UPSTREAM_FAILURES_TOTAL,
        "planner",
    );
    assert!(
        !failures.is_empty(),
        "the backend was unreachable and left no `{}` series for pool=\"planner\". \
         Exposition:\n{exposition}",
        crate::metrics::UPSTREAM_FAILURES_TOTAL,
    );
    assert!(
        failures.iter().any(|l| l.contains(&format!(
            "disposition=\"{}\"",
            crate::proxy::DISPOSITION_TRANSIENT
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
        "the A2A relay leg invented a differently-shaped failure series: {}",
        failures[0]
    );
}
