// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE PROMETHEUS SERIES SHAPE, THREE PLANES — asserted on a REAL `/metrics` scrape.
//!
//! Before this module, `busbar_requests_total` and `busbar_request_duration_seconds` were emitted
//! from `ingress::finish_inner` and nowhere else, which is the MODEL plane's ingress only. A tool
//! call and an agent task were not under-labelled on `/metrics` — they were ABSENT. An operator
//! watching a dashboard saw model traffic and had no signal at all that the MCP or A2A plane was
//! failing.
//!
//! ## Why this drives the router and scrapes `/metrics` rather than calling the emit helper
//!
//! The failure this guards against is not "the macro does not increment". It is "the emission is
//! not on the path a deployment actually runs". So every assertion below goes through
//! `crate::build_router` over a real socket, and reads the exposition back out of the real
//! `GET /metrics` route (the built-in `prometheus` exporter's plugin route, mounted exactly as
//! production mounts it). A test that called `telemetry::request_finished` directly would pass
//! against a handler that was mounted nowhere — the same shape as a store plugin whose unit tests
//! pass while its ABI drops every write.

use crate::a2a::config::{AgentDefCfg, AgentPinCfg, PinMechanism};
use crate::mcp::ingress::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

fn mcp_cfg() -> McpCfg {
    McpCfg {
        canonical_uri: CANONICAL.to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

fn unpinned_agent(url: &str) -> AgentDefCfg {
    AgentDefCfg {
        url: url.to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::Unpinned,
            key: None,
            fingerprint: None,
        },
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        allow_private: false,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        client_identity: None,
        hooks: Vec::new(),
    }
}

/// A well-formed MCP JSON-RPC envelope for `method`, with the mirrored headers the transport
/// requires. Nothing here is malformed: the point is REAL tool-plane traffic.
fn mcp_envelope(method: &str) -> (serde_json::Value, Vec<(&'static str, String)>) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let headers = vec![
        ("mcp-protocol-version", PROTOCOL_VERSION.to_string()),
        ("mcp-method", method.to_string()),
    ];
    (body, headers)
}

/// Every non-comment `/metrics` line for `family` that carries `plane="<plane>"`.
fn series_for<'a>(exposition: &'a str, family: &str, plane: &str) -> Vec<&'a str> {
    let want = format!("plane=\"{plane}\"");
    exposition
        .lines()
        .filter(|l| !l.starts_with('#') && l.starts_with(family) && l.contains(&want))
        .collect()
}

/// A TOOL CALL and an AGENT TASK each produce a `busbar_requests_total` and a
/// `busbar_request_duration_seconds` series on a real `/metrics` scrape, labelled with the plane
/// they arrived on.
///
/// RED BEFORE GREEN: on the pre-change tree this fails on the very first assertion, because
/// `plane` is not a label on any series and no MCP or A2A request reaches an emission site at all.
#[tokio::test]
async fn mcp_and_a2a_traffic_appear_on_a_real_metrics_scrape() {
    crate::metrics::init();
    let app = TestApp::new()
        .public_url("https://busbar.example")
        .mcp(&mcp_cfg())
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // ── TOOL-PLANE TRAFFIC ──────────────────────────────────────────────────────────────────────
    let (body, headers) = mcp_envelope("tools/list");
    let mut req = client.post(format!("{base}/mcp")).json(&body);
    for (k, v) in &headers {
        req = req.header(*k, v.clone());
    }
    let mcp_status = req.send().await.unwrap().status().as_u16();

    // ── AGENT-PLANE TRAFFIC ─────────────────────────────────────────────────────────────────────
    let a2a_status = client
        .post(format!("{base}/a2a/agents/planner"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": { "message": { "role": "user", "parts": [{ "kind": "text", "text": "go" }] } },
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();

    // ── MODEL-PLANE TRAFFIC, so the three planes are compared on ONE scrape ─────────────────────
    // An unroutable model is deliberate: it reaches `ingress::finish_inner` without needing an
    // upstream, which is all this assertion needs. The point is the SERIES SHAPE, not the status.
    let llm_status = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "no-such-model",
            "messages": [{ "role": "user", "content": "hi" }],
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();

    // ── THE SCRAPE, through the real `/metrics` route ───────────────────────────────────────────
    let scrape = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(
        scrape.status().as_u16(),
        200,
        "the built-in prometheus exporter must serve /metrics on this router"
    );
    let exposition = scrape.text().await.unwrap();
    server.abort();

    // ONE FAMILY, THREE PLANES. Asserted over all three together rather than over the two new ones,
    // because the claim being made is that an operator can write
    // `sum by (plane) (rate(busbar_requests_total[5m]))` and see the whole gateway — which is false
    // the moment any plane answers in a vocabulary of its own.
    for plane in ["llm", "mcp", "a2a"] {
        let counters = series_for(&exposition, crate::metrics::REQUESTS_TOTAL, plane);
        assert!(
            !counters.is_empty(),
            "no `{}` series for plane=\"{plane}\" after driving real traffic \
             (mcp {mcp_status}, a2a {a2a_status}, llm {llm_status}). Exposition:\n{exposition}",
            crate::metrics::REQUESTS_TOTAL,
        );
        let durations = series_for(&exposition, crate::metrics::REQUEST_DURATION_SECONDS, plane);
        assert!(
            !durations.is_empty(),
            "no `{}` series for plane=\"{plane}\" after driving real traffic. Exposition:\n{exposition}",
            crate::metrics::REQUEST_DURATION_SECONDS,
        );
    }

    // The two new planes did NOT arrive as a second vocabulary: their series carry exactly the
    // label keys the model plane's do, so a panel written against one works against all three.
    let keys_of = |line: &str| -> Vec<String> {
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
    };
    let llm_keys = keys_of(series_for(&exposition, crate::metrics::REQUESTS_TOTAL, "llm")[0]);
    assert_eq!(
        llm_keys,
        vec![
            "ingress_protocol".to_string(),
            "outcome".to_string(),
            "plane".to_string(),
            "pool".to_string()
        ],
        "the model plane's label set is the contract the other two are held to"
    );
    for plane in ["mcp", "a2a"] {
        for line in series_for(&exposition, crate::metrics::REQUESTS_TOTAL, plane) {
            assert_eq!(
                keys_of(line),
                llm_keys,
                "plane=\"{plane}\" invented a differently-shaped series: {line}"
            );
        }
    }
}
