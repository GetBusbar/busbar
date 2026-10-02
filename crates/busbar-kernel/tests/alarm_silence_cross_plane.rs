// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE ALARM/DISPUTE SILENCE TEST, relocated here from `src/tests/alarm_silence_tests.rs`
//! (the "fix the 38" pass after the A6/HostCtx dev-dependency-cycle cleanup): it drives a real
//! request lifecycle (success, failed-upstream, `/healthz`, `/stats`) through `build_router`, which
//! only routes `/pa/v1/messages`/`/pb/v1/messages` through the REAL `busbar_llm` plane's
//! `build_runtime`/`viewer` — same reason as `endpoints_cross_plane.rs` (see its header). What this
//! test asserts (no tracing event or metric name mentions "alarm"/"dispute" on a 1.5.5-shaped
//! deployment) is core's own structured-field/metric-set behaviour, not anything about the LLM
//! dialect — the real plane is present only so the requests have somewhere to route.
//!
//! `metric_name_reads_every_exposition_line_shape` (a pure-function test, no `TestApp`/router) names
//! no plane and stays in `src/tests/alarm_silence_tests.rs`.

mod linked;

use axum::body::Body;
use axum::http::Request;
use busbar_kernel::test_support::warn_capture::WarnCapture;
use busbar_kernel::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use std::sync::Arc;
use tower::ServiceExt as _;

fn register_planes() {
    linked::install();
}

/// The words an alarm or a disputes-report entry would carry, matched case-insensitively.
const MARKERS: &[&str] = &["alarm", "dispute"];

fn mentions_a_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// The metric name of one exposition line: the token before `{` or the first space on a sample
/// line, or the second token of a `# HELP` / `# TYPE` line.
fn metric_name(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("# ") {
        let mut it = rest.split_whitespace();
        let _kind = it.next()?;
        return it.next();
    }
    let end = line.find(['{', ' ']).unwrap_or(line.len());
    let name = &line[..end];
    (!name.is_empty()).then_some(name)
}

fn anthropic_ok() -> MockResponse {
    MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
            "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    }
}

fn post(path: &str, pool: &str) -> Request<Body> {
    let body = serde_json::json!({
        "model": pool,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8
    })
    .to_string();
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

/// Drain a response body so the request's own "finished" bookkeeping runs before the next step.
async fn drain(res: axum::response::Response) -> (u16, Vec<u8>) {
    let status = res.status().as_u16();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (status, bytes.to_vec())
}

#[test]
fn a_1_5_5_request_lifecycle_emits_no_alarm_or_dispute_event_or_metric() {
    register_planes();
    busbar_kernel::metrics::init();
    let cap = WarnCapture::capturing_debug();
    let subscriber = {
        use tracing_subscriber::layer::SubscriberExt as _;
        tracing_subscriber::registry().with(cap.clone())
    };

    let mut statuses: Vec<(&str, u16)> = Vec::new();
    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        rt.block_on(async {
            let state = Arc::new(MockServerState::new());
            state.push(anthropic_ok());
            let server = MockServer::new(state).await;

            // A 1.5.5-shaped app: two pools over the Anthropic wire, open data-plane auth, no
            // governance, no plane claimed. `pb`'s lane points at a closed port so its request
            // fails upstream — the path a stall or lane alarm would ride.
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "m-ok",
                        busbar_kernel::proto::PROTO_ANTHROPIC,
                        &server.base_url(),
                    )
                    .api_key("up"),
                )
                .lane(
                    LaneSpec::new(
                        "m-dead",
                        busbar_kernel::proto::PROTO_ANTHROPIC,
                        "http://127.0.0.1:1",
                    )
                    .api_key("up"),
                )
                .pool("pa", &[(0, 1)])
                .pool("pb", &[(1, 1)])
                .build();
            let router = busbar_kernel::build_router(app);

            let (ok, _) = drain(
                router
                    .clone()
                    .oneshot(post("/pa/v1/messages", "pa"))
                    .await
                    .unwrap(),
            )
            .await;
            statuses.push(("ok request", ok));
            let (failed, _) = drain(
                router
                    .clone()
                    .oneshot(post("/pb/v1/messages", "pb"))
                    .await
                    .unwrap(),
            )
            .await;
            statuses.push(("failed-upstream request", failed));
            let (healthz, _) = drain(router.clone().oneshot(get("/healthz")).await.unwrap()).await;
            statuses.push(("healthz", healthz));
            let (stats, _) = drain(router.clone().oneshot(get("/stats")).await.unwrap()).await;
            statuses.push(("stats", stats));

            server.shutdown().await;
        });
    });

    // The lifecycle really happened: the successful request reached the mock and came back 200,
    // the dead-lane request did NOT succeed, and the probe answered.
    let status_of = |what: &str| {
        statuses
            .iter()
            .find(|(w, _)| *w == what)
            .map(|(_, s)| *s)
            .unwrap()
    };
    assert_eq!(status_of("ok request"), 200, "statuses: {statuses:?}");
    assert_ne!(
        status_of("failed-upstream request"),
        200,
        "statuses: {statuses:?}"
    );
    assert_eq!(status_of("healthz"), 200, "statuses: {statuses:?}");

    // No event at DEBUG or above mentions an alarm or a dispute, in its message or in any field.
    let events = cap.messages();
    let hits: Vec<&String> = events.iter().filter(|m| mentions_a_marker(m)).collect();
    assert!(
        hits.is_empty(),
        "no tracing event may carry an alarm/dispute message or field on a 1.5.5-shaped \
         deployment; found:\n{}",
        hits.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );

    // No metric name carries either word.
    let exposition = busbar_kernel::metrics::render();
    let leaked: Vec<&str> = exposition
        .lines()
        .filter_map(metric_name)
        .filter(|n| mentions_a_marker(n))
        .collect();
    assert!(
        leaked.is_empty(),
        "no metric name may mention an alarm or a dispute on a 1.5.5-shaped deployment; found: \
         {leaked:?}"
    );
}
