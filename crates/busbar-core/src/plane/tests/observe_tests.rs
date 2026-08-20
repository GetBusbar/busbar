// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE INGRESS BOUNDARY, at the two edges where it could do damage.
//!
//! Emitting from a layer instead of from each handler buys coverage of every `return` — and buys
//! one new way to be wrong that a handler-level emit could not have: counting a request TWICE,
//! once at the door and once in `ingress::finish_inner`. On the model plane, which already emitted,
//! that would silently double every number on every existing dashboard. So the residual plane's
//! exactness is asserted here rather than assumed from reading [`super::observe`].

use crate::test_support::{metric_sum, LaneSpec, TestApp};

/// A pool name used by NOTHING else in this binary. The test process shares one global recorder and
/// runs tests in parallel, so an exact-delta assertion has to be made on a label set no other test
/// can touch; `"unresolved"` would not be one.
const POOL: &str = "observe-residual-exactness-pool";

/// A MODEL-plane request is counted EXACTLY ONCE with the planes mounted alongside it.
///
/// The residual plane is the one the boundary must not touch: it labels its own requests from
/// `ingress::finish_inner`, which also owns the non-2xx flat-fee refund and therefore cannot be
/// replaced by the layer. If the layer ever stops asking the mount table and starts counting
/// everything, this goes to 2 and says so.
#[tokio::test]
async fn a_model_plane_request_is_counted_exactly_once() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "observe-residual-model",
            crate::proto::Protocol::openai(),
            "http://127.0.0.1:1",
        ))
        .pool(POOL, &[(0, 1)])
        .mcp(&crate::mcp::McpCfg {
            canonical_uri: "https://gateway.example.com/mcp".to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // The model plane's `busbar_requests_total` carries NO `plane` label (v1.5.4-identical); this
    // pool name is unique to this test, so it alone pins the delta.
    let labels = [("pool", POOL)];
    let before = metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    // The upstream is a closed port, so this fails to forward — which is fine and deliberate. What
    // is under test is HOW MANY TIMES the request is counted, not what it returned.
    let _ = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": POOL,
            "messages": [{ "role": "user", "content": "hi" }],
        }))
        .send()
        .await
        .unwrap();
    let after = metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    server.abort();

    assert_eq!(
        (after - before).round() as u64,
        1,
        "one model-plane request must produce ONE count, not one from `finish_inner` plus one from \
         the plane ingress boundary"
    );
}
