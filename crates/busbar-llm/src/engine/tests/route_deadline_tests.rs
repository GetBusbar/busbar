//! The two ways a request leaves the failover walk without an attempt, and the exact shape each
//! one has: the walk deadline checked BEFORE every attempt answers 503 with the shared
//! request-timeout detail, while a pick that finds no usable lane answers through the pool's
//! exhaustion terminal (503, the overloaded kind, a `Retry-After` header).
use super::{forward_with_pool, DETAIL_REQUEST_TIMEOUT, KIND_OVERLOADED};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use std::sync::Arc;

fn one_lane() -> Vec<crate::engine::WeightedLane> {
    vec![crate::engine::WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }]
}

fn chat_body() -> bytes::Bytes {
    serde_json::to_vec(
        &serde_json::json!({"model": "p", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .unwrap()
    .into()
}

/// An OpenAI-shaped error body: (status, kind, message).
async fn openai_error(resp: axum::response::Response) -> (u16, String, String) {
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("json error body: {e}: {}", String::from_utf8_lossy(&bytes)));
    (
        status,
        v["error"]["type"].as_str().unwrap_or_default().to_string(),
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// The OpenAI-native spelling of busbar's own overloaded 503 kind, read off the ingress error
/// writer itself so the test pins "the same kind as every other busbar 503" and no vendor string.
async fn overloaded_kind_on_openai() -> String {
    let resp = super::ingress_error(
        "openai",
        http::StatusCode::SERVICE_UNAVAILABLE,
        KIND_OVERLOADED,
        "x",
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["error"]["type"].as_str().unwrap_or_default().to_string()
}

/// A pool whose failover budget is already spent when the walk starts (a zero-second deadline)
/// answers 503 with the shared request-timeout detail before any attempt is made: the live lane
/// is never contacted.
#[tokio::test]
async fn route_deadline_503_carries_detail_request_timeout() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        // The pool's own failover budget: zero seconds, so the pre-attempt deadline check fires
        // on the very first pass of the walk.
        .pool_failover(
            "p",
            serde_yaml::from_str("timeout_secs: 0\nmax_hops: 1").unwrap(),
        )
        .build();
    let (_host, _rt) = crate::engine::test_host_rt(&app);

    let resp = forward_with_pool(
        &app,
        one_lane(),
        chat_body(),
        None,
        "p",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    let (status, kind, message) = openai_error(resp).await;
    assert_eq!(status, 503, "an expired walk deadline is a 503");
    assert_eq!(
        message, DETAIL_REQUEST_TIMEOUT,
        "the pre-attempt deadline check carries the shared request-timeout detail"
    );
    assert_eq!(
        kind,
        overloaded_kind_on_openai().await,
        "the deadline 503 is the overloaded kind"
    );
    assert!(
        state.get_last_request_path().is_none(),
        "no attempt may be made once the deadline has passed"
    );
    server.shutdown().await;
}

/// A pool whose only member is administratively down has no usable lane: the pick returns
/// nothing and the request lands on the pool's exhaustion terminal — a 503 of the overloaded
/// kind carrying a `Retry-After` header, not the deadline detail.
#[tokio::test]
async fn pick_among_none_lands_on_on_exhausted_with_overloaded_and_retry_after() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: reqwest::StatusCode::OK,
        body: serde_json::json!({"choices": []}),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("m0", crate::proto_codec::PROTO_OPENAI, &server.base_url())
                .dead("administratively down for test"),
        )
        .pool("p", &[(0, 1)])
        .build();
    let (_host, _rt) = crate::engine::test_host_rt(&app);

    let resp = forward_with_pool(
        &app,
        one_lane(),
        chat_body(),
        None,
        "p",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let (status, kind, message) = openai_error(resp).await;
    assert_eq!(
        status, 503,
        "no usable lane is a 503 through the exhaustion terminal"
    );
    assert_eq!(kind, overloaded_kind_on_openai().await);
    assert!(
        retry_after.is_some_and(|s| s >= 1),
        "the exhaustion terminal advertises a whole-second Retry-After; got {retry_after:?}"
    );
    assert_ne!(
        message, DETAIL_REQUEST_TIMEOUT,
        "the exhaustion terminal is not the deadline 503; its detail is the overloaded one"
    );
    assert!(
        state.get_last_request_path().is_none(),
        "a down member is never contacted"
    );
    server.shutdown().await;
}
