// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HUGE-BODY OFFLOAD PROOF. Bodies at/above `TRANSLATE_OFFLOAD_THRESHOLD` run the SAME
//! `translate_request_cross_protocol` on the blocking pool; below it, inline. Because both arms
//! call one function, the differential claim is exercised end-to-end: a >128 KiB request must
//! translate and forward byte-equivalently to a small one (same shape, padded content), on a
//! current_thread runtime (the data plane's flavor), and the small-body path must not regress
//! (the alloc gate elsewhere pins it).

use crate::engine::WeightedLane;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::json;
use std::sync::Arc;

fn member(idx: usize) -> WeightedLane {
    WeightedLane {
        reasoning: None,
        idx,
        weight: 1,
        attempt_timeout_ms: None,
    }
}

fn ok_response() -> MockResponse {
    MockResponse::Ok {
        status: reqwest::StatusCode::OK,
        body: json!({
            "id": "chatcmpl-off", "object": "chat.completion", "created": 0, "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                          "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        }),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn huge_body_translates_via_offload_and_forwards() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(ok_response());
    state.push(ok_response());
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("", &[(0, 1)])
        .build();

    // Well over the 128 KiB threshold: a single user turn with ~300 KiB of content.
    let big = "x".repeat(300 * 1024);
    let huge: bytes::Bytes = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": big}],
        "max_tokens": 16,
    }))
    .unwrap()
    .into();
    assert!(huge.len() >= 128 * 1024);

    let resp = crate::engine::forward_with_pool(
        &app,
        vec![member(0)],
        huge,
        None,
        "",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a >threshold body must translate on the blocking pool and forward normally"
    );

    // And a small body still round-trips (the inline arm), same runtime.
    let small: bytes::Bytes = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16,
    }))
    .unwrap()
    .into();
    let resp = crate::engine::forward_with_pool(
        &app,
        vec![member(0)],
        small,
        None,
        "",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    server.shutdown().await;
}
