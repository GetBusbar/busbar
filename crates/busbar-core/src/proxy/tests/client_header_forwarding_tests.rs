// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T4 HEADER FIDELITY — the client-header FORWARDING golden.
//!
//! busbar rebuilds the egress header map fresh (lane creds + CT/UA/Accept) and historically DROPPED
//! every client-supplied request header, silently discarding the caller's GA/beta/version selectors
//! (`anthropic-beta`, `OpenAI-Beta`, `anthropic-version`). The forwarding seam
//! (`proxy::egress::{collect,apply}_forwarded_client_headers` + the `FORWARDED_CLIENT_HEADERS`
//! allowlist) restores that fidelity under three invariants this file pins:
//!
//!   1. FORWARD — an allowlisted header the caller actually sent REACHES the matching-dialect upstream
//!      (and, for `anthropic-version`, the caller's explicit value OVERRIDES busbar's pinned default).
//!   2. NO CROSS-DIALECT LEAK — a beta header meant for one dialect is NOT forwarded when the request
//!      is routed to a DIFFERENT dialect's lane.
//!   3. OPT-IN — a request that sends NO allowlisted header leaves the egress map untouched (the
//!      money-path oracles rely on this to stay byte-identical).
//!
//! Each test drives a real request through `forward_with_pool_keyed` (the production forward entry
//! that carries the collected allowlist) and inspects the exact header set the `MockServer` upstream
//! received via `MockServerState::get_last_request_header`.

use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;

/// A distinctive, clearly non-default `anthropic-version` so an assertion that the caller's value
/// reached the upstream cannot be satisfied by busbar's own pinned default.
const CLIENT_ANTHROPIC_VERSION: &str = "2020-01-01-clienttest";
const CLIENT_ANTHROPIC_BETA: &str = "prompt-caching-2024-07-31,message-batches-2024-09-24";
const CLIENT_OPENAI_BETA: &str = "assistants=v2";

fn anthropic_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100
    }))
    .unwrap()
    .into()
}

/// Build the collected forwarded-header set from a client HeaderMap exactly as an ingress handler
/// does — exercising the real `collect_forwarded_client_headers` allowlist filter (opt-in).
fn collect(pairs: &[(&'static str, &str)]) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    let mut hm = axum::http::HeaderMap::new();
    for (name, value) in pairs {
        hm.insert(
            axum::http::HeaderName::from_static(name),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
    }
    crate::proxy::collect_forwarded_client_headers(&hm)
}

async fn drive(
    app: &Arc<crate::state::App>,
    ingress_protocol: &'static str,
    client_fwd: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
) {
    let resp = crate::proxy::forward_with_pool_keyed(
        app,
        vec![crate::state::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        anthropic_body(),
        None,
        None,
        "p",
        None,
        ingress_protocol,
        crate::handlers::CHAT,
        None,
        client_fwd,
    )
    .await;
    // The request reached the upstream (headers recorded) regardless of the response shape; drain it.
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
}

/// FORWARD: a client `anthropic-beta` + `anthropic-version` on an Anthropic-ingress request routed to
/// an Anthropic lane REACHES the upstream verbatim, and the caller's version OVERRIDES busbar's pinned
/// default.
#[tokio::test]
async fn client_anthropic_beta_reaches_matching_anthropic_upstream() {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();

    drive(
        &app,
        "anthropic",
        collect(&[
            ("anthropic-beta", CLIENT_ANTHROPIC_BETA),
            ("anthropic-version", CLIENT_ANTHROPIC_VERSION),
        ]),
    )
    .await;

    assert_eq!(
        state.get_last_request_header("anthropic-beta").as_deref(),
        Some(CLIENT_ANTHROPIC_BETA),
        "the client anthropic-beta must reach the matching Anthropic upstream verbatim"
    );
    assert_eq!(
        state.get_last_request_header("anthropic-version").as_deref(),
        Some(CLIENT_ANTHROPIC_VERSION),
        "the caller's explicit anthropic-version must OVERRIDE busbar's pinned default"
    );
    server.shutdown().await;
}

/// FORWARD (OpenAI dialect): a client `OpenAI-Beta` on an OpenAI-ingress request routed to an OpenAI
/// lane reaches the upstream.
#[tokio::test]
async fn client_openai_beta_reaches_matching_openai_upstream() {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "chatcmpl-x",
            "object": "chat.completion",
            "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();

    drive(&app, "openai", collect(&[("openai-beta", CLIENT_OPENAI_BETA)])).await;

    assert_eq!(
        state.get_last_request_header("openai-beta").as_deref(),
        Some(CLIENT_OPENAI_BETA),
        "the client OpenAI-Beta must reach the matching OpenAI upstream"
    );
    server.shutdown().await;
}

/// NO CROSS-DIALECT LEAK: a client `anthropic-beta` on an Anthropic-ingress request that is routed to
/// an OpenAI lane (cross-protocol hop) must NOT ride to the OpenAI upstream — `anthropic-beta` is
/// allowlisted for the `anthropic` dialect only.
#[tokio::test]
async fn client_anthropic_beta_does_not_leak_to_openai_upstream() {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "chatcmpl-x",
            "object": "chat.completion",
            "created": 1,
            "model": "glm",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    // Lane speaks OpenAI; ingress is Anthropic → the anthropic-beta the client sent is meant for the
    // Anthropic dialect and must be dropped at this OpenAI egress.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("test-model", crate::proto::PROTO_OPENAI, &server.base_url())
                .provider("zai"),
        )
        .pool("p", &[(0, 1)])
        .build();

    drive(
        &app,
        "anthropic",
        collect(&[("anthropic-beta", CLIENT_ANTHROPIC_BETA)]),
    )
    .await;

    assert_eq!(
        state.get_last_request_header("anthropic-beta"),
        None,
        "an anthropic-beta must NOT leak cross-dialect to an OpenAI upstream"
    );
    server.shutdown().await;
}

/// OPT-IN: a request that sends NO allowlisted header forwards nothing — the upstream sees no
/// `anthropic-beta`, and `anthropic-version` remains busbar's own pinned default (NOT the client
/// test sentinel). This is the invariant that keeps the money-path oracles byte-identical.
#[tokio::test]
async fn no_client_beta_leaves_egress_unchanged() {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();

    // No allowlisted header collected → nothing forwarded.
    drive(&app, "anthropic", collect(&[])).await;

    assert_eq!(
        state.get_last_request_header("anthropic-beta"),
        None,
        "no anthropic-beta is forwarded when the client sent none (opt-in)"
    );
    let version = state.get_last_request_header("anthropic-version");
    assert!(
        version.is_some(),
        "busbar still sends its own pinned anthropic-version"
    );
    assert_ne!(
        version.as_deref(),
        Some(CLIENT_ANTHROPIC_VERSION),
        "with no client version sent, busbar's default stands — not the client sentinel"
    );
    server.shutdown().await;
}
