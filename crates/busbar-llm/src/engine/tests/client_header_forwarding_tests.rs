// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CLIENT-HEADER FIDELITY — the client-header FORWARDING golden.
//!
//! busbar rebuilds the egress header map fresh (lane creds + CT/UA/Accept) and historically DROPPED
//! every client-supplied request header, silently discarding the caller's GA/beta/version selectors
//! (`anthropic-beta`, `OpenAI-Beta`, `anthropic-version`). The forwarding seam restores that fidelity
//! as a NEUTRAL mechanism plus a PLANE policy:
//!
//!   * NEUTRAL (`busbar_substrate::proxy::{collect,apply}_client_headers`) — forwards EXACTLY the set
//!     of header names it is handed, hard-coding NONE. Proven by `neutral_mechanism_*` below.
//!   * PLANE (`crate::engine::{FORWARDED_CLIENT_HEADERS, forwardable_client_header_names,
//!     client_header_names_for_egress}`) — the dialect-scoped allowlist that supplies those names. The
//!     dialect tokens live HERE in the LLM plane, never in the neutral crate.
//!
//! The end-to-end invariants this file pins (each drives a real request through
//! `forward_with_pool_keyed` — the production forward entry that carries the collected allowlist — and
//! inspects the exact header set the `MockServer` upstream received):
//!
//!   1. FORWARD — an allowlisted header the caller actually sent REACHES the matching-dialect upstream
//!      (and, for `anthropic-version`, the caller's explicit value OVERRIDES busbar's pinned default).
//!   2. NO CROSS-DIALECT LEAK — a beta header meant for one dialect is NOT forwarded when the request
//!      is routed to a DIFFERENT dialect's lane.
//!   3. OPT-IN — a request that sends NO allowlisted header leaves the egress map untouched.
//!   4. NON-ALLOWLISTED DROP — a client header that is NOT on the plane's allowlist is never captured,
//!      so it never reaches the upstream.

use crate::engine::forward_with_pool_keyed;
use crate::test_support::*;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
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

/// Build the collected forwarded-header set from a client HeaderMap exactly as the native ingress
/// handler does — through the NEUTRAL collector fed the PLANE's forwardable-name set (opt-in filter).
fn collect(pairs: &[(&'static str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
    let mut hm = HeaderMap::new();
    for (name, value) in pairs {
        hm.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    busbar_substrate::proxy::collect_client_headers(
        &hm,
        &crate::engine::forwardable_client_header_names(),
    )
}

async fn drive<A: busbar_substrate::testkit::BuiltAppSeam + ?Sized>(
    app: &Arc<A>,
    ingress_protocol: &'static str,
    client_fwd: Vec<(HeaderName, HeaderValue)>,
) {
    let resp = forward_with_pool_keyed(
        app,
        vec![crate::engine::WeightedLane {
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
        crate::test_support::CHAT,
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
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto_codec::PROTO_ANTHROPIC,
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
        state
            .get_last_request_header("anthropic-version")
            .as_deref(),
        Some(CLIENT_ANTHROPIC_VERSION),
        "the caller's explicit anthropic-version must OVERRIDE busbar's pinned default"
    );
    server.shutdown().await;
}

/// FORWARD (OpenAI dialect): a client `OpenAI-Beta` on an OpenAI-ingress request routed to an OpenAI
/// lane reaches the upstream.
#[tokio::test]
async fn client_openai_beta_reaches_matching_openai_upstream() {
    crate::testkit::install_test_seams();
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
            crate::proto_codec::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();

    drive(
        &app,
        "openai",
        collect(&[("openai-beta", CLIENT_OPENAI_BETA)]),
    )
    .await;

    assert_eq!(
        state.get_last_request_header("openai-beta").as_deref(),
        Some(CLIENT_OPENAI_BETA),
        "the client OpenAI-Beta must reach the matching OpenAI upstream"
    );
    server.shutdown().await;
}

/// NO CROSS-DIALECT LEAK: a client `anthropic-beta` on an Anthropic-ingress request that is routed to
/// an OpenAI lane (cross-protocol hop) must NOT ride to the OpenAI upstream — `anthropic-beta` is
/// allowlisted for the `anthropic` dialect only, so the egress allowlist for `openai` excludes it.
#[tokio::test]
async fn client_anthropic_beta_does_not_leak_to_openai_upstream() {
    crate::testkit::install_test_seams();
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
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
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
/// sentinel). This is the invariant that keeps the money-path oracles byte-identical.
#[tokio::test]
async fn no_client_beta_leaves_egress_unchanged() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto_codec::PROTO_ANTHROPIC,
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

/// NON-ALLOWLISTED DROP: a client sends BOTH an allowlisted `anthropic-beta` AND an arbitrary
/// `x-secret-header` that is NOT on the plane's allowlist. The allowlisted one reaches the upstream;
/// the non-allowlisted one is never even captured, so it never reaches the upstream.
#[tokio::test]
async fn non_allowlisted_client_header_is_not_forwarded() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();

    drive(
        &app,
        "anthropic",
        collect(&[
            ("anthropic-beta", CLIENT_ANTHROPIC_BETA),
            ("x-secret-header", "leak-me"),
        ]),
    )
    .await;

    assert_eq!(
        state.get_last_request_header("anthropic-beta").as_deref(),
        Some(CLIENT_ANTHROPIC_BETA),
        "the allowlisted anthropic-beta still reaches the upstream"
    );
    assert_eq!(
        state.get_last_request_header("x-secret-header"),
        None,
        "a client header that is NOT on the plane allowlist must never be forwarded"
    );
    server.shutdown().await;
}

// ── NEUTRAL-MECHANISM DIRECT TESTS ────────────────────────────────────────────────────────────────
// These bypass the plane policy entirely and drive `busbar_substrate::proxy::{collect,apply}` with
// ARBITRARY, made-up header names to prove the neutral mechanism forwards EXACTLY the set it is given
// and hard-codes nothing — the whole point of the redo.

/// `collect_client_headers` captures exactly the names it is handed — no more (a name not in the set
/// is ignored) and no less (every name in the set that the caller sent is captured, with multiplicity).
#[test]
fn neutral_collect_captures_exactly_the_given_names() {
    let mut hm = HeaderMap::new();
    hm.insert(
        HeaderName::from_static("x-made-up-alpha"),
        HeaderValue::from_static("a1"),
    );
    hm.append(
        HeaderName::from_static("x-made-up-alpha"),
        HeaderValue::from_static("a2"),
    );
    hm.insert(
        HeaderName::from_static("x-made-up-beta"),
        HeaderValue::from_static("b"),
    );
    hm.insert(
        HeaderName::from_static("x-not-requested"),
        HeaderValue::from_static("nope"),
    );

    // Ask for two arbitrary names the neutral crate has never heard of.
    let got = busbar_substrate::proxy::collect_client_headers(
        &hm,
        &["x-made-up-alpha", "x-made-up-beta"],
    );

    // alpha appears twice (multiplicity preserved), beta once, the un-requested name never.
    let alpha: Vec<_> = got
        .iter()
        .filter(|(n, _)| n.as_str() == "x-made-up-alpha")
        .map(|(_, v)| v.to_str().unwrap())
        .collect();
    assert_eq!(
        alpha,
        vec!["a1", "a2"],
        "multiplicity of a requested name is preserved"
    );
    assert!(
        got.iter()
            .any(|(n, v)| n.as_str() == "x-made-up-beta" && v == "b"),
        "a requested name the caller sent is captured"
    );
    assert!(
        got.iter().all(|(n, _)| n.as_str() != "x-not-requested"),
        "a name NOT in the requested set is never captured — the mechanism hard-codes nothing"
    );
}

/// `apply_client_headers` forwards exactly the names in the `allowed` set onto the egress map: an
/// arbitrary made-up name in `allowed` is forwarded; a collected name NOT in `allowed` is dropped; an
/// EMPTY `allowed` forwards nothing.
#[test]
fn neutral_apply_forwards_exactly_the_allowed_set() {
    let collected = vec![
        (
            HeaderName::from_static("x-made-up-allowed"),
            HeaderValue::from_static("yes"),
        ),
        (
            HeaderName::from_static("x-made-up-denied"),
            HeaderValue::from_static("no"),
        ),
    ];

    // Only the arbitrary allowed name rides through — the neutral crate never heard of either name.
    let mut egress = HeaderMap::new();
    busbar_substrate::proxy::apply_client_headers(&mut egress, &collected, &["x-made-up-allowed"]);
    assert_eq!(
        egress.get("x-made-up-allowed").map(|v| v.to_str().unwrap()),
        Some("yes"),
        "a name in the allowed set is forwarded, chosen purely by the caller-supplied data"
    );
    assert!(
        egress.get("x-made-up-denied").is_none(),
        "a collected name NOT in the allowed set is dropped"
    );

    // Empty allowlist ⇒ nothing forwarded (byte-identical egress).
    let mut egress_empty = HeaderMap::new();
    busbar_substrate::proxy::apply_client_headers(&mut egress_empty, &collected, &[]);
    assert!(
        egress_empty.is_empty(),
        "an empty allowlist forwards nothing — no hidden hard-coded names"
    );
}

/// `apply_client_headers` REPLACES a pre-existing egress default with the caller's first value, then
/// APPENDS subsequent same-name values (multiplicity), for any arbitrary name.
#[test]
fn neutral_apply_replaces_then_appends() {
    let name = HeaderName::from_static("x-made-up-multi");
    let collected = vec![
        (name.clone(), HeaderValue::from_static("first")),
        (name.clone(), HeaderValue::from_static("second")),
    ];
    let mut egress = HeaderMap::new();
    // A busbar default the caller's value must override.
    egress.insert(name.clone(), HeaderValue::from_static("busbar-default"));

    busbar_substrate::proxy::apply_client_headers(&mut egress, &collected, &["x-made-up-multi"]);

    let values: Vec<_> = egress
        .get_all(&name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(
        values,
        vec!["first", "second"],
        "the first caller value REPLACES the busbar default; the second is APPENDED"
    );
}
