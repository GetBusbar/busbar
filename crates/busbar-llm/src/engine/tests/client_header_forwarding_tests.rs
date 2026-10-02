// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR IS INVISIBLE TO UPSTREAMS (OWNER HARD RULE 2026-10-02) — the client-header forwarding
//! golden.
//!
//! On a same-dialect route every client header and body field passes through unchanged, except what
//! busbar governs: the dialects' credential headers and tenant selectors (declared as data in
//! the plane's dialect table, replaced from busbar's config), and the per-connection mechanics
//! (hop-by-hop, `host`, `content-length`), which the upstream connection re-derives. A translated
//! route translates what maps and drops the rest; no header maps. Each test drives a real request
//! through `forward_with_pool_keyed` and inspects what the `MockServer` upstream received.

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
/// An arbitrary header no table anywhere names.
const TRACE: (&str, &str) = ("x-client-trace", "abc");
/// The lane's own upstream key, the one credential the upstream may see.
const LANE_KEY: &str = "sk-lane-upstream";

fn anthropic_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100
    }))
    .unwrap()
    .into()
}

fn openai_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "hi"}],
        "x_vendor_flag": true
    }))
    .unwrap()
    .into()
}

fn openai_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}
    })
}

/// The collected set, exactly as the native ingress builds it: the neutral collector asked with the
/// plane's governed-name data.
fn collect(pairs: &[(&'static str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
    let mut hm = HeaderMap::new();
    for (name, value) in pairs {
        hm.append(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    busbar_kernel::proxy::collect_client_headers(&hm, crate::engine::governed)
}

/// One upstream of `protocol` answering `reply`, the lane keyed with [`LANE_KEY`].
async fn upstream(
    protocol: &'static str,
    reply: serde_json::Value,
) -> (
    Arc<MockServerState>,
    MockServer,
    Arc<busbar_kernel::state::App>,
) {
    upstream_of(protocol, reply, None).await
}

/// [`upstream`], the lane's provider named when `provider` is.
async fn upstream_of(
    protocol: &'static str,
    reply: serde_json::Value,
    provider: Option<&str>,
) -> (
    Arc<MockServerState>,
    MockServer,
    Arc<busbar_kernel::state::App>,
) {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: reply,
    });
    let server = MockServer::new(state.clone()).await;
    let mut lane = LaneSpec::new("test-model", protocol, &server.base_url()).api_key(LANE_KEY);
    if let Some(p) = provider {
        lane = lane.provider(p);
    }
    let app = TestApp::new().lane(lane).pool("p", &[(0, 1)]).build();
    (state, server, app)
}

async fn drive<A: busbar_kernel::test_support::BuiltAppSeam + ?Sized>(
    app: &Arc<A>,
    ingress_protocol: &'static str,
    body: bytes::Bytes,
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
        body,
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

/// SAME DIALECT (anthropic): the caller's `anthropic-beta`, `anthropic-version` and an arbitrary
/// header reach the upstream verbatim; the caller's version OVERRIDES busbar's pinned default.
#[tokio::test]
async fn same_dialect_anthropic_forwards_every_client_header() {
    let (state, server, app) = upstream(
        crate::proto_codec::PROTO_ANTHROPIC,
        json!({ "content": [] }),
    )
    .await;
    drive(
        &app,
        "anthropic",
        anthropic_body(),
        collect(&[
            ("anthropic-beta", CLIENT_ANTHROPIC_BETA),
            ("anthropic-version", CLIENT_ANTHROPIC_VERSION),
            TRACE,
        ]),
    )
    .await;
    let seen = |name: &str| state.get_last_request_header(name);
    assert_eq!(
        seen("anthropic-beta").as_deref(),
        Some(CLIENT_ANTHROPIC_BETA)
    );
    assert_eq!(
        seen("anthropic-version").as_deref(),
        Some(CLIENT_ANTHROPIC_VERSION)
    );
    assert_eq!(
        seen(TRACE.0).as_deref(),
        Some(TRACE.1),
        "an arbitrary header passes"
    );
    server.shutdown().await;
}

/// SAME DIALECT (openai): `OpenAI-Beta`, an arbitrary header and the caller's own `user-agent`
/// reach the upstream, and an UNKNOWN body field rides through untouched.
#[tokio::test]
async fn same_dialect_openai_forwards_headers_and_unknown_body_fields() {
    let (state, server, app) = upstream(crate::proto_codec::PROTO_OPENAI, openai_reply()).await;
    drive(
        &app,
        "openai",
        openai_body(),
        collect(&[
            ("openai-beta", CLIENT_OPENAI_BETA),
            TRACE,
            ("user-agent", "OpenAI/Python 9.9.9"),
        ]),
    )
    .await;
    let seen = |name: &str| state.get_last_request_header(name);
    assert_eq!(seen("openai-beta").as_deref(), Some(CLIENT_OPENAI_BETA));
    assert_eq!(seen(TRACE.0).as_deref(), Some(TRACE.1));
    assert_eq!(
        seen("user-agent").as_deref(),
        Some("OpenAI/Python 9.9.9"),
        "the caller's user-agent wins over busbar's native default"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert_eq!(
        body["x_vendor_flag"],
        json!(true),
        "an unknown body field passes"
    );
    server.shutdown().await;
}

/// GOVERNED (credential): the caller's busbar credential, in any carrier, never reaches the
/// upstream; the upstream sees the lane's own key.
#[tokio::test]
async fn caller_credential_is_replaced_by_the_lane_credential() {
    let (state, server, app) = upstream(crate::proto_codec::PROTO_OPENAI, openai_reply()).await;
    drive(
        &app,
        "openai",
        openai_body(),
        collect(&[
            ("authorization", "Bearer busbar-caller-key"),
            ("x-api-key", "busbar-caller-key"),
            ("x-goog-api-key", "busbar-caller-key"),
            ("api-key", "busbar-caller-key"),
        ]),
    )
    .await;
    let seen = |name: &str| state.get_last_request_header(name);
    assert_eq!(seen("authorization"), Some(format!("Bearer {LANE_KEY}")));
    for carrier in ["x-api-key", "x-goog-api-key", "api-key"] {
        assert_eq!(
            seen(carrier),
            None,
            "{carrier}: the caller's key never goes upstream"
        );
    }
    server.shutdown().await;
}

/// GOVERNED (tenant selectors): the caller's `OpenAI-Organization` / `OpenAI-Project` are ignored;
/// what goes upstream comes from busbar's config, which sets none.
#[tokio::test]
async fn caller_tenant_selectors_are_ignored() {
    let (state, server, app) = upstream(crate::proto_codec::PROTO_OPENAI, openai_reply()).await;
    drive(
        &app,
        "openai",
        openai_body(),
        collect(&[
            ("openai-organization", "org-caller"),
            ("openai-project", "proj-caller"),
            TRACE,
        ]),
    )
    .await;
    let seen = |name: &str| state.get_last_request_header(name);
    assert_eq!(seen("openai-organization"), None);
    assert_eq!(seen("openai-project"), None);
    assert_eq!(seen(TRACE.0).as_deref(), Some(TRACE.1));
    server.shutdown().await;
}

/// MECHANICS: the caller's hop-by-hop fields (and a field its `connection` nominates), `host` and
/// `content-length` never reach the upstream; the upstream connection derives its own.
#[tokio::test]
async fn hop_by_hop_host_and_length_are_re_derived() {
    let (state, server, app) = upstream(crate::proto_codec::PROTO_OPENAI, openai_reply()).await;
    let body = openai_body();
    drive(
        &app,
        "openai",
        body.clone(),
        collect(&[
            ("connection", "keep-alive, x-nominated"),
            ("x-nominated", "1"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("proxy-authorization", "Basic Zm9v"),
            ("host", "client.example"),
            ("content-length", "9999"),
            TRACE,
        ]),
    )
    .await;
    let seen = |name: &str| state.get_last_request_header(name);
    for gone in [
        "x-nominated",
        "keep-alive",
        "te",
        "upgrade",
        "proxy-authorization",
    ] {
        assert_eq!(seen(gone), None, "{gone} is per-connection");
    }
    assert_ne!(seen("host").as_deref(), Some("client.example"));
    assert_ne!(seen("content-length").as_deref(), Some("9999"));
    assert_eq!(seen(TRACE.0).as_deref(), Some(TRACE.1));
    server.shutdown().await;
}

/// TRANSLATED: an anthropic request routed to an openai lane forwards no client header (no header
/// maps between the two dialects) and drops the body member the far dialect cannot carry.
#[tokio::test]
async fn translated_route_drops_what_does_not_map() {
    let (state, server, app) = upstream_of(
        crate::proto_codec::PROTO_OPENAI,
        openai_reply(),
        Some("zai"),
    )
    .await;
    let body: bytes::Bytes = serde_json::to_vec(&json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100,
        "x_vendor_flag": true
    }))
    .unwrap()
    .into();
    drive(
        &app,
        "anthropic",
        body,
        collect(&[("anthropic-beta", CLIENT_ANTHROPIC_BETA), TRACE]),
    )
    .await;
    let seen = |name: &str| state.get_last_request_header(name);
    assert_eq!(seen("anthropic-beta"), None, "no cross-dialect header leak");
    assert_eq!(
        seen(TRACE.0),
        None,
        "a translated route forwards no client header"
    );
    assert_eq!(
        seen("user-agent").as_deref(),
        Some(crate::engine::egress_user_agent("openai")),
        "busbar writes the far dialect as its native client"
    );
    let sent: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
    assert!(
        sent.get("x_vendor_flag").is_none(),
        "an untranslatable member is dropped"
    );
    server.shutdown().await;
}

/// A request that sends no client header leaves busbar's own egress headers standing, and a
/// same-dialect hop fakes no user-agent.
#[tokio::test]
async fn no_client_header_leaves_egress_unchanged() {
    let (state, server, app) = upstream(
        crate::proto_codec::PROTO_ANTHROPIC,
        json!({ "content": [] }),
    )
    .await;
    drive(&app, "anthropic", anthropic_body(), collect(&[])).await;
    assert_eq!(state.get_last_request_header("anthropic-beta"), None);
    assert_eq!(
        state
            .get_last_request_header("anthropic-version")
            .as_deref(),
        Some("2023-06-01"),
        "busbar's own pinned anthropic-version stands"
    );
    assert_eq!(state.get_last_request_header("user-agent"), None);
    server.shutdown().await;
}

/// DECLARED EGRESS HEADERS (#83a S2-a, SD-3b): the Anthropic dialect DECLARES its credential scheme
/// and its version header and carries no builder; the kernel presents both. An Anthropic lane's
/// upstream request carries exactly the declared headers — one credential in the header its family
/// names (never both) and the pinned `anthropic-version` — the bytes its builder used to write.
#[tokio::test]
async fn anthropic_egress_carries_exactly_the_declared_headers() {
    crate::testkit::install_test_seams();
    for (key, x_api_key, authorization) in [
        ("sk-ant-api03-e2e", Some("sk-ant-api03-e2e"), None),
        ("  sk-ant-api03-e2e", Some("sk-ant-api03-e2e"), None),
        ("sk-ant-oat01-e2e", None, Some("Bearer sk-ant-oat01-e2e")),
        ("opaque-lane-key", Some("opaque-lane-key"), None),
    ] {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": [] }),
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto_codec::PROTO_ANTHROPIC,
                    &server.base_url(),
                )
                .api_key(key),
            )
            .pool("p", &[(0, 1)])
            .build();
        drive(&app, "anthropic", anthropic_body(), collect(&[])).await;
        let seen = |name: &str| state.get_last_request_header(name);
        assert_eq!(seen("x-api-key").as_deref(), x_api_key, "{key:?}");
        assert_eq!(seen("authorization").as_deref(), authorization, "{key:?}");
        assert_eq!(
            seen("anthropic-version").as_deref(),
            Some("2023-06-01"),
            "{key:?}: the declared version header, pinned as a literal"
        );
        server.shutdown().await;
    }
}

// ── NEUTRAL-MECHANISM DIRECT TESTS ────────────────────────────────────────────────────────────────
// `busbar_kernel::proxy::{collect,apply}_client_headers` with made-up names: the mechanism forwards
// everything but the mechanics and what the caller says it governs, and names no dialect header.

/// `collect_client_headers` keeps every header, in order and with multiplicity, except the
/// per-connection mechanics and the governed names.
#[test]
fn neutral_collect_keeps_all_but_mechanics_and_governed() {
    let mut hm = HeaderMap::new();
    for (n, v) in [
        ("x-made-up-alpha", "a1"),
        ("x-made-up-alpha", "a2"),
        ("x-made-up-governed", "g"),
        ("x-busbar-made-up", "busbar's own"),
        ("connection", "x-made-up-nominated"),
        ("x-made-up-nominated", "n"),
        ("transfer-encoding", "chunked"),
        ("host", "h"),
        ("content-length", "1"),
    ] {
        hm.append(HeaderName::from_static(n), HeaderValue::from_static(v));
    }
    let got = busbar_kernel::proxy::collect_client_headers(&hm, |n| n == "x-made-up-governed");
    let names: Vec<(&str, &str)> = got
        .iter()
        .map(|(n, v)| (n.as_str(), v.to_str().unwrap()))
        .collect();
    assert_eq!(
        names,
        vec![("x-made-up-alpha", "a1"), ("x-made-up-alpha", "a2")]
    );
}

/// `apply_client_headers` REPLACES a busbar default with the caller's first value and APPENDS the
/// rest.
#[test]
fn neutral_apply_replaces_then_appends() {
    let name = HeaderName::from_static("x-made-up-multi");
    let collected = vec![
        (name.clone(), HeaderValue::from_static("first")),
        (name.clone(), HeaderValue::from_static("second")),
    ];
    let mut egress = HeaderMap::new();
    egress.insert(name.clone(), HeaderValue::from_static("busbar-default"));
    busbar_kernel::proxy::apply_client_headers(&mut egress, &collected);
    let values: Vec<_> = egress
        .get_all(&name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(values, vec!["first", "second"]);
}
