// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PROTOCOL RESPONSE MODEL FIDELITY — the engine/proxy-level proof of the model-fill seam.
//!
//! On a cross-protocol hop where the UPSTREAM 2xx body omits the serving model (a Gemini
//! `generateContent` response with no `modelVersion`), the egress reader produces `resp.model =
//! None`. Busbar nonetheless KNOWS the lane it routed to, so the response-translation seam
//! (`TranslateCodec::translate_response`, via `IrHandle::fill_response_model_if_absent`) stamps the
//! routed lane wire model BEFORE the ingress writer runs. The client therefore always receives the
//! REAL serving model — never omitted, never empty, never a hardcoded default.
//!
//! These are ENGINE-level (they drive `forward_with_pool` through a real mock upstream), NOT
//! codec-level: the codec golden parity tests deliberately drive read→write directly, bypass the
//! engine, and so still see `model = None → omitted`. The fill is an engine/proxy concern and is
//! proven here.
//!
//! MUTATION: drop the `ir.fill_response_model_if_absent(lane_model)` call in
//! `TranslateCodec::translate_response` (or make the override in `ChatRespHandle` a no-op) and the
//! first test goes red — the anthropic writer's omit-when-None defense leaves `model` absent, so the
//! `model == <lane model>` assertion fails. The second test guards the other direction: it stays
//! green ONLY because the fill is fill-ONLY (it must never overwrite an upstream-provided model).

use crate::state::WeightedLane;
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

/// An ANTHROPIC-dialect client request (the ingress). Routed to a Gemini lane, so the hop is
/// cross-protocol on both legs.
fn anthropic_chat_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "claude-ingress-alias",
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 16,
    }))
    .unwrap()
    .into()
}

/// A native Gemini `generateContent` 2xx body. `with_model` toggles whether the upstream reports its
/// serving model as `modelVersion`; when absent, the egress reader yields `resp.model = None`.
fn gemini_response(with_model: Option<&str>) -> serde_json::Value {
    let mut body = json!({
        "candidates": [{
            "content": { "role": "model", "parts": [{ "text": "hello" }] },
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 1,
            "candidatesTokenCount": 1,
            "totalTokenCount": 2
        }
    });
    if let Some(m) = with_model {
        body["modelVersion"] = json!(m);
    }
    body
}

/// The routed lane's wire model — deliberately distinct from the ingress request's `model` alias, so
/// an assertion on it cannot be satisfied by an echo of the client's own request.
const LANE_MODEL: &str = "gemini-2.5-pro-routed";

/// THE CORE CLAIM: upstream omitted the model, so the client's (cross-protocol) response reports the
/// REAL lane model the proxy routed to — not omitted, not empty, not a default.
#[tokio::test]
async fn cross_protocol_response_reports_routed_lane_model_when_upstream_omits_it() {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        // No `modelVersion` → the Gemini reader surfaces `resp.model = None`.
        body: gemini_response(None),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            LANE_MODEL,
            crate::proto::PROTO_GEMINI,
            &server.base_url(),
        ))
        .pool("", &[(0, 1)])
        .build();

    let response = crate::proxy::forward_with_pool(
        &app,
        vec![member(0)],
        anthropic_chat_body(),
        None,
        "",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "the gemini lane serves 200"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a buffered body");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("anthropic JSON body");

    assert_eq!(
        v.get("model").and_then(|m| m.as_str()),
        Some(LANE_MODEL),
        "the client's cross-protocol response must report the ROUTED LANE model when the upstream \
         body carried none; got {v}"
    );
    // Belt-and-braces: it is neither omitted nor an empty placeholder.
    assert!(v.get("model").is_some(), "model must not be omitted");
    assert_ne!(
        v.get("model").and_then(|m| m.as_str()),
        Some(""),
        "model must never be an empty string"
    );

    server.shutdown().await;
}

/// FILL-ONLY GUARD: when the upstream DID report its serving model, that value is preserved verbatim
/// — the lane model must NEVER overwrite an upstream-provided model. This is the invariant that keeps
/// the fill lossless rather than a lie.
#[tokio::test]
async fn cross_protocol_response_never_overrides_an_upstream_provided_model() {
    const UPSTREAM_MODEL: &str = "gemini-2.5-flash-actual";
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: gemini_response(Some(UPSTREAM_MODEL)),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            LANE_MODEL,
            crate::proto::PROTO_GEMINI,
            &server.base_url(),
        ))
        .pool("", &[(0, 1)])
        .build();

    let response = crate::proxy::forward_with_pool(
        &app,
        vec![member(0)],
        anthropic_chat_body(),
        None,
        "",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;
    assert_eq!(response.status().as_u16(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a buffered body");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("anthropic JSON body");

    assert_eq!(
        v.get("model").and_then(|m| m.as_str()),
        Some(UPSTREAM_MODEL),
        "the upstream-reported model must be preserved verbatim; the lane model must NOT override \
         it; got {v}"
    );

    server.shutdown().await;
}
