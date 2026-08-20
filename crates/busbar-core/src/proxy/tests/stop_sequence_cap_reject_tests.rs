// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FAIL-CLOSED edge reject for a cross-protocol stop-sequence list over the egress dialect's
//! published cap (Cohere: 5, Gemini: 5, OpenAI: 4). Before this fix, `ProtocolWriter::write_request`
//! (via a now-deleted proto-layer helper) silently truncated the list to the cap and forwarded
//! the partial set upstream with only a `tracing::warn!` — a caller relying on their Nth+ stop
//! sequence to bound generation silently lost that guard. The engine now REJECTS such a request
//! up front, naming the vendor and the cap, so the caller can resubmit within the limit. A
//! same-protocol request relays verbatim (never rebuilt from the IR), so an over-cap
//! same-protocol request is untouched and left to that vendor's own native 400.

use super::translate_request_cross_protocol;
use crate::proto::Protocol;
use crate::test_support::{LaneSpec, TestApp};
use serde_json::json;

fn http() -> crate::transport::Transport {
    crate::transport::Transport::Http
}

// ---- CROSS-PROTOCOL over-cap stop list: REJECTED up front (was truncate-and-forward). ----

#[test]
fn openai_to_cohere_over_cap_stop_sequences_is_rejected() {
    // OpenAI ingress (unbounded `stop` array) → Cohere lane = cross-protocol. Cohere v2 caps
    // `stop_sequences` at 5; a 6-item list must be rejected, not silently trimmed to 5.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "command-r-plus",
            Protocol::cohere(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["a", "b", "c", "d", "e", "f"]
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let result = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::chat("openai", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    );
    let resp = result.expect_err(
        "cross-protocol stop-sequence list over Cohere's cap of 5 must be rejected, not silently truncated",
    );
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "over-cap stop sequences must return a 4xx naming the vendor cap"
    );
}

#[test]
fn openai_to_cohere_exactly_cap_stop_sequences_is_allowed() {
    // Guardrail: exactly 5 stop sequences is within Cohere's published cap and must succeed,
    // forwarding the full set (not a further-truncated subset).
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "command-r-plus",
            Protocol::cohere(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["a", "b", "c", "d", "e"]
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let out = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::chat("openai", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("exactly-cap stop-sequence list must not be rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("stop_sequences"),
        Some(&json!(["a", "b", "c", "d", "e"])),
        "an at-cap stop list must be forwarded whole, not further truncated"
    );
}

#[test]
fn openai_to_gemini_over_cap_stop_sequences_is_rejected() {
    // OpenAI ingress (unbounded `stop` array) → Gemini lane = cross-protocol. Gemini caps
    // `stopSequences` at 5; a 6-item list must be rejected, not silently trimmed to 5.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gemini-1.5-pro",
            Protocol::gemini(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["a", "b", "c", "d", "e", "f"]
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let result = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::chat("openai", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    );
    let resp = result.expect_err(
        "cross-protocol stop-sequence list over Gemini's cap of 5 must be rejected, not silently truncated",
    );
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "over-cap stop sequences must return a 4xx naming the vendor cap"
    );
}

#[test]
fn anthropic_to_openai_over_cap_stop_sequences_is_rejected() {
    // Anthropic ingress (unbounded `stop_sequences` array) → OpenAI lane = cross-protocol. OpenAI
    // Chat Completions caps `stop` at 4; a 5-item list must be rejected, not silently trimmed to 4.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            Protocol::openai(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16,
        "stop_sequences": ["a", "b", "c", "d", "e"]
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let result = translate_request_cross_protocol(
        &app,
        0,
        "anthropic",
        crate::handlers::chat("anthropic", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    );
    let resp = result.expect_err(
        "cross-protocol stop-sequence list over OpenAI's cap of 4 must be rejected, not silently truncated",
    );
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "over-cap stop sequences must return a 4xx naming the vendor cap"
    );
}

// ---- SAME-PROTOCOL over-cap stop list: UNTOUCHED (relayed verbatim to Cohere's own 400). ----

#[test]
fn cohere_to_cohere_over_cap_stop_sequences_is_preserved_verbatim() {
    // Cohere ingress → Cohere lane = same-protocol. The request relays verbatim (never rebuilt
    // through the IR), so busbar's own cap guard never runs here; an over-cap list is left to
    // Cohere's own native 400 on the wire, not intercepted at this layer.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "command-r-plus",
            Protocol::cohere(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "command-r-plus",
        "messages": [{"role": "user", "content": "hi"}],
        "stop_sequences": ["a", "b", "c", "d", "e", "f"]
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let out = translate_request_cross_protocol(
        &app,
        0,
        "cohere",
        crate::handlers::chat("cohere", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
)
    .expect("same-protocol over-cap stop list must NOT be rejected by busbar (Cohere's own API guards it)");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("stop_sequences"),
        Some(&json!(["a", "b", "c", "d", "e", "f"])),
        "same-protocol stop_sequences must be relayed unchanged (all six preserved)"
    );
}
