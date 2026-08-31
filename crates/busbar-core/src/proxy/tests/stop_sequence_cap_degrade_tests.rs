// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! v1.5.4-restored stop-sequence-cap cross-protocol degrade (Cohere: 5, Gemini: 5, OpenAI: 4).
//! v1.5.4's `clamp_stop` TRUNCATED an over-cap list to the cap, emitted a `tracing::warn!` naming
//! the vendor, cap, and dropped count, and forwarded the clamped set upstream at HTTP 200. 1.6.0
//! briefly turned that silent-degrade into a hard 400; this restores the v1.5.4 outcome: the egress
//! writer clamps to the cap and forwards. A same-protocol request relays verbatim (never rebuilt
//! from the IR), so an over-cap same-protocol request is untouched and left to that vendor's own
//! native 400.

use super::translate_request_cross_protocol;
use crate::test_support::{LaneSpec, TestApp};
use serde_json::json;

fn http() -> crate::transport::Transport {
    crate::transport::Transport::Http
}

// ---- CROSS-PROTOCOL over-cap stop list: CLAMPED to cap and forwarded at 200 (v1.5.4). ----

#[test]
fn openai_to_cohere_over_cap_stop_sequences_is_clamped_not_rejected() {
    // OpenAI ingress (unbounded `stop` array) → Cohere lane = cross-protocol. Cohere v2 caps
    // `stop_sequences` at 5; a 6-item list is CLAMPED to the first 5 and forwarded, not rejected.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "command-r-plus",
            crate::proto::PROTO_COHERE,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["a", "b", "c", "d", "e", "f"]
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
    .expect("cross-protocol over-cap stop list must be clamped and forwarded, not rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("stop_sequences"),
        Some(&json!(["a", "b", "c", "d", "e"])),
        "an over-cap stop list must be clamped to Cohere's cap of 5 (v1.5.4 truncate-and-forward)"
    );
}

#[test]
fn openai_to_cohere_exactly_cap_stop_sequences_is_allowed() {
    // Guardrail: exactly 5 stop sequences is within Cohere's published cap and must be forwarded
    // whole (no clamp when at or under the cap).
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "command-r-plus",
            crate::proto::PROTO_COHERE,
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
        "an at-cap stop list must be forwarded whole, not truncated"
    );
}

#[test]
fn openai_to_gemini_over_cap_stop_sequences_is_clamped_not_rejected() {
    // OpenAI ingress (unbounded `stop` array) → Gemini lane = cross-protocol. Gemini caps
    // `stopSequences` at 5; a 6-item list is clamped to 5 and forwarded, not rejected.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gemini-1.5-pro",
            crate::proto::PROTO_GEMINI,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["a", "b", "c", "d", "e", "f"]
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
    .expect("cross-protocol over-cap stop list must be clamped and forwarded, not rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.pointer("/generationConfig/stopSequences"),
        Some(&json!(["a", "b", "c", "d", "e"])),
        "an over-cap stop list must be clamped to Gemini's cap of 5 (v1.5.4 truncate-and-forward)"
    );
}

#[test]
fn anthropic_to_openai_over_cap_stop_sequences_is_clamped_not_rejected() {
    // Anthropic ingress (unbounded `stop_sequences` array) → OpenAI lane = cross-protocol. OpenAI
    // Chat Completions caps `stop` at 4; a 5-item list is clamped to 4 and forwarded, not rejected.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto::PROTO_OPENAI,
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
    let out = translate_request_cross_protocol(
        &app,
        0,
        "anthropic",
        crate::handlers::chat("anthropic", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("cross-protocol over-cap stop list must be clamped and forwarded, not rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("stop"),
        Some(&json!(["a", "b", "c", "d"])),
        "an over-cap stop list must be clamped to OpenAI's cap of 4 (v1.5.4 truncate-and-forward)"
    );
}

// ---- SAME-PROTOCOL over-cap stop list: UNTOUCHED (relayed verbatim to Cohere's own 400). ----

#[test]
fn cohere_to_cohere_over_cap_stop_sequences_is_preserved_verbatim() {
    // Cohere ingress → Cohere lane = same-protocol. The request relays verbatim (never rebuilt
    // through the IR), so busbar's own clamp never runs here; an over-cap list is left to
    // Cohere's own native 400 on the wire, not intercepted at this layer.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "command-r-plus",
            crate::proto::PROTO_COHERE,
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
