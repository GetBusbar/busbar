// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FAIL-CLOSED edge reject for requests whose response would be forced through the
//! single-candidate IR (`IrResponse` models exactly ONE assistant turn). A cross-protocol hop's
//! response reader keeps candidate `[0]` and drops the rest; before this fix that happened
//! silently with an HTTP 200. The engine now REJECTS such a request up front. A same-protocol
//! route relays the backend body verbatim (never through the IR), so an `n>1` request there is
//! untouched and must keep working.

use super::translate_request_cross_protocol;
use crate::operation::Operation;
use crate::proto::Protocol;
use crate::test_support::{LaneSpec, TestApp};
use serde_json::json;

fn http() -> crate::transport::Transport {
    crate::transport::Transport::Http
}

// ---- CROSS-PROTOCOL multi-candidate: REJECTED up front (was 200-with-1). ----

#[test]
fn openai_to_anthropic_n_gt_1_is_rejected() {
    // OpenAI ingress → Anthropic lane = a cross-protocol hop whose response would be read through
    // the single-candidate IR. `n:3` therefore cannot be honored; reject rather than return 1-of-3.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-3-5-sonnet",
            Protocol::anthropic(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16,
        "n": 3
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
    );
    let resp = result.expect_err("cross-protocol n>1 must be rejected, not silently truncated");
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "cross-protocol n>1 must return a 4xx naming the limitation"
    );
}

#[test]
fn gemini_ingress_to_openai_candidate_count_gt_1_is_rejected() {
    // Gemini ingress → OpenAI lane = cross-protocol. `generationConfig.candidateCount:2` cannot be
    // represented through the single-candidate IR.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            Protocol::openai(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": { "candidateCount": 2 }
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let result = translate_request_cross_protocol(
        &app,
        0,
        "gemini",
        crate::handlers::chat("gemini", http()),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
    );
    let resp = result
        .expect_err("cross-protocol candidateCount>1 must be rejected, not silently truncated");
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
}

// ---- SAME-PROTOCOL multi-candidate: UNTOUCHED (served verbatim, all N preserved). ----

#[test]
fn openai_to_openai_n_gt_1_is_preserved_verbatim() {
    // OpenAI ingress → OpenAI lane = same-protocol. The response body relays verbatim (never through
    // the IR), so `n:3` is legitimate and must NOT be rejected. The request seam short-circuits to
    // the pristine bytes, which still carry `n:3`.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            Protocol::openai(),
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "n": 3
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
    )
    .expect("same-protocol n>1 is legitimate and must NOT be rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("n"),
        Some(&json!(3)),
        "same-protocol n>1 must be relayed unchanged (all candidates preserved)"
    );
}

#[test]
fn same_protocol_n_1_and_absent_are_not_rejected_cross_protocol() {
    // Guardrail: a genuine single-candidate cross-protocol request (n=1, or n absent) must succeed.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-3-5-sonnet",
            Protocol::anthropic(),
            "http://unused.local",
        ))
        .build();
    for body in [
        json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":16,"n":1}),
        json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":16}),
    ] {
        let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
        let r = translate_request_cross_protocol(
            &app,
            0,
            "openai",
            crate::handlers::chat("openai", http()),
            Some(body),
            crate::proxy::APPLICATION_JSON,
            true,
            &hop_bytes,
        );
        assert!(
            r.is_ok(),
            "a single-candidate cross-protocol request must not be rejected"
        );
    }
}

// ---- BATCH EMBEDDINGS → Gemini :embedContent: REJECTED (was 200-with-one). ----

#[test]
fn multi_input_embeddings_to_gemini_is_rejected() {
    // OpenAI embeddings (multi-input) → Gemini lane. Gemini `:embedContent` embeds a SINGLE input;
    // reducing to the first would silently misalign inputs[i] <-> embeddings[i]. Reject instead.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "text-embedding-004",
            Protocol::gemini(),
            "http://unused.local",
        ))
        .build();
    let op = crate::handlers::op_for("openai", Operation::EMBEDDINGS, http())
        .expect("openai serves embeddings");
    let body = json!({
        "model": "text-embedding-3-small",
        "input": ["alpha", "beta", "gamma"]
    });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let result = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        op,
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
    );
    let resp = result.expect_err("multi-input embeddings → Gemini :embedContent must be rejected");
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[test]
fn single_input_embeddings_to_gemini_is_allowed() {
    // A single-input embeddings request is representable on `:embedContent` and must succeed.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "text-embedding-004",
            Protocol::gemini(),
            "http://unused.local",
        ))
        .build();
    let op = crate::handlers::op_for("openai", Operation::EMBEDDINGS, http())
        .expect("openai serves embeddings");
    let body = json!({ "model": "text-embedding-3-small", "input": ["alpha"] });
    let hop_bytes = bytes::Bytes::from(crate::json::to_vec(&body).unwrap());
    let r = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        op,
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
    );
    assert!(r.is_ok(), "single-input embeddings → Gemini must succeed");
}
