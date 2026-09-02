// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! v1.5.4-restored multi-candidate cross-protocol degrade. The busbar IR (`IrResponse`) models
//! exactly ONE assistant turn, so a cross-protocol hop's response reader keeps candidate `[0]` and
//! drops the rest. v1.5.4 forwarded such a request and returned that first candidate at HTTP 200;
//! 1.6.0 briefly turned that silent-degrade into a hard 400. This restores the v1.5.4 outcome:
//! `n>1` / `candidateCount>1` is FORWARDED (1-of-N at 200), not rejected. A same-protocol route
//! relays the backend body verbatim (never through the IR), so an `n>1` request there keeps all N.

use super::translate_request_cross_protocol;
use crate::test_support::{LaneSpec, TestApp};
use busbar_core::operation::Operation;
use serde_json::json;

fn http() -> busbar_substrate::transport::Transport {
    busbar_substrate::transport::Transport::Http
}

// ---- CROSS-PROTOCOL multi-candidate: FORWARDED, first candidate at 200 (v1.5.4 degrade). ----

#[test]
fn openai_to_anthropic_n_gt_1_is_forwarded_not_rejected() {
    crate::testkit::install_test_seams();
    // OpenAI ingress → Anthropic lane = a cross-protocol hop whose response is read through the
    // single-candidate IR. v1.5.4 forwarded `n:3` and returned candidate [0]; restore that. The
    // request must translate to a valid Anthropic body (Anthropic models no `n`, so it is dropped).
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-3-5-sonnet",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16,
        "n": 3
    });
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        busbar_substrate::handlers::chat("openai", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("cross-protocol n>1 must be forwarded (1-of-N at 200), not rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    // Anthropic has no multi-candidate control, so `n` does not cross; the translated body is a
    // well-formed single-turn Anthropic request the backend accepts.
    assert!(
        parsed.get("n").is_none(),
        "Anthropic models no candidate count; `n` must not appear on the egress body"
    );
    assert!(
        parsed.get("messages").is_some(),
        "the translated Anthropic body must carry the messages"
    );
}

#[test]
fn gemini_ingress_to_openai_candidate_count_gt_1_is_forwarded_not_rejected() {
    crate::testkit::install_test_seams();
    // Gemini ingress → OpenAI lane = cross-protocol. v1.5.4 forwarded `candidateCount:2` and read
    // candidate [0] back. OpenAI models `n`, so the ask crosses; the response reader still keeps
    // only the first candidate. Either way it must NOT be rejected with a 400.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": { "candidateCount": 2 }
    });
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "gemini",
        busbar_substrate::handlers::chat("gemini", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("cross-protocol candidateCount>1 must be forwarded, not rejected");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get("messages").is_some(),
        "the translated OpenAI body must carry the messages"
    );
}

// ---- SAME-PROTOCOL multi-candidate: UNTOUCHED (served verbatim, all N preserved). ----

#[test]
fn openai_to_openai_n_gt_1_is_preserved_verbatim() {
    crate::testkit::install_test_seams();
    // OpenAI ingress → OpenAI lane = same-protocol. The response body relays verbatim (never through
    // the IR), so `n:3` is legitimate and must NOT be rejected. The request seam short-circuits to
    // the pristine bytes, which still carry `n:3`.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://unused.local",
        ))
        .build();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "n": 3
    });
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        busbar_substrate::handlers::chat("openai", http()),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
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
fn single_candidate_cross_protocol_is_not_rejected() {
    crate::testkit::install_test_seams();
    // Guardrail: a genuine single-candidate cross-protocol request (n=1, or n absent) must succeed.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-3-5-sonnet",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://unused.local",
        ))
        .build();
    for body in [
        json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":16,"n":1}),
        json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":16}),
    ] {
        let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
        let (host, rt) = crate::engine::test_host_rt(&app);
        let r = translate_request_cross_protocol(
            &host,
            &rt,
            0,
            "openai",
            busbar_substrate::handlers::chat("openai", http()),
            Some(body),
            crate::engine::APPLICATION_JSON,
            true,
            &hop_bytes,
            "test-key",
        );
        assert!(
            r.is_ok(),
            "a single-candidate cross-protocol request must not be rejected"
        );
    }
}

// ---- BATCH EMBEDDINGS → Gemini :embedContent: FORWARDED, first input at 200 (v1.5.4). ----

#[test]
fn multi_input_embeddings_to_gemini_embeds_first_not_rejected() {
    crate::testkit::install_test_seams();
    // OpenAI embeddings (multi-input) → Gemini lane. Gemini `:embedContent` embeds a SINGLE input;
    // v1.5.4 embedded the FIRST input (with a `warn!`) and returned 200. Restore that: forward with
    // the first input on the wire, do not reject.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "text-embedding-004",
            crate::proto_codec::PROTO_GEMINI,
            "http://unused.local",
        ))
        .build();
    let op = busbar_substrate::handlers::op_for("openai", Operation::EMBEDDINGS, http())
        .expect("openai serves embeddings");
    let body = json!({
        "model": "text-embedding-3-small",
        "input": ["alpha", "beta", "gamma"]
    });
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let out = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        op,
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect(
        "multi-input embeddings → Gemini :embedContent must forward the first input, not reject",
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.pointer("/content/parts/0/text"),
        Some(&json!("alpha")),
        "the FIRST input must be embedded (v1.5.4 first-input degrade)"
    );
}

#[test]
fn single_input_embeddings_to_gemini_is_allowed() {
    crate::testkit::install_test_seams();
    // A single-input embeddings request is representable on `:embedContent` and must succeed.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "text-embedding-004",
            crate::proto_codec::PROTO_GEMINI,
            "http://unused.local",
        ))
        .build();
    let op = busbar_substrate::handlers::op_for("openai", Operation::EMBEDDINGS, http())
        .expect("openai serves embeddings");
    let body = json!({ "model": "text-embedding-3-small", "input": ["alpha"] });
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let (host, rt) = crate::engine::test_host_rt(&app);
    let r = translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        op,
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    );
    assert!(r.is_ok(), "single-input embeddings → Gemini must succeed");
}
