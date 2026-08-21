// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/handlers/bedrock.rs`.

use super::*;

#[test]
fn invoke_rerank_not_misclassified_by_inputtext_substring() {
    // A rerank body whose query/document text merely MENTIONS "inputText" must resolve to
    // Rerank (checked first, key-anchored), not be stolen by the embeddings substring scan.
    let h = BedrockRequestHandler;
    let body = br#"{"query":"how does inputText work?","documents":["textToImageParams too"]}"#;
    assert_eq!(
        h.resolve_operation("/model/cohere.rerank-v3-5:0/invoke", body),
        Some(Operation::RERANK),
    );
    // Real Titan embeddings (top-level inputText key) still resolves to Embeddings.
    assert_eq!(
        h.resolve_operation(
            "/model/amazon.titan-embed-text-v2:0/invoke",
            br#"{"inputText":"hello"}"#,
        ),
        Some(Operation::EMBEDDINGS),
    );
    // Real Titan image (top-level textToImageParams key) still resolves to Image.
    assert_eq!(
        h.resolve_operation(
            "/model/amazon.titan-image-generator-v1/invoke",
            br#"{"textToImageParams":{"text":"a cat"}}"#,
        ),
        Some(Operation::IMAGE),
    );
    // Converse remains chat.
    assert_eq!(
        h.resolve_operation("/model/anthropic.claude/converse", b"{}"),
        Some(Operation::CHAT),
    );
}

#[test]
fn image_read_request_captures_prompt_and_count() {
    // Titan image InvokeModel body → IR Image with the prompt from textToImageParams.text and
    // n from imageGenerationConfig.numberOfImages.
    let body =
        br#"{"textToImageParams":{"text":"a cat"},"imageGenerationConfig":{"numberOfImages":2}}"#;
    let ir =
        super::super::super::leaf_codec::image_read_request("bedrock", body, "application/json")
            .expect("valid titan image body");
    let r = ir;
    assert_eq!(r.prompt.as_deref(), Some("a cat"));
    assert_eq!(r.n, Some(2));
}

// FIND (money): Titan/SDXL image responses are per-image (N base64 images, no usage object); the
// reader must record a cost basis from the N returned images so `billing()` is `Images{count:N}`,
// not `None`. Fails pre-fix (both usage and cost_basis left unset → `billing()` is None → unmetered).
#[test]
fn image_response_bills_per_image() {
    let wire = br#"{"images":["AAAA","BBBB","CCCC"]}"#;
    let resp = super::read_image_response(wire).unwrap();
    match resp.billing() {
        Some(busbar_core::billing::Billing::Images { count, .. }) => assert_eq!(count, 3),
        other => panic!("Titan per-image response must bill Images, got {other:?}"),
    }
}

#[test]
fn embeddings_read_request_captures_input_text() {
    // Titan embeddings InvokeModel body → IR Embeddings carrying the inputText string.
    let ir = super::super::super::leaf_codec::embeddings_read_request(
        "bedrock",
        br#"{"inputText":"hello"}"#,
        "application/json",
    )
    .expect("valid titan embeddings body");
    let r = ir;
    assert_eq!(r.input, EmbInput::Text(vec!["hello".to_string()]));
}

#[test]
fn embeddings_write_request_warns_on_dropped_non_text_input() {
    use crate::ir::embeddings::EmbeddingsReq;
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = EmbeddingsReq {
        input: EmbInput::Tokens(vec![vec![1, 2, 3]]),
        ..Default::default()
    };
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        super::super::super::leaf_codec::embeddings_write_request("bedrock", &req)
    });

    // Behavior: a non-text input has no Titan analog, so `inputText` is empty (regression half).
    let body: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(body["inputText"], json!(""));

    assert!(
        cap.contains("dropping a non-text embeddings input"),
        "a dropped non-text embeddings input must warn: {:?}",
        cap.messages()
    );
}

#[test]
fn embeddings_read_request_without_input_text_is_bad_request() {
    // A Titan embeddings body missing the required inputText key must 400 at the trust
    // boundary, not resolve to an empty embed input.
    let err = super::super::super::leaf_codec::embeddings_read_request(
        "bedrock",
        br#"{"dimensions":256}"#,
        "application/json",
    )
    .expect_err("missing inputText must reject");
    assert!(matches!(err, IngressReject::BadRequest(_)));
}

#[test]
fn embeddings_write_read_roundtrip_preserves_input_text() {
    // write_request emits `inputText`; read_request must recover the same input string.
    let req = crate::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec!["roundtrip".to_string()]),
        encoding_formats: vec![EncFmt::Float],
        ..Default::default()
    };
    let wire = super::super::super::leaf_codec::embeddings_write_request("bedrock", &req);
    let back = super::super::super::leaf_codec::embeddings_read_request(
        "bedrock",
        &wire,
        "application/json",
    )
    .expect("emitted body reparses");
    let r = back;
    assert_eq!(r.input, EmbInput::Text(vec!["roundtrip".to_string()]));
}
