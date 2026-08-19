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
    let ir = BedrockImage
        .read_request(body, "application/json")
        .expect("valid titan image body");
    let IrReq::Image(r) = ir else {
        panic!("expected IrReq::Image");
    };
    assert_eq!(r.prompt.as_deref(), Some("a cat"));
    assert_eq!(r.n, Some(2));
}

#[test]
fn embeddings_read_request_captures_input_text() {
    // Titan embeddings InvokeModel body → IR Embeddings carrying the inputText string.
    let ir = BedrockEmbeddings
        .read_request(br#"{"inputText":"hello"}"#, "application/json")
        .expect("valid titan embeddings body");
    let IrReq::Embeddings(r) = ir else {
        panic!("expected IrReq::Embeddings");
    };
    assert_eq!(r.input, EmbInput::Text(vec!["hello".to_string()]));
}

#[test]
fn embeddings_write_request_warns_on_dropped_non_text_input() {
    use busbar_core::ir::embeddings::EmbeddingsReq;
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = IrReq::Embeddings(EmbeddingsReq {
        input: EmbInput::Tokens(vec![vec![1, 2, 3]]),
        ..Default::default()
    });
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out =
        tracing::subscriber::with_default(subscriber, || BedrockEmbeddings.write_request(&req));

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
    let err = BedrockEmbeddings
        .read_request(br#"{"dimensions":256}"#, "application/json")
        .expect_err("missing inputText must reject");
    assert!(matches!(err, IngressReject::BadRequest(_)));
}

#[test]
fn embeddings_write_read_roundtrip_preserves_input_text() {
    // write_request emits `inputText`; read_request must recover the same input string.
    let req = IrReq::Embeddings(busbar_core::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec!["roundtrip".to_string()]),
        encoding_formats: vec![EncFmt::Float],
        ..Default::default()
    });
    let wire = BedrockEmbeddings.write_request(&req);
    let back = BedrockEmbeddings
        .read_request(&wire, "application/json")
        .expect("emitted body reparses");
    let IrReq::Embeddings(r) = back else {
        panic!("expected IrReq::Embeddings");
    };
    assert_eq!(r.input, EmbInput::Text(vec!["roundtrip".to_string()]));
}
