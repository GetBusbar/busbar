// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Titan/Bedrock InvokeModel writers send exactly the members v1.5.5 sent (LLM2#7; architect
//! ruling 2026-10-23 R-1: customer-visible behaviour stays v1.5.5's):
//!   * embeddings: `inputText` and `dimensions` (v1.5.5 `handlers/bedrock.rs:196-228`);
//!   * image: `taskType`, `textToImageParams.text`, `imageGenerationConfig.numberOfImages`
//!     (v1.5.5 `handlers/bedrock.rs:121-131`);
//!   * rerank: `query`, `documents`, `api_version`, `top_n` (v1.5.5 `handlers/bedrock.rs:311-324`),
//!     and the answer `results[].{index,relevance_score}` plus `id` (`:334-348`).
//!
//! Every other member the IR carries (`normalize`, a negative prompt, a seed, a guidance scale, a
//! size, a quality tier, `return_documents`, a ranked `document`) is dropped with a warn. Carrying
//! them put new bytes on the far end's wire: an OpenAI `quality: "hd"` is off Titan's vocabulary
//! (`standard|premium`), so a request 1.5.5 served could come back a 400. The readers still read
//! them, so nothing a caller sends is refused.

use super::*;
use busbar_contract::testkit::WarnCapture;

/// Run `write` under a warn capture: the wire it wrote, parsed, and the capture.
fn written(write: impl FnOnce() -> Vec<u8>) -> (Value, WarnCapture) {
    let cap = WarnCapture::default();
    let bytes = tracing::subscriber::with_default(cap.clone(), write);
    (serde_json::from_slice(&bytes).unwrap(), cap)
}

#[test]
fn titan_embeddings_writer_drops_normalize_as_1_5_5_did() {
    let req = EmbeddingsReq {
        input: EmbInput::Text(vec!["hello".to_string()]),
        dimensions: Some(256),
        normalize: Some(false),
        ..Default::default()
    };
    let (v, cap) = written(|| write_embeddings_request(&req).to_vec());
    assert_eq!(
        v,
        serde_json::json!({"inputText": "hello", "dimensions": 256}),
        "exactly v1.5.5's members: {v}"
    );
    assert!(
        cap.contains("dropping `normalize`"),
        "the drop is warned: {:?}",
        cap.messages()
    );
}

#[test]
fn titan_embeddings_writer_omits_normalize_when_absent() {
    let req = EmbeddingsReq {
        input: EmbInput::Text(vec!["hello".to_string()]),
        ..Default::default()
    };
    let (v, cap) = written(|| write_embeddings_request(&req).to_vec());
    assert!(
        v.get("normalize").is_none(),
        "an unset normalize must not be fabricated on the wire: {v}"
    );
    assert!(
        !cap.contains("dropping"),
        "nothing dropped, nothing warned: {:?}",
        cap.messages()
    );
}

#[test]
fn titan_image_writer_sends_only_the_1_5_5_members() {
    let req = crate::codec::ir::image::ImageReq {
        prompt: Some("a red bus".to_string()),
        negative_prompt: Some("blurry".to_string()),
        n: Some(2),
        seed: Some(1234),
        guidance_scale: Some(7.5),
        size: Some(crate::codec::ir::image::ImageSize::Wh {
            width: 1024,
            height: 1024,
        }),
        quality: Some("hd".to_string()),
        ..Default::default()
    };
    let (v, cap) = written(|| write_image_request(&req).to_vec());
    assert_eq!(
        v,
        serde_json::json!({
            "taskType": "TEXT_IMAGE",
            "textToImageParams": {"text": "a red bus"},
            "imageGenerationConfig": {"numberOfImages": 2}
        }),
        "exactly v1.5.5's members: {v}"
    );
    for name in [
        "negative_prompt",
        "seed",
        "guidance_scale",
        "size",
        "quality",
    ] {
        assert!(
            cap.contains(&format!("dropping `{name}`")),
            "the `{name}` drop is warned: {:?}",
            cap.messages()
        );
    }
}

#[test]
fn titan_image_writer_omits_unset_optional_params() {
    let req = crate::codec::ir::image::ImageReq {
        prompt: Some("a red bus".to_string()),
        ..Default::default()
    };
    let (v, cap) = written(|| write_image_request(&req).to_vec());
    assert!(v["textToImageParams"].get("negativeText").is_none(), "{v}");
    assert!(v["imageGenerationConfig"].get("seed").is_none(), "{v}");
    assert!(v["imageGenerationConfig"].get("cfgScale").is_none(), "{v}");
    assert!(
        !cap.contains("dropping"),
        "nothing dropped, nothing warned: {:?}",
        cap.messages()
    );
}

#[test]
fn bedrock_rerank_writer_drops_return_documents_as_1_5_5_did() {
    let req = crate::codec::ir::rerank::RerankReq {
        model: String::new(),
        query: "q".into(),
        documents: vec!["a".into(), "b".into()],
        top_n: Some(1),
        return_documents: Some(true),
        ..Default::default()
    };
    let (v, cap) = written(|| write_rerank_request(&req).to_vec());
    assert_eq!(
        v,
        serde_json::json!({"query": "q", "documents": ["a", "b"], "api_version": 2, "top_n": 1}),
        "exactly v1.5.5's members: {v}"
    );
    assert!(
        cap.contains("dropping `return_documents`"),
        "the drop is warned: {:?}",
        cap.messages()
    );
    // The reader still reads a Bedrock caller's flag: nothing a caller sends is refused.
    let body = br#"{"query":"q","documents":["a"],"return_documents":true}"#;
    let back = read_rerank_request(body, "application/json").expect("read");
    assert_eq!(back.return_documents, Some(true));
}

#[test]
fn bedrock_rerank_answer_echoes_no_document_as_1_5_5_did() {
    let resp = crate::codec::ir::rerank::RerankResp {
        id: Some("r1".into()),
        results: vec![crate::codec::ir::rerank::RerankResult {
            index: 1,
            relevance_score: 0.5,
            document: Some("b".into()),
        }],
        ..Default::default()
    };
    let (v, cap) = written(|| write_rerank_response(&resp).bytes.to_vec());
    assert_eq!(
        v,
        serde_json::json!({"results": [{"index": 1, "relevance_score": 0.5}], "id": "r1"}),
        "exactly v1.5.5's members: {v}"
    );
    assert!(
        cap.contains("dropping `document`"),
        "the drop is warned: {:?}",
        cap.messages()
    );
}

// L4: an oversize width/height must not WRAP through `as u32` (`4294967297 as u32 == 1`) — the
// checked `u32::try_from(...).ok()` drops the geometry instead. Fails pre-fix: `size` became
// `Wh { width: 1, .. }`.
#[test]
fn bedrock_image_oversize_geometry_does_not_wrap() {
    let body = serde_json::json!({
        "textToImageParams": { "text": "a bus" },
        "imageGenerationConfig": { "width": 4294967297u64, "height": 512 },
    });
    let ir =
        read_image_request(&serde_json::to_vec(&body).unwrap(), "application/json").expect("read");
    assert_eq!(
        ir.size, None,
        "an out-of-u32-range width must drop the geometry, not wrap to 1px: {:?}",
        ir.size
    );

    // A valid in-range geometry still parses.
    let body_ok = serde_json::json!({
        "textToImageParams": { "text": "a bus" },
        "imageGenerationConfig": { "width": 1024, "height": 768 },
    });
    let ir_ok = read_image_request(&serde_json::to_vec(&body_ok).unwrap(), "application/json")
        .expect("read");
    assert_eq!(
        ir_ok.size,
        Some(crate::codec::ir::image::ImageSize::Wh {
            width: 1024,
            height: 768
        }),
        "in-range geometry must parse unchanged"
    );
}
