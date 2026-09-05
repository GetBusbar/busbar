// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression net for the Titan writer round-trip losses:
//!   * embeddings `normalize` — captured by `read_embeddings_request`, formerly dropped by the
//!     writer.
//!   * image `negativeText` / `seed` / `cfgScale` — captured by `read_image_request`, formerly
//!     dropped by the writer.
//!
//! Each param must survive `write_* -> read_*` so egress to a Titan backend is lossless.

use super::*;

#[test]
fn titan_embeddings_writer_round_trips_normalize() {
    let req = EmbeddingsReq {
        input: EmbInput::Text(vec!["hello".to_string()]),
        dimensions: Some(256),
        normalize: Some(false),
        ..Default::default()
    };
    let wire = write_embeddings_request(&req);

    // Present on the wire in Titan's native top-level shape...
    let v: Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        v["normalize"],
        serde_json::json!(false),
        "normalize on wire: {v}"
    );

    // ...and it round-trips back through the reader rather than being dropped.
    let back = read_embeddings_request(&wire, "application/json").expect("re-read");
    assert_eq!(back.normalize, Some(false), "normalize must round-trip");
}

#[test]
fn titan_embeddings_writer_omits_normalize_when_absent() {
    let req = EmbeddingsReq {
        input: EmbInput::Text(vec!["hello".to_string()]),
        ..Default::default()
    };
    let v: Value = serde_json::from_slice(&write_embeddings_request(&req)).unwrap();
    assert!(
        v.get("normalize").is_none(),
        "an unset normalize must not be fabricated on the wire: {v}"
    );
}

#[test]
fn titan_image_writer_round_trips_negative_seed_cfgscale() {
    let req = crate::ir::image::ImageReq {
        prompt: Some("a red bus".to_string()),
        negative_prompt: Some("blurry".to_string()),
        n: Some(2),
        seed: Some(1234),
        guidance_scale: Some(7.5),
        ..Default::default()
    };
    let wire = write_image_request(&req);
    let v: Value = serde_json::from_slice(&wire).unwrap();

    // Native Titan layout: negativeText under textToImageParams; seed/cfgScale under
    // imageGenerationConfig.
    assert_eq!(v["textToImageParams"]["negativeText"], "blurry", "{v}");
    assert_eq!(
        v["imageGenerationConfig"]["seed"],
        serde_json::json!(1234),
        "{v}"
    );
    assert_eq!(
        v["imageGenerationConfig"]["cfgScale"],
        serde_json::json!(7.5),
        "{v}"
    );

    let back = read_image_request(&wire, "application/json").expect("re-read");
    assert_eq!(back.negative_prompt.as_deref(), Some("blurry"));
    assert_eq!(back.seed, Some(1234));
    assert_eq!(back.guidance_scale, Some(7.5));
}

#[test]
fn titan_image_writer_omits_unset_optional_params() {
    let req = crate::ir::image::ImageReq {
        prompt: Some("a red bus".to_string()),
        ..Default::default()
    };
    let v: Value = serde_json::from_slice(&write_image_request(&req)).unwrap();
    assert!(v["textToImageParams"].get("negativeText").is_none(), "{v}");
    assert!(v["imageGenerationConfig"].get("seed").is_none(), "{v}");
    assert!(v["imageGenerationConfig"].get("cfgScale").is_none(), "{v}");
}

// M2: `return_documents` is emitted by the bedrock rerank writer and honored by the
// cohere.rerank-*/amazon.rerank-* models, but the reader formerly never parsed it — so a
// bedrock->bedrock rerank with `return_documents:true` lost the flag. Fails pre-fix: the read-back
// `return_documents` was `None`.
#[test]
fn bedrock_rerank_writer_round_trips_return_documents() {
    let req = crate::ir::rerank::RerankReq {
        model: String::new(),
        query: "q".into(),
        documents: vec!["a".into(), "b".into()],
        return_documents: Some(true),
        ..Default::default()
    };
    let wire = write_rerank_request(&req);
    let v: Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        v["return_documents"],
        serde_json::json!(true),
        "return_documents on wire: {v}"
    );
    let back = read_rerank_request(&wire, "application/json").expect("re-read");
    assert_eq!(
        back.return_documents,
        Some(true),
        "return_documents must round-trip through write->read"
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
        Some(crate::ir::image::ImageSize::Wh {
            width: 1024,
            height: 768
        }),
        "in-range geometry must parse unchanged"
    );
}
