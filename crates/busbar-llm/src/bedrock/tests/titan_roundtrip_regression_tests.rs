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
