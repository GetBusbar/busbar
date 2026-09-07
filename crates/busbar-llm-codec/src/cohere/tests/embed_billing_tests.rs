// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BILLED-UNIT TESTS for the Cohere `/v2/embed` response reader.
//!
//! `read_embeddings_response` had no test at all, and the one billed bucket it read was
//! `billed_units.input_tokens`. The pinned Cohere OpenAPI document types `ApiMetaBilledUnits` with
//! SEVEN sibling counts — `images`, `input_tokens`, `image_tokens`, `output_tokens`,
//! `search_units`, `classifications`, `pages` — and its own `/v2/embed` image example answers with
//!
//!   meta: { api_version: { version: '2' }, billed_units: { images: 1 } }
//!
//! i.e. NO `input_tokens` at all. An image embed therefore reached the ledger as "no usage
//! reported" and billed nothing. These tests pin the two counts an embed call is actually invoiced
//! on (`images`, `image_tokens`) alongside the text one, and pin that a text-only body still reads
//! and re-serializes exactly as it did.

use super::*;

/// The pinned spec's own `/v2/embed` image example: `billed_units.images` and nothing else. The
/// read must report the billed image count — before this it reported `usage: None`, which the
/// billing projection turns into "this call is free".
#[test]
fn an_image_embed_bills_the_images_the_spec_example_reports() {
    let wire = serde_json::to_vec(&json!({
        "id": "emb-img-1",
        "response_type": "embeddings_by_type",
        "embeddings": { "float": [[0.5, -0.25]] },
        "meta": {
            "api_version": { "version": "2" },
            "billed_units": { "images": 1 }
        }
    }))
    .unwrap();
    let ir = read_embeddings_response(&wire).expect("parses");
    assert_eq!(
        ir.billed_images,
        Some(1),
        "the spec's image example bills one image; a dropped `images` bills the call at zero"
    );
    // ... and it reaches the ledger as a billable item rather than as "no usage reported".
    assert_eq!(
        ir.billing(),
        Some(busbar_substrate_values::billing::Billing::Images {
            count: 1,
            size: None,
            quality: None
        }),
        "an image embed that reports its billed images must not project to a free call"
    );
    // ... and it survives the write leg, exactly as rerank's `search_units` does.
    let out = write_embeddings_response(&ir);
    let v: Value = serde_json::from_slice(out.bytes.as_ref()).unwrap();
    assert_eq!(v["meta"]["billed_units"]["images"], json!(1));
}

/// `billed_units.image_tokens` is a BILLED TOKEN count (the spec: "The number of billed image
/// tokens"), so it belongs in the input total the ledger prices and in the per-modality slice that
/// partitions it.
#[test]
fn image_tokens_are_input_tokens_the_total_counts() {
    let wire = serde_json::to_vec(&json!({
        "embeddings": { "float": [[0.5]] },
        "meta": { "billed_units": { "input_tokens": 7, "image_tokens": 40, "images": 2 } }
    }))
    .unwrap();
    let ir = read_embeddings_response(&wire).expect("parses");
    let u = ir.usage.clone().expect("usage is reported");
    assert_eq!(u.input, 47, "billed image tokens are billed input tokens");
    assert_eq!(u.input_image, Some(40), "the image slice partitions input");
    assert_eq!(ir.billed_images, Some(2));
    // Round-trip: the two token buckets go back out where they came from (not summed into one).
    let out = write_embeddings_response(&ir);
    let v: Value = serde_json::from_slice(out.bytes.as_ref()).unwrap();
    assert_eq!(v["meta"]["billed_units"]["input_tokens"], json!(7));
    assert_eq!(v["meta"]["billed_units"]["image_tokens"], json!(40));
    assert_eq!(v["meta"]["billed_units"]["images"], json!(2));
    let back = read_embeddings_response(out.bytes.as_ref()).expect("re-reads");
    assert_eq!(back.usage, ir.usage);
    assert_eq!(back.billed_images, ir.billed_images);
}

/// Cohere types every `billed_units` count as `number`, not `integer` — a backend that answers
/// `1200.0` must bill 1200, not zero. (`read_rerank_response` already reads its bucket tolerantly.)
#[test]
fn a_billed_count_the_spec_types_as_a_double_is_the_count_it_says() {
    let wire = serde_json::to_vec(&json!({
        "embeddings": { "float": [[0.5]] },
        "meta": { "billed_units": { "input_tokens": 1200.0, "images": 3.0 } }
    }))
    .unwrap();
    let ir = read_embeddings_response(&wire).expect("parses");
    assert_eq!(ir.usage.expect("usage").input, 1200);
    assert_eq!(ir.billed_images, Some(3));
}

/// A text-only embed body reads AND re-serializes exactly as it did before the image buckets were
/// read: no `image_tokens`/`images` key appears, and `input_tokens` is the same number.
#[test]
fn a_text_only_embed_body_is_byte_identical_on_the_write_leg() {
    let wire = serde_json::to_vec(&json!({
        "id": "emb-text-1",
        "response_type": "embeddings_by_type",
        "embeddings": { "float": [[0.5, -0.25]] },
        "meta": { "billed_units": { "input_tokens": 12 } }
    }))
    .unwrap();
    let ir = read_embeddings_response(&wire).expect("parses");
    assert_eq!(ir.billed_images, None);
    assert_eq!(ir.usage.as_ref().expect("usage").input, 12);
    assert_eq!(ir.usage.as_ref().expect("usage").input_image, None);
    let out = write_embeddings_response(&ir);
    assert_eq!(
        String::from_utf8(out.bytes.to_vec()).unwrap(),
        r#"{"embeddings":{"float":[[0.5,-0.25]]},"id":"emb-text-1","meta":{"billed_units":{"input_tokens":12}},"response_type":"embeddings_by_type"}"#,
        "a text-only embed response keeps the bytes it had"
    );
}
