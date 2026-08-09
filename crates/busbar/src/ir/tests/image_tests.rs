// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/image.rs`.

use super::*;

#[test]
fn geometry_conventions_are_parallel_not_collapsed() {
    let req = ImageReq {
        model: "imagen-3".into(),
        aspect_ratio: Some("16:9".into()),
        image_size_tier: Some("2K".into()),
        size: Some(ImageSize::Wh {
            width: 1024,
            height: 1024,
        }),
        ..Default::default()
    };
    // all three can be set — a codec picks its provider's convention without losing the others.
    assert!(req.aspect_ratio.is_some() && req.image_size_tier.is_some() && req.size.is_some());
}

#[test]
fn billing_prefers_tokens_else_per_image() {
    let tokenized = ImageResp {
        usage: Some(TokenUsage {
            input: 5,
            output: 272,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(matches!(tokenized.billing(), Some(Billing::Tokens(_))));

    let per_image = ImageResp {
        cost_basis: Some(CostBasis {
            count: 2,
            size: Some("1024x1024".into()),
            quality: Some("hd".into()),
        }),
        ..Default::default()
    };
    assert!(matches!(
        per_image.billing(),
        Some(Billing::Images { count: 2, .. })
    ));

    assert!(ImageResp::default().billing().is_none());
}

#[test]
fn variation_op_needs_no_prompt() {
    let req = ImageReq {
        op: ImageOp::Variation,
        input_images: vec!["b64data".into()],
        ..Default::default()
    };
    assert_eq!(req.op, ImageOp::Variation);
    assert!(req.prompt.is_none());
}
