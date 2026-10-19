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
        usage: Some(super::ImageTokens {
            input: Some(5),
            output: Some(272),
        }),
        ..Default::default()
    };
    // Image tokens are ledgered under their own classes, never on a token tier (Q128 arch u55,
    // PENDING OWNER; an absent rate prices them at 0).
    match tokenized.billing() {
        Some(Billing::Tokens(t)) => {
            assert_eq!((t.input, t.output), (0, 0));
            assert_eq!(t.open_units.get("image_input_tokens"), Some(&5));
            assert_eq!(t.open_units.get("image_output_tokens"), Some(&272));
        }
        other => panic!("expected the image token classes, got {other:?}"),
    }

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

// ── IrFacts projection + the new-String-field forcing function ───────────────────────────────────────────────────────

use busbar_contract::ir::facts::{ContentItem, IrFacts, OPAQUE_CONTENT_MARKER};
use busbar_contract::operation::OpVerb;

fn screened(items: &[ContentItem<'_>]) -> Vec<String> {
    items
        .iter()
        .map(|i| i.screenable_text().into_owned())
        .collect()
}

/// THE NEW-STRING-FIELD FORCING FUNCTION for `ImageReq`.
///
/// A per-family projection has no compiler exhaustiveness check on a STRUCT's fields (unlike the
/// `IrReq` enum's arms), so a `String` field added later could silently go unprojected and re-blind a
/// gate — the exact hole this change closes. This test constructs `ImageReq` with EVERY field named
/// explicitly (NO `..Default::default()`), so adding a field is a COMPILE ERROR here that forces the
/// author to this test, its comment, and a projection decision. Each caller-text field carries a
/// unique sentinel and is asserted screenable; each binary input is asserted opaque (and its bytes
/// asserted NOT to leak). If you add a `String` field: project it in `image.rs` and assert it here.
#[test]
fn image_projection_covers_every_text_field() {
    let req = ImageReq {
        op: ImageOp::Generate,
        model: "gpt-image-1".into(),
        prompt: Some("PROMPT-TXT".into()),
        negative_prompt: Some("NEG-TXT".into()),
        n: Some(1),
        size: Some(ImageSize::Auto),
        aspect_ratio: Some("16:9".into()),
        image_size_tier: Some("2K".into()),
        quality: Some("high".into()),
        style: Some("vivid".into()),
        response_format: Some("b64_json".into()),
        output_format: Some("png".into()),
        output_compression: Some(80),
        seed: Some(7),
        guidance_scale: Some(7.5),
        steps: Some(30),
        background: Some("transparent".into()),
        input_images: vec!["IMG-BYTES".into()],
        mask: Some("MASK-BYTES".into()),
        mask_prompt: Some("MASK-TXT".into()),
        strength: Some(0.5),
        person_generation: Some("allow".into()),
        moderation: Some("auto".into()),
        add_watermark: Some(false),
        output_uri: Some("gs://bucket/x".into()),
        user: Some("alice".into()),
        weighted_prompts: vec![("WEIGHTED-TXT".into(), 1.0)],
        extra: Default::default(),
    };
    assert_eq!(IrFacts::verb(&req), OpVerb::IMAGE);
    let items = req.content();
    let text = screened(&items).join("\u{0}");
    // Every caller-authored text field is screenable.
    for expected in ["PROMPT-TXT", "NEG-TXT", "MASK-TXT", "WEIGHTED-TXT"] {
        assert!(
            text.contains(expected),
            "gate cannot see image text field: {expected}"
        );
    }
    // The two binary inputs are opaque, present-but-unscreenable — and their bytes never leak.
    let opaque = items
        .iter()
        .filter(|i| matches!(i, ContentItem::Opaque { .. }))
        .count();
    assert_eq!(
        opaque, 2,
        "input_images + mask must each project one opaque item"
    );
    assert!(!text.contains("IMG-BYTES") && !text.contains("MASK-BYTES"));
    assert!(items
        .iter()
        .filter(|i| matches!(i, ContentItem::Opaque { .. }))
        .all(|i| i.screenable_text() == OPAQUE_CONTENT_MARKER));
    // Fields that are NOT caller free-text (geometry/quality/provenance) contribute nothing.
    assert!(!text.contains("gs://bucket"));
}

/// AN IMAGE ANSWER'S REPORTED TOKENS REACH THE UNITS THE DOOR REPORTS, under their own classes and
/// on no token tier (Q128 arch u55, PENDING OWNER): the counts a gpt-image-1 answer states are the
/// ledger lines `image_input_tokens` / `image_output_tokens`, and the four token tiers stay 0, so no
/// `tokens:` cap moves. RED: a count left in the never-billed residual map, or one on a token tier.
#[test]
fn an_image_answers_tokens_reach_the_reported_units_under_their_classes() {
    let answer = ImageResp {
        usage: Some(super::ImageTokens {
            input: Some(5),
            output: Some(272),
        }),
        ..Default::default()
    };
    let Some(Billing::Tokens(t)) = answer.billing() else {
        panic!("a token-reporting image answer is a token usage");
    };
    assert!(
        t.residual_units.is_empty(),
        "nothing is left unledgered: {t:?}"
    );
    let units = crate::exchange::reply::Units::of(Some(&t), std::collections::BTreeMap::new());
    assert_eq!(
        (
            units.tokens_in,
            units.tokens_out,
            units.cache_read,
            units.cache_write
        ),
        (0, 0, 0, 0),
        "no token tier carries an image token"
    );
    assert_eq!(
        units.open,
        std::collections::BTreeMap::from([
            ("image_input_tokens".to_string(), 5),
            ("image_output_tokens".to_string(), 272),
        ])
    );
}
