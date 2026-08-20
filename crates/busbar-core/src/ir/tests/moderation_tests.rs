// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/moderation.rs`.

use super::*;

#[test]
fn results_are_positional_and_carry_flags_and_scores() {
    let r = ModerationResult {
        flagged: true,
        categories: [("violence".to_string(), true)].into_iter().collect(),
        category_scores: [("violence".to_string(), 0.97)].into_iter().collect(),
        applied_input_types: [("violence".to_string(), vec!["text".to_string()])]
            .into_iter()
            .collect(),
    };
    let resp = ModerationResp {
        results: vec![r],
        ..Default::default()
    };
    assert!(resp.results[0].flagged);
    assert_eq!(resp.results[0].category_scores["violence"], 0.97);
    assert_eq!(
        resp.results[0].applied_input_types["violence"],
        vec!["text".to_string()]
    );
}

#[test]
fn request_holds_mixed_text_and_image_inputs() {
    let req = ModerationReq {
        model: "omni-moderation-latest".into(),
        input: vec![
            ModerationInput::Text("hi".into()),
            ModerationInput::ImageUrl("https://example/i.png".into()),
        ],
        ..Default::default()
    };
    assert_eq!(req.input.len(), 2);
}

// ── IrFacts projection (close-non-chat-gate-blindness) ───────────────────────────────────────────

use crate::ir::facts::{ContentItem, IrFacts, OPAQUE_CONTENT_MARKER};
use crate::operation::Operation;

#[test]
fn moderation_projects_text_and_marks_image_url_opaque() {
    let req = ModerationReq {
        model: "omni-moderation-latest".into(),
        input: vec![
            ModerationInput::Text("screen this text".into()),
            ModerationInput::ImageUrl("https://example.com/x.png".into()),
        ],
        ..Default::default()
    };
    assert_eq!(IrFacts::verb(&req), Operation::MODERATION);
    let items = req.content();
    assert_eq!(items.len(), 2);
    // The text is screenable; the ImageUrl is opaque, not the empty projection it was before (MAJOR-5).
    assert!(matches!(items[0], ContentItem::Text { .. }));
    assert_eq!(items[0].screenable_text(), "screen this text");
    assert!(matches!(items[1], ContentItem::Opaque { .. }));
    assert_eq!(items[1].screenable_text(), OPAQUE_CONTENT_MARKER);
    // The image URL bytes never leak into the gate view.
    assert!(!items[1].screenable_text().contains("example.com"));
    assert_eq!(
        req.shape().text_chars,
        "screen this text".len() + OPAQUE_CONTENT_MARKER.len()
    );
}
