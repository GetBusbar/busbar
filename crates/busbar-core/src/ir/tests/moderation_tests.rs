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
