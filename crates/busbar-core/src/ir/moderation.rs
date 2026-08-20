// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Moderation IR. The degenerate operation: OpenAI-only (K=1), no
//! cross-provider superset needed — no other provider ships a moderations endpoint — so this models
//! OpenAI's shape exactly. Split request/response per. Flat-fee: no `Billing` on the response
//! (`IrResp::usage()` returns `Billing::Flat` for moderation).

use crate::lossless::SourceScopedExtra;
use std::collections::BTreeMap;

/// A moderation input item — text or an image reference (omni-moderation accepts both).
#[derive(Debug, Clone, PartialEq)]
pub enum ModerationInput {
    Text(String),
    ImageUrl(String),
}

/// Moderation request IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModerationReq {
    pub model: String,
    pub input: Vec<ModerationInput>,
    /// Source-protocol-namespaced extras. Empty for OpenAI (the only provider), but present for
    /// uniformity so the codec pattern is identical across ops.
    pub extra: SourceScopedExtra,
}

/// THE MODERATION FAMILY'S WALK — this IR's answer to [`crate::ir::facts::IrFacts`]. Moderation
/// input is EXACTLY the content to classify, so it is exactly what a screening gate must see: a
/// `ModerationInput::Text` is caller free-text → [`crate::ir::facts::ContentItem::Text`]; a
/// `ModerationInput::ImageUrl` is an image reference busbar does not fetch or render →
/// [`crate::ir::facts::ContentItem::Opaque`] (MAJOR-5; chat-parity, present-but-unscreenable).
impl crate::ir::facts::IrFacts for ModerationReq {
    fn verb(&self) -> crate::operation::Operation {
        crate::operation::Operation::MODERATION
    }

    fn wants_stream(&self) -> bool {
        false
    }

    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        let items = crate::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = crate::ir::facts::Shape::counts_over(&items);
        crate::ir::facts::Shape {
            turn_count: 1,
            has_tools: false,
            tool_count: 0,
            text_chars,
            system_chars,
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        use crate::ir::facts::{ContentItem, Slot, OPAQUE_CONTENT_MARKER};
        use std::borrow::Cow;
        self.input
            .iter()
            .map(|item| match item {
                ModerationInput::Text(t) => ContentItem::Text {
                    author: "user",
                    slot: Slot::Turn(0),
                    text: Cow::Borrowed(t.as_str()),
                },
                ModerationInput::ImageUrl(_) => ContentItem::Opaque {
                    author: "user",
                    slot: Slot::Turn(0),
                    label: "image_url",
                    marker: OPAQUE_CONTENT_MARKER,
                },
            })
            .collect()
    }
}

/// One per-input moderation verdict. Positional: `results[i]` corresponds to `input[i]`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModerationResult {
    pub flagged: bool,
    pub categories: BTreeMap<String, bool>,
    pub category_scores: BTreeMap<String, f64>,
    /// Per-category, which input modalities triggered it (omni-moderation: `["text"]` / `["image"]`).
    pub applied_input_types: BTreeMap<String, Vec<String>>,
}

/// Moderation response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModerationResp {
    pub id: Option<String>,
    pub model: Option<String>,
    pub results: Vec<ModerationResult>,
    pub extra: SourceScopedExtra,
}

#[cfg(test)]
#[path = "tests/moderation_tests.rs"]
mod tests;
