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
