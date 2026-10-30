// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A provider entry's LANE-CAPABILITY keys, parsed and validated. A provider entry (catalog
//! definition, deployment, resolved section) carries the keys `max_output_key`,
//! `anthropic_adaptive_thinking`, `native_structured_output` and `model_capabilities`; a
//! `model_capabilities` rule additionally takes the per-model keys `reasoning_none` and
//! `thinking_always_on`. The kernel holds them as these values and never reads them. A bad value
//! (an unknown `max_output_key` spelling, an unknown key inside a `model_capabilities` rule) is
//! refused by THIS module's `Deserialize` while the config is parsed at boot, before anything is
//! built.
//!
//! This file is config grammar: the config-schema gate tracks it, so the two `Deserialize` shapes
//! below are frozen additive-only exactly as they were while the kernel declared them.

use serde::{Deserialize, Serialize};

/// The spelling of a cross-protocol output-token cap a provider expects (see
/// `ProviderDef::max_output_key`).
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaxOutputKeyCfg {
    /// `max_tokens` — the default.
    MaxTokens,
    /// `max_completion_tokens`.
    MaxCompletionTokens,
}

/// One per-model capability rule (see `ProviderDef::model_capabilities`). Every key but `models` is
/// optional; an absent key leaves the value the provider level (or the default) set.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilities {
    /// Wire-model globs (`*` matches any run of characters), e.g. `claude-opus-4-7*`.
    pub models: Vec<String>,
    /// See `ProviderDef::max_output_key`.
    #[serde(default)]
    pub max_output_key: Option<MaxOutputKeyCfg>,
    /// See `ProviderDef::anthropic_adaptive_thinking`.
    #[serde(default)]
    pub anthropic_adaptive_thinking: Option<bool>,
    /// See `ProviderDef::native_structured_output`.
    #[serde(default)]
    pub native_structured_output: Option<bool>,
    /// The model accepts `reasoning_effort: "none"` (see [`LaneCaps::reasoning_none`]). Per-model
    /// only: a fact about one model generation, never about a whole provider.
    #[serde(default)]
    pub reasoning_none: Option<bool>,
    /// The model cannot switch thinking off (see [`LaneCaps::thinking_always_on`]). Per-model only.
    #[serde(default)]
    pub thinking_always_on: Option<bool>,
}
