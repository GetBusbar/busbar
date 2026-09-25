// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A provider entry's LANE-CAPABILITY keys — the egress writer's own vocabulary, parsed, validated
//! and resolved here, beside [`LaneCaps`] and `EgressPrep`, never in the kernel (architect ruling
//! LANECAPS-MOVE; spec Part 1 and #43: the owner of a shape declares it).
//!
//! A provider entry (catalog definition, deployment, resolved section) carries the keys
//! `max_output_key`, `anthropic_adaptive_thinking`, `native_structured_output` and
//! `model_capabilities`; a `model_capabilities` rule additionally takes the per-model keys
//! `reasoning_none` and `thinking_always_on`. The kernel holds them as these values and never reads them:
//! it lays the entry's declaration beside the lane's wire model and asks [`resolve_lane_caps`] for
//! the [`LaneCaps`] the egress writer receives. A bad value (an unknown `max_output_key` spelling,
//! an unknown key inside a `model_capabilities` rule) is refused by THIS module's `Deserialize`
//! while the config is parsed at boot, before anything is built.
//!
//! This file is config grammar: the config-schema gate tracks it, so the two `Deserialize` shapes
//! below are frozen additive-only exactly as they were while the kernel declared them.

use serde::Deserialize;

use super::egress_prep::{LaneCaps, MaxOutputKey};

/// The spelling of a cross-protocol output-token cap a provider expects (see
/// `ProviderDef::max_output_key`).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaxOutputKeyCfg {
    /// `max_tokens` — the default.
    MaxTokens,
    /// `max_completion_tokens`.
    MaxCompletionTokens,
}

/// One per-model capability rule (see `ProviderDef::model_capabilities`). Every key but `models` is
/// optional; an absent key leaves the value the provider level (or the default) set.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
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

/// The three capabilities a provider entry declares at PROVIDER level (each `None` = not declared),
/// named field by field so the caller cannot hand one capability's value to another.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderLaneCaps {
    /// The entry's `max_output_key`.
    pub max_output_key: Option<MaxOutputKeyCfg>,
    /// The entry's `anthropic_adaptive_thinking`.
    pub anthropic_adaptive_thinking: Option<bool>,
    /// The entry's `native_structured_output`.
    pub native_structured_output: Option<bool>,
}

/// The lane capabilities of one provider entry for one wire model: every default is the
/// pre-capability form; the provider-level values apply, then the FIRST matching model rule.
pub fn resolve_lane_caps(
    provider: ProviderLaneCaps,
    model_capabilities: &[ModelCapabilities],
    wire_model: &str,
) -> LaneCaps {
    let key = |k: MaxOutputKeyCfg| match k {
        MaxOutputKeyCfg::MaxTokens => MaxOutputKey::MaxTokens,
        MaxOutputKeyCfg::MaxCompletionTokens => MaxOutputKey::MaxCompletionTokens,
    };
    let mut caps = LaneCaps::default();
    if let Some(k) = provider.max_output_key {
        caps.max_output_key = key(k);
    }
    if let Some(b) = provider.anthropic_adaptive_thinking {
        caps.anthropic_adaptive_thinking = b;
    }
    if let Some(b) = provider.native_structured_output {
        caps.native_structured_output = b;
    }
    if let Some(rule) = model_capabilities
        .iter()
        .find(|r| r.models.iter().any(|g| glob_match(g, wire_model)))
    {
        if let Some(k) = rule.max_output_key {
            caps.max_output_key = key(k);
        }
        if let Some(b) = rule.anthropic_adaptive_thinking {
            caps.anthropic_adaptive_thinking = b;
        }
        if let Some(b) = rule.native_structured_output {
            caps.native_structured_output = b;
        }
        if let Some(b) = rule.reasoning_none {
            caps.reasoning_none = b;
        }
        if let Some(b) = rule.thinking_always_on {
            caps.thinking_always_on = b;
        }
    }
    caps
}

/// `*`-only glob: `*` matches any (possibly empty) run of characters; every other character matches
/// itself. Enough for model-family patterns (`claude-opus-4-7*`, `*sonnet-5*`) without a dependency.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
#[path = "../tests/lane_caps_tests.rs"]
mod tests;
