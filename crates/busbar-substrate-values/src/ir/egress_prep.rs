// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `EgressPrep` — the resolved-primitives param bag the cross-protocol request seam threads into
//! `IrHandle::prepare_for_egress`. **NEUTRAL:** every field is a primitive (`&str`, `bool`,
//! `Option<u32>`, `u32`, `[u32; 4]`, `Option<usize>`) — it names ZERO concrete LLM IR — and the core
//! driver (`proxy/wire.rs`) is what *constructs* it from lane config. Relocated DOWN from
//! `busbar-core` (`ir::egress_prep`) at Batch C-1 so a plane crate names it without reaching into
//! `busbar-core`; core re-exports it from its historical path (`busbar_kernel::ir::egress_prep`).

/// Resolved primitives for [`crate::ir::handle::IrHandle::prepare_for_egress`] — never a `Lane` or
/// config handle.
pub struct EgressPrep<'a> {
    pub ingress_protocol: &'a str,
    pub egress_requires_max_tokens: bool,
    pub lane_default_max_tokens: Option<u32>,
    pub global_default_max_tokens: u32,
    /// The per-lane reasoning capability gate: the effective `reasoning` flag for THIS attempt's
    /// lane (pool-member override wins over the model-level flag). When false and the request
    /// carries a reasoning ask, the ask is CLEARED here with a warn — the one place the gate
    /// lives, so no writer can ever send a thinking param to a lane that did not claim it.
    pub reasoning_allowed: bool,
    /// The resolved effort-word → budget table (limits.reasoning_effort_budgets), stamped onto the
    /// IR for writers to project words ↔ numbers with the operator's numbers.
    pub reasoning_budgets: [u32; 4],
    /// The prompt-cache gate: `lane.prompt_caching || !writer.cache_markers_model_gated()`,
    /// resolved by the caller. When false and the request carries `cache_control` breakpoints,
    /// they are CLEARED here with a warn — the one place the gate lives, so no writer can emit a
    /// model-gated cache marker (Bedrock `cachePoint`) to a lane that did not claim it.
    pub prompt_caching_allowed: bool,
    /// The egress writer's `max_cache_control_breakpoints()` (`Some(4)` for Anthropic, `None`
    /// elsewhere — see that method's doc for why Bedrock is deliberately excluded). Anthropic 400s
    /// past this count; the IR carries breakpoints unbounded, so a cross-protocol request can
    /// exceed it. `None` means "no cap to enforce here" — the cap walk below is a no-op.
    pub cache_control_cap: Option<usize>,
    /// True only for a Gemini AI-Studio egress lane — NEVER for Vertex. When true, every
    /// `IrBlock::ToolUse` with no `thought_signature` gets Google's documented sentinel
    /// (`GEMINI_SKIP_THOUGHT_SIGNATURE`) injected so a cross-protocol `functionCall` part (whose
    /// history never had a real signature to echo) doesn't 400 the Gemini 3 backend. Vertex AI's
    /// Gemini surface is NOT confirmed to honor the same sentinel-bypass value — there are real
    /// reports of Vertex rejecting it with a 400 — so excluding Vertex lanes here is a safety
    /// requirement, not a nicety. The caller resolves this from lane config (protocol == Gemini AND
    /// no `path_base` override, i.e. not a Vertex-style URL-model lane) before constructing
    /// `EgressPrep`, matching how `reasoning_allowed`/`prompt_caching_allowed` are resolved.
    pub thought_signature_fill: bool,
    /// The egress LANE's declared request-shape capabilities (see [`LaneCaps`]), resolved by the
    /// caller from the lane's provider entry and model patterns exactly as `reasoning_allowed` /
    /// `prompt_caching_allowed` are. The request handle keeps them for the egress write, whose
    /// dialect writer is the only party that knows what each one changes.
    pub lane_caps: LaneCaps,
}

/// Which key a dialect with two spellings of the output-token cap writes a CROSS-PROTOCOL cap under
/// (a same-dialect request keeps the spelling its caller sent). Only the OpenAI Chat Completions
/// dialect has two (`max_tokens`, `max_completion_tokens`); every other writer ignores this.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaxOutputKey {
    /// The key every OpenAI-compatible host accepts, and what 1.5.5 wrote. The default.
    #[default]
    MaxTokens,
    /// The current key, REQUIRED by OpenAI's o-series / gpt-5 models (they reject `max_tokens`),
    /// and not understood by every OpenAI-compatible host.
    MaxCompletionTokens,
}

/// A lane's declared REQUEST-SHAPE capabilities: facts about what one upstream model accepts that a
/// dialect writer cannot see from the request (the writer never sees the lane or its model). Each is
/// declared per provider entry, with per-model patterns, in the provider catalog, and each DEFAULT is
/// the form busbar sent before the capability existed, so a lane that declares nothing keeps
/// receiving exactly the bytes it always did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneCaps {
    /// See [`MaxOutputKey`].
    pub max_output_key: MaxOutputKey,
    /// The lane accepts adaptive thinking (`thinking:{type:"adaptive"}` plus `output_config.effort`)
    /// — the only reasoning on-mode some Claude models accept. False: a reasoning ask is written as
    /// `thinking.budget_tokens`, the form every other Claude model accepts.
    pub anthropic_adaptive_thinking: bool,
    /// The lane accepts native structured outputs (`output_config.format`). False: a structured
    /// output directive is written in the dialect's pre-capability form (a forced tool on the
    /// Anthropic wire).
    pub native_structured_output: bool,
}

impl LaneCaps {
    /// The capabilities of a lane that declares none — every pre-capability form. The same value as
    /// `LaneCaps::default()`, usable in a `const` (a static upstream table).
    pub const NONE: LaneCaps = LaneCaps {
        max_output_key: MaxOutputKey::MaxTokens,
        anthropic_adaptive_thinking: false,
        native_structured_output: false,
    };
}
