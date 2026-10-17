// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `EgressPrep` — the resolved-primitives param bag the cross-protocol request seam threads into
//! `IrHandle::prepare_for_egress`. **NEUTRAL:** every field is a primitive (`&str`, `bool`,
//! `Option<u32>`, `u32`, `[u32; 4]`, `Option<usize>`) — it names ZERO concrete IR — and the kernel
//! driver is what *constructs* it from lane config. A shape (DECISIONS #83): relocated,
//! module-path-only, from `busbar-substrate-values::ir::egress_prep`, which re-exports it under its
//! historical path.

/// Resolved primitives for the request handle's `prepare_for_egress` — never a `Lane` or
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
    /// model-gated cache marker to a lane that did not claim it.
    pub prompt_caching_allowed: bool,
    /// The egress writer's `max_cache_control_breakpoints()` (`Some(n)` for a dialect that publishes
    /// a cap, `None` elsewhere — see that method's doc). A capped dialect refuses a request
    /// past this count; the IR carries breakpoints unbounded, so a cross-protocol request can
    /// exceed it. `None` means "no cap to enforce here" — the cap walk below is a no-op.
    pub cache_control_cap: Option<usize>,
    /// True only for an egress lane whose dialect documents a thought-signature sentinel AND whose
    /// host is confirmed to honor it. When true, every tool-use block with no thought signature gets
    /// the dialect's documented sentinel injected, so a cross-protocol tool call (whose history never
    /// had a real signature to echo) is not refused by the backend. A host of the same dialect that
    /// is NOT confirmed to honor the sentinel (a `path_base`-overridden, URL-model lane) is excluded:
    /// a safety requirement, not a nicety. The caller resolves this from lane config before
    /// constructing `EgressPrep`, matching how `reasoning_allowed`/`prompt_caching_allowed` are resolved.
    pub thought_signature_fill: bool,
    /// The egress LANE's declared request-shape capabilities (see [`LaneCaps`]), resolved by the
    /// caller from the lane's provider entry and model patterns exactly as `reasoning_allowed` /
    /// `prompt_caching_allowed` are. The request handle keeps them for the egress write, whose
    /// dialect writer is the only party that knows what each one changes.
    pub lane_caps: LaneCaps,
}

/// Which key a dialect with two spellings of the output-token cap writes a CROSS-PROTOCOL cap under
/// (a same-dialect request keeps the spelling its caller sent). Only one dialect has two
/// (`max_tokens`, `max_completion_tokens`); every other writer ignores this.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaxOutputKey {
    /// The key every compatible host accepts, and what 1.5.5 wrote. The default.
    #[default]
    MaxTokens,
    /// The current key, REQUIRED by some of that dialect's models (they reject `max_tokens`), and
    /// not understood by every compatible host.
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
    /// — the only reasoning on-mode some models accept. False: a reasoning ask is written as
    /// `thinking.budget_tokens`, the form every other model of that dialect accepts.
    pub anthropic_adaptive_thinking: bool,
    /// The lane accepts native structured outputs (`output_config.format`). False: a structured
    /// output directive is written in the dialect's pre-capability form (a forced tool).
    pub native_structured_output: bool,
    /// The lane accepts `reasoning_effort: "none"` / `reasoning.effort: "none"` (the two dialect
    /// spellings) — reasoning switched OFF on a model that reasons by default. False: an Off ask
    /// is omitted on those dialects (a model that does not know the word 400s on it).
    pub reasoning_none: bool,
    /// The lane's model cannot switch thinking off: an Off ask OMITS the dialect's `thinking` member instead of writing `{type:"disabled"}`, which such a
    /// model rejects. False: Off is written as `{type:"disabled"}`.
    pub thinking_always_on: bool,
}

impl LaneCaps {
    /// The capabilities of a lane that declares none — every pre-capability form. The same value as
    /// `LaneCaps::default()`, usable in a `const` (a static upstream table).
    pub const NONE: LaneCaps = LaneCaps {
        max_output_key: MaxOutputKey::MaxTokens,
        anthropic_adaptive_thinking: false,
        native_structured_output: false,
        reasoning_none: false,
        thinking_always_on: false,
    };
}
