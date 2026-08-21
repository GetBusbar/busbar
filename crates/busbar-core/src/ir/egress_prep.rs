// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `EgressPrep` — the resolved-primitives param bag the cross-protocol request seam threads into
//! `IrHandle::prepare_for_egress`. **NEUTRAL and CORE-RETAINED (design (b)):** every field is a
//! primitive (`&str`, `bool`, `Option<u32>`, `u32`, `[u32; 4]`, `Option<usize>`) — it names ZERO
//! concrete LLM IR — and the core driver (`proxy/wire.rs`) is what *constructs* it from lane config.
//! Relocated here from `ir::variant` at the G6 A4b dissolve, when `variant` (the `IrReq`/`IrResp`
//! hub) was removed; the freeze witness excludes it for exactly this reason (cf. IrError/Slot/Shape).

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
}
