// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 1 — THE FAMILY-BLIND VIEW core reads of any plane's request, whatever it speaks.
//!
//! ## Why this is a trait and not an enum, which is the whole point
//!
//! Core's `ir::variant::IrReq` is a CLOSED ENUM: `Chat | Embeddings | Moderation | Image |
//! Transcription | Speech | Rerank | Invoke | Subscribe`. A plugin protocol cannot add a variant to
//! it without editing core — which is exactly the failure `proto/registry.rs`'s own header condemns:
//! *"A REGISTRY WHOSE POPULATION IS A `match` IN CORE HAS NOT REMOVED THE MATCH, IT HAS MOVED IT."*
//! An enum is a match. Protocols-as-plugins is impossible at the IR layer while that enum is the
//! currency, for the same reason it was impossible at the decl layer before the registry.
//!
//! **There is no single shared IR.** LLM, MCP and A2A have THREE DISTINCT IRs: the LLM family's
//! seven variants, MCP's `Invoke`/`Subscribe`, and A2A's own types — which have no `IrReq` variant at
//! all. A2A is therefore not a thought experiment about a plane that does not speak the IR; **it is
//! that plane, in production, today.**
//!
//! So the universal contract is a family-blind VIEW, open by construction because a trait has no
//! fixed variant list. Whatever core must dispatch on becomes DATA the plugin supplies, never a
//! variant matched in core — the same move the protocol registry made for declarations.
//!
//! ## THE GAP THIS CLOSES, and it was found by checking rather than assuming
//!
//! Core already has a seam that CLAIMS this role — `ir::facts::IrFacts`, whose module header calls it
//! *"the family-blind seam"*. It is not. Two of its five methods embed chat vocabulary, and they are
//! the two that carry the payload:
//!
//! * `Shape { turn_count, has_tools, tool_count, text_chars, system_chars, max_tokens }` — that is a
//!   CHAT BODY. "Conversation turns", "tool definitions", "system slot", an output cap in tokens.
//!   None of it means anything to A2A, and nothing about a packet-oriented plane could answer it.
//! * `ContentItem { role: IrRole, slot: Slot, .. }` where `IrRole` is `System | User | Assistant |
//!   Tool` — chat roles, in the universal seam.
//!
//! The other three (`verb`, `wants_stream`, `end_user`) generalise cleanly. A2A implements none of
//! the five, which is the evidence: the trait was shaped by the two planes that happened to
//! implement it.
//!
//! [`PlaneFacts`] keeps the three that generalise and replaces the two that do not with the
//! family-blind quantities core actually needs — a MAGNITUDE for metering and admission, and
//! SCREENABLE MATERIAL for hooks and audit. Roles, slots, turns and tools are a Layer 2 refinement
//! the LLM family adds on top, because they are real and useful *there* and meaningless elsewhere.

/// HOW BIG this unit of work is, in the plane's own unit — the family-blind replacement for
/// `Shape`'s chat counts.
///
/// Core needs a magnitude for pre-admission budget refusal and for metering. It does not need to know
/// whether that magnitude came from conversation turns, packet bytes or connection seconds; it needs
/// a number and the name of what is being counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magnitude {
    /// The plane's own unit: `"tokens"`, `"bytes"`, `"seconds"`, `"calls"`. Operator-visible — it is
    /// what a budget is denominated in and what a metering row records.
    pub unit: &'static str,
    /// The estimated amount, for pre-admission refusal. The real amount is reported afterwards
    /// through [`crate::plane::PlaneMetering::charge`].
    pub amount: u64,
    /// The caller's own cap on this unit, where the protocol has one (an LLM `max_tokens`, a session
    /// byte quota). `None` where the protocol has no such concept.
    pub caller_cap: Option<u64>,
}

/// ONE PIECE OF SCREENABLE MATERIAL — the family-blind replacement for `ContentItem`.
///
/// What a hook, an audit record or a content policy is shown. Deliberately carries NO role and NO
/// slot: those are chat concepts. A `label` is the plane's own word for what this item is
/// (`"message"`, `"tool_arguments"`, `"task_payload"`, `"packet"`), which is strictly more general
/// and loses nothing a consumer can act on.
#[derive(Debug, Clone, PartialEq)]
pub enum Screenable<'a> {
    /// Text the engine may screen.
    Text {
        label: &'a str,
        text: std::borrow::Cow<'a, str>,
    },
    /// Content busbar cannot or must not read. The marker stands in for it and the bytes never leave
    /// the plane — the same contract `ContentItem::Opaque` already has, generalised.
    Opaque {
        label: &'a str,
        marker: &'static str,
    },
}

/// THE LAYER 1 VIEW. Every plane implements this, whatever it speaks.
///
/// This is what governance, metering, admission, hooks and audit read — and it is ALL they read. A
/// plane that speaks no IR (A2A today, a session-oriented plane tomorrow) implements exactly this and
/// nothing else.
pub trait PlaneFacts {
    /// The semantic operation, as the plane's own word. A `&str` rather than a closed `Operation`
    /// enum for the same reason this whole module exists: a closed vocabulary in core is a match in
    /// core. The plane's declaration enumerates its verbs, so the set is still bounded and still safe
    /// as a metric label — bounded BY DECLARATION rather than by a core enum.
    fn verb(&self) -> &str;

    /// Did the caller ask for a streamed response? A duplex session answers `true` and means
    /// "continuously", which is the honest reading rather than a special case.
    fn wants_stream(&self) -> bool;

    /// End-user identifier for provider-side abuse tracking, where the protocol carries one. Caller
    /// identity, never content. `None` is a statement about the protocol, not an omission.
    fn end_user(&self) -> Option<&str>;

    /// How big this work is, in the plane's own unit.
    fn magnitude(&self) -> Magnitude;

    /// The screenable projection, in request order. Grant-gated at the seam that CALLS this, never
    /// here: a projection that decides for itself whether it may be seen is a projection with a
    /// policy in it.
    fn screenable(&self) -> Vec<Screenable<'_>>;
}

#[cfg(test)]
#[path = "../tests/facts_tests.rs"]
mod tests;
