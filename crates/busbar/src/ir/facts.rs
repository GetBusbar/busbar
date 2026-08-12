// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ir::facts` — THE ONE PROJECTION. What the shared pipeline is allowed to know about a request,
//! read from the IR and from nothing else.
//!
//! # Why this module exists, and why it lives HERE
//!
//! busbar has two implementations of "what is the text in this request". One is
//! `proto/*/reader.rs`, which produces the [`IrRequest`] the provider's bytes are ultimately built
//! from. The other is `proxy/hooks.rs::build_prompt_projection`, which re-derives the same answer
//! from the **raw ingress body** with its own `flatten_content`, its own `flatten_gemini_parts` and
//! its own per-dialect dispatch. They disagree — measurably, on twelve fixtures of the differential
//! corpus — and the disagreement is security-shaped rather than untidy: a PII/DLP gate wired as a
//! `prompt: ro` hook screens the first view while the request that goes upstream is built from the
//! second, **so a redactor can pass a request whose real payload it never saw.** One instance of
//! that class has already shipped and been fixed as a one-off.
//!
//! This module is the successor to the second implementation. It lives in `ir/`, beside the IR and
//! not beside the hooks, and **that placement is the design decision rather than a filing
//! preference.** `ir/` is the one module the pipeline is allowed to depend on and the protocols are
//! required to produce; putting the projection here makes "a hook sees the IR" a compile-time fact
//! instead of a convention. A projection type living in `hooks/` is a projection type that can be
//! tempted back toward the wire.
//!
//! **THIS FILE CONTAINS NO EXECUTABLE PROTOCOL COMPARISON AND MUST NEVER CONTAIN ONE.** No
//! `PROTO_*`, no dialect literal in a condition, no `match ingress_protocol`. The protocol is what
//! the IR was parsed FROM; it is a dimension carried as provenance on the item ([`Slot`]), never a
//! branch in what happens after. If a future edit here needs to know which dialect produced a block,
//! the thing being deleted has been rebuilt and the edit is wrong.
//!
//! The few vendor words below are in COMMENTS, and every one of them is the "no branch here" kind —
//! naming a wire origin so a reader can find it, or naming the function this module replaces. That
//! is the same standard `proxy/engine/walk.rs` holds at three literals across 3,767 lines, and it is
//! the standard, not an exception to it: a vendor word a reviewer can read is fine, a vendor word
//! `rustc` can branch on is the defect.
//!
//! # The protocol as a dimension rather than a branch
//!
//! Today the dimension is encoded as a `&str` protocol name that every consumer re-branches on.
//! Here it is carried as **provenance on the item**: [`Slot`] says which turn a piece of content
//! came from and whether it came from the system slot, a turn, a tool call's arguments or a tool
//! result. A consumer reads `slot`; it never reads a protocol name. The protocol determined the slot
//! at parse time — in exactly one `proto/` arm — and never appears again.
//!
//! # Scope of this unit: the LLM family, and NO CALLER
//!
//! [`project`] is the LLM family's walk. [`IrFacts`] is the family-blind seam the pipeline will read
//! through, so a second family (the MCP `tools/call` IR; see [`crate::ir::toolcall`]) implements the
//! trait with its own walk rather than being folded into a superset — one IR per family is a
//! standing rule, because a shared superset across families is a lossless-translation surface
//! between things that never translate.
//!
//! Nothing calls any of this yet. `decide_policy_order`, `build_rewrite_request`,
//! `capture_stage_shape` and `fire_stage_taps` still read the raw-body projection; re-pointing them
//! and deleting it is a later, separate unit, so that this one can land with the entire existing
//! suite green and the divergence merely *measured*. Hence the module-level dead-code allowance
//! below: it comes off in the same commit that wires the first caller, and its removal is that
//! commit's proof.
//!
//! # What this projection does NOT widen, deliberately
//!
//! An [`IrBlock::Image`] contributes no item. That is parity with the projection being replaced
//! (which shows a media-only turn as `{role, text: ""}`), not an oversight: widening image
//! provenance to hook sidecars is a real disclosure decision that deserves its own unit and its own
//! CHANGELOG line, and smuggling it inside a refactor is exactly how a project loses the right to
//! say "refactor" and be believed. The turn itself is never lost — see [`project`]'s empty-turn
//! rule.
#![cfg_attr(not(test), allow(dead_code))]

use crate::ir::{IrBlock, IrRequest, IrRole};
use crate::operation::Operation;
use serde_json::Value;
use std::borrow::Cow;

/// Fixed non-content marker substituted for content busbar cannot read — see
/// [`IrBlock::is_opaque`]. Busbar cannot decrypt provider-encrypted reasoning, so handing a hook the
/// raw bytes has zero screening value AND would be a new information disclosure: the projection is
/// POSTed to an operator-configured sidecar that never received provider ciphertext before.
///
/// It is a PRESENCE signal, not a trust signal, and a consumer must not treat it as one. A client
/// can send a plain text block whose text IS this exact string; the hook seam is upstream of any
/// authentication of content. The correct read is *"there is content here I cannot screen"* —
/// reject or escalate — never *"this text is genuine ciphertext"* and never *"this turn is empty"*.
///
/// The string is BYTE-IDENTICAL to the marker the raw-body projection substitutes today, and
/// `opaque_marker_is_byte_identical_to_the_projection_it_replaces` pins that, so the cutover is not
/// also a wire change for the one shape both implementations already agree on.
pub(crate) const OPAQUE_CONTENT_MARKER: &str = "[busbar:redacted_reasoning]";

/// Label for an opaque reasoning item. A stable, protocol-blind noun: three wire shapes across three
/// dialects land here and the consumer must not be able to tell which.
pub(crate) const LABEL_REASONING: &str = "reasoning";

/// Label for a structured, non-prose content member — the shape a tool result carries when it
/// answers with data rather than prose (one dialect's `{"json": …}` tool-result member reaches the
/// IR as [`IrBlock::Json`]; NO BRANCH HERE, the reader already decided). Named rather than left
/// empty so a screening hook can tell a JSON payload apart from a tool call's arguments without
/// inspecting the value.
pub(crate) const LABEL_JSON: &str = "json";

/// WHERE a piece of content came from — the protocol dimension, carried as provenance.
///
/// This is the piece that makes the move onto the IR a design rather than a rename. A consumer that
/// wants "the system prompt" reads [`Slot::System`]; one that wants turn 3 reads the items whose
/// slot indexes 3. Which wire key the dialect spelled it with (`system` / `systemInstruction` /
/// `instructions`, `messages` / `contents` / `input`) was decided in one `proto/` arm and is gone.
///
/// `ToolArgs` and `ToolResult` carry the index of the TURN they belong to, not an index of their
/// own, so a consumer can attribute a tool call's arguments to the turn that made it — the
/// attribution a guardrail needs and the flat text projection cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    /// The request's system prompt, wherever the dialect put it.
    System,
    /// Ordinary content of the conversation turn at this index into `IrRequest::messages`.
    Turn(usize),
    /// The ARGUMENTS of a tool call made in the turn at this index — attacker-influenceable, sent
    /// upstream verbatim, and projected by nothing before this module existed.
    ToolArgs(usize),
    /// Content of a tool RESULT carried by the turn at this index — typically the largest untrusted
    /// blob in a modern agent request.
    ToolResult(usize),
}

impl Slot {
    /// The conversation turn this slot belongs to, or `None` for the system slot. The one place the
    /// "tool slots are attributed to their turn" rule is written, so no consumer re-derives it.
    pub(crate) fn turn_index(self) -> Option<usize> {
        match self {
            Slot::System => None,
            Slot::Turn(i) | Slot::ToolArgs(i) | Slot::ToolResult(i) => Some(i),
        }
    }
}

/// One content item, borrowed. The shared pipeline walks these; it never knows which protocol
/// produced them and never downcasts.
///
/// Three variants because a screening consumer must be able to tell three things apart, and
/// collapsing any two of them back into a bare string is how the original bypass happened:
/// screenable prose, a structured payload that is content but is not prose, and **content that is
/// present and cannot be shown**. "Nothing here" and "something here I cannot show you" are
/// different answers and a guardrail acts differently on each.
///
/// `role` rides EVERY variant, not only `Text`. An opaque reasoning blob and a tool call's arguments
/// both have an author, and "who wrote this" is the first thing a policy asks — a hook that
/// scrutinizes caller input strictly and trusts assistant output cannot make that distinction from a
/// slot alone.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ContentItem<'a> {
    /// Real, screenable text. Borrowed from the IR wherever the IR owns a `String`.
    Text {
        role: IrRole,
        slot: Slot,
        text: Cow<'a, str>,
    },
    /// A structured payload: a tool call's arguments, or a structured tool-result member. Carried as
    /// the `Value` itself rather than pre-serialized, so a consumer that wants to walk it can, and
    /// one that wants text calls [`ContentItem::screenable_text`].
    Data {
        role: IrRole,
        slot: Slot,
        label: &'a str,
        value: &'a Value,
    },
    /// Content busbar cannot read. `marker` stands in for it; the bytes never leave the IR.
    Opaque {
        role: IrRole,
        slot: Slot,
        label: &'static str,
        marker: &'static str,
    },
}

impl ContentItem<'_> {
    /// Who authored this content.
    pub(crate) fn role(&self) -> IrRole {
        match self {
            ContentItem::Text { role, .. }
            | ContentItem::Data { role, .. }
            | ContentItem::Opaque { role, .. } => *role,
        }
    }

    /// Where this content came from.
    pub(crate) fn slot(&self) -> Slot {
        match self {
            ContentItem::Text { slot, .. }
            | ContentItem::Data { slot, .. }
            | ContentItem::Opaque { slot, .. } => *slot,
        }
    }

    /// The text a screening consumer is shown for this item — and, by construction, the text the
    /// `total_chars` SIZE signal counts.
    ///
    /// **This is the single definition of "what a hook sees", and that is the point.** The two
    /// tripwires this design supersedes (`system_text_chars_counts_block_arrays` and
    /// `size_signal_and_projection_agree_on_reasoning`) exist because a size signal and a content
    /// projection were computed by two functions that could drift. Here [`Shape::text_chars`] is a
    /// sum over this method, so they cannot: there is nothing left for them to disagree about.
    pub(crate) fn screenable_text(&self) -> Cow<'_, str> {
        match self {
            ContentItem::Text { text, .. } => Cow::Borrowed(text.as_ref()),
            ContentItem::Data { value, .. } => Cow::Owned(value.to_string()),
            ContentItem::Opaque { marker, .. } => Cow::Borrowed(marker),
        }
    }
}

/// Counts and sizes. NO content — this is the bucket every hook gets whether or not it holds a
/// content grant, so nothing in it may be derived from what the text SAYS.
///
/// One field per signal the hook wire already carries (`message_count`, `has_tools`, `total_chars`,
/// `max_tokens`), and no more: a speculative signal here is a wire key an operator will one day
/// depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shape {
    /// Conversation turns, counted on the IR. **This is not the wire `messages.len()`** — every
    /// reader hoists system-role turns into the system slot, so a body that carries its system
    /// prompt in-band counts one lower here than it does on the wire. That difference is the
    /// divergence being fixed, and it is operator-visible.
    pub(crate) turn_count: usize,
    /// Did the caller declare any tools?
    pub(crate) has_tools: bool,
    /// Total chars of everything a content-granted hook would be shown, system slot included.
    /// Counts TEXT, never the separators a consumer joins items with — so a flattened rendering can
    /// be longer than this by one char per join, exactly as it is today.
    pub(crate) text_chars: usize,
    /// The caller's output cap, normalized by the reader from whichever field its dialect spells it
    /// in. Reading this from the IR is a FIX, not merely a move: the raw-body projection is
    /// dialect-aware for exactly one dialect's spelling and returns `None` for a body that spells
    /// the cap in a nested config object, silently blinding any routing policy keyed on it.
    pub(crate) max_tokens: Option<u32>,
}

/// Everything the SHARED pipeline needs to know about any request on any protocol.
///
/// The pipeline holds the request behind this trait and nothing else. Nothing here is model-shaped,
/// nothing downcasts, and no method returns a wire body. A protocol family joins by implementing it;
/// govern, hook, select, dispatch, classify, meter and audit then span the new family with no work
/// in any of them, which is the whole payoff and also the acceptance test.
///
/// **`target()` is deliberately ABSENT.** The design sketches one ("pool | mcp server | agent — the
/// container name"), and it belongs on this trait eventually — but the container is a ROUTING fact
/// resolved outside the IR, and [`IrRequest`] cannot answer it, so the only thing that could land
/// today is a stub returning `""` that every caller would have to know not to trust. A method that
/// lies is worse than a method that is missing; it lands with the first implementer that actually
/// knows the answer, additively.
pub(crate) trait IrFacts {
    /// The semantic operation — the same closed vocabulary the metrics label and the `paths:` config
    /// key use, so a consumer that switches on it is switching on something already enumerated.
    fn verb(&self) -> Operation;

    /// Did the caller ask to stream?
    fn wants_stream(&self) -> bool;

    /// End-user identifier for provider-side abuse tracking, normalized by the reader from whichever
    /// field its dialect spells it in. Rides the `user: ro` grant; it is caller identity, not
    /// content.
    fn end_user(&self) -> Option<&str>;

    /// Counts and sizes. No content.
    fn shape(&self) -> Shape;

    /// The content projection, in request order. Grant-gated at the seam that CALLS this, never
    /// here: a projection that decides for itself whether it may be seen is a projection with a
    /// policy in it.
    fn content(&self) -> Vec<ContentItem<'_>>;
}

impl IrFacts for IrRequest {
    fn verb(&self) -> Operation {
        Operation::Chat
    }

    fn wants_stream(&self) -> bool {
        self.stream
    }

    fn end_user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    fn shape(&self) -> Shape {
        Shape {
            turn_count: self.messages.len(),
            has_tools: !self.tools.is_empty(),
            // Summed over the SAME items a content-granted hook is shown. See
            // `ContentItem::screenable_text` for why this is a sum and not a second walk.
            text_chars: project(self)
                .iter()
                .map(|i| i.screenable_text().chars().count())
                .sum(),
            max_tokens: self.max_tokens,
        }
    }

    fn content(&self) -> Vec<ContentItem<'_>> {
        project(self)
    }
}

/// THE PROJECTION: walk one chat-family IR request into the flat, ordered, protocol-blind item
/// stream.
///
/// System slot first, then each turn in order; within a turn, blocks in the order the reader
/// produced them, which is the order the writer will send them. A consumer reconstructs a flat
/// per-turn rendering by grouping on [`Slot::turn_index`] and joining
/// [`ContentItem::screenable_text`].
///
/// # The empty-turn rule
///
/// **A turn that yields no items still yields one empty [`ContentItem::Text`].** A media-only turn
/// must not vanish: a screening hook that sees three turns where the provider sees four has been
/// told the request is something it is not, and "a turn I could not read anything from" is a fact
/// worth stating. The old projection held this as an index-alignment contract against the wire
/// `messages` array; that exact contract cannot survive the move (readers hoist system turns, and
/// one dialect's item can produce zero or one messages), but the PROPERTY it existed to protect —
/// every turn is visible — survives here, expressed against `IrRequest::messages` instead.
///
/// # Opacity is checked BEFORE `text` is read, never after
///
/// [`IrBlock::Thinking`] is the one block whose `text` is not always plaintext: for two dialects'
/// redacted shapes it holds the provider CIPHERTEXT itself, and for a third it is empty while the
/// blob rides `signature`. A naive `if redacted { marker } else { text }` gets the third case wrong
/// in the worst direction — it shows a hook an EMPTY turn for a request the provider receives in
/// full, which is a policy-enforcement-point bypass and is the original bug restored.
/// [`IrBlock::is_opaque`] is the one place that knows all three shapes, and it is asked first.
pub(crate) fn project(req: &IrRequest) -> Vec<ContentItem<'_>> {
    let mut out = Vec::new();
    walk(&req.system, IrRole::System, None, Slot::System, &mut out);
    for (i, m) in req.messages.iter().enumerate() {
        let before = out.len();
        walk(&m.content, m.role, Some(i), Slot::Turn(i), &mut out);
        if out.len() == before {
            // The empty-turn rule. See this function's doc comment.
            out.push(ContentItem::Text {
                role: m.role,
                slot: Slot::Turn(i),
                text: Cow::Borrowed(""),
            });
        }
    }
    out
}

/// One level of the block walk. `turn` is `None` for the system slot, where a tool call or tool
/// result has no turn to be attributed to and keeps the slot it was reached through.
fn walk<'a>(
    blocks: &'a [IrBlock],
    role: IrRole,
    turn: Option<usize>,
    slot: Slot,
    out: &mut Vec<ContentItem<'a>>,
) {
    for b in blocks {
        match b {
            IrBlock::Text { text, .. } => out.push(ContentItem::Text {
                role,
                slot,
                text: Cow::Borrowed(text.as_str()),
            }),
            IrBlock::Thinking { text, .. } => {
                if b.is_opaque() {
                    out.push(ContentItem::Opaque {
                        role,
                        slot,
                        label: LABEL_REASONING,
                        marker: OPAQUE_CONTENT_MARKER,
                    });
                } else {
                    // Reasoning busbar CAN read is ordinary screenable content and is shown as such:
                    // a client replaying a multi-turn body sends this text to the provider, so a
                    // gate that cannot see it is a gate with a hole in it.
                    out.push(ContentItem::Text {
                        role,
                        slot,
                        text: Cow::Borrowed(text.as_str()),
                    });
                }
            }
            IrBlock::ToolUse { name, input, .. } => out.push(ContentItem::Data {
                role,
                slot: turn.map_or(slot, Slot::ToolArgs),
                label: name.as_str(),
                value: input,
            }),
            IrBlock::ToolResult { content, .. } => walk(
                content,
                role,
                turn,
                turn.map_or(slot, Slot::ToolResult),
                out,
            ),
            // Structurally text-less and DELIBERATELY not widened here — see the module header.
            IrBlock::Image { .. } => {}
            IrBlock::Json(v) => out.push(ContentItem::Data {
                role,
                slot,
                label: LABEL_JSON,
                value: v,
            }),
            // No catch-all arm, on purpose: a new IR block variant must be decided HERE, in a diff a
            // reviewer reads, rather than defaulting to invisible. Invisible is the failure
            // direction this module exists to close.
        }
    }
}

#[cfg(test)]
#[path = "tests/facts_tests.rs"]
mod tests;
