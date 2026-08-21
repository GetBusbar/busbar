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
//! # Scope: the LLM family's walk, behind a seam two families now implement
//!
//! [`project`] is the LLM family's walk. [`IrFacts`] is the family-blind seam the pipeline reads
//! through, so a second family (the invocation IR; see [`crate::ir::invoke`]) implements the trait
//! with its own walk rather than being folded into a superset — one IR per family is a standing
//! rule, because a shared superset across families is a lossless-translation surface between things
//! that never translate.
//!
//! **THE SEAM HAS PRODUCTION CALLERS, AND THAT IS WHY THERE IS NO DEAD-CODE ALLOWANCE HERE.** This
//! header used to say "nothing calls any of this yet" and to carry a module-level
//! `allow(dead_code)`, on the promise that the allowance "comes off in the same commit that wires
//! the first caller, and its removal is that commit's proof". The callers landed — `proxy/hooks.rs`
//! reads requests through this trait, `hooks/gate.rs` takes it as the only thing a gate is shown,
//! and `ir/invoke.rs` is the second family implementing it — but the promise was not kept and the
//! allowance outlived the condition it was written for. Taking it off IS the proof, one unit late:
//! the compiler now has to agree that every item here is reachable.
//!
//! # What this projection does NOT widen, deliberately
//!
//! An [`IrBlock::Image`] contributes no item. That is parity with the projection being replaced
//! (which shows a media-only turn as `{role, text: ""}`), not an oversight: widening image
//! provenance to hook sidecars is a real disclosure decision that deserves its own unit and its own
//! CHANGELOG line, and smuggling it inside a refactor is exactly how a project loses the right to
//! say "refactor" and be believed. The turn itself is never lost — see [`project`]'s empty-turn
//! rule.

// NOTE: the `IrRequest` projection (`impl IrFacts for IrRequest` + `project`) relocated to the
// busbar-llm plugin (`ir::facts_impl`) at the G6 A4b dissolve — this neutral module names no concrete
// IR type in code anymore (doc-link mentions of `IrBlock`/`IrRequest`/`IrRole` resolve only in the
// test build that re-includes the plugin's IR). The trait, `Slot`/`ContentItem`/`Shape` and
// `NeutralFacts` stay here as the operation-blind projection surface.
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
pub const OPAQUE_CONTENT_MARKER: &str = "[busbar:redacted_reasoning]";

/// Label for an opaque reasoning item. A stable, protocol-blind noun: three wire shapes across three
/// dialects land here and the consumer must not be able to tell which.
pub const LABEL_REASONING: &str = "reasoning";

/// Label for a structured, non-prose content member — the shape a tool result carries when it
/// answers with data rather than prose (one dialect's `{"json": …}` tool-result member reaches the
/// IR as [`IrBlock::Json`]; NO BRANCH HERE, the reader already decided). Named rather than left
/// empty so a screening hook can tell a JSON payload apart from a tool call's arguments without
/// inspecting the value.
pub const LABEL_JSON: &str = "json";

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
pub enum Slot {
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
    pub fn turn_index(self) -> Option<usize> {
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
pub enum ContentItem<'a> {
    /// Real, screenable text. Borrowed from the IR wherever the IR owns a `String`.
    Text {
        author: &'static str,
        slot: Slot,
        text: Cow<'a, str>,
    },
    /// A structured payload: a tool call's arguments, or a structured tool-result member. Carried as
    /// the `Value` itself rather than pre-serialized, so a consumer that wants to walk it can, and
    /// one that wants text calls [`ContentItem::screenable_text`].
    Data {
        author: &'static str,
        slot: Slot,
        label: &'a str,
        value: &'a Value,
    },
    /// Content busbar cannot read. `marker` stands in for it; the bytes never leave the IR.
    Opaque {
        author: &'static str,
        slot: Slot,
        label: &'static str,
        marker: &'static str,
    },
}

impl ContentItem<'_> {
    /// Who authored this content — an OPAQUE label the producing walk chose, never a core enum. The
    /// LLM walk uses `"system"`/`"user"`/`"assistant"`/`"tool"` (the strings the hook wire has always
    /// carried); a non-chat plane uses its own words. Core reads this as the hook-wire bucket label a
    /// screening consumer is shown and **branches on nothing** — the label carries no protocol.
    pub fn author(&self) -> &'static str {
        match self {
            ContentItem::Text { author, .. }
            | ContentItem::Data { author, .. }
            | ContentItem::Opaque { author, .. } => author,
        }
    }

    /// Where this content came from.
    pub fn slot(&self) -> Slot {
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
    pub fn screenable_text(&self) -> Cow<'_, str> {
        match self {
            ContentItem::Text { text, .. } => Cow::Borrowed(text.as_ref()),
            ContentItem::Data { value, .. } => Cow::Owned(value.to_string()),
            ContentItem::Opaque { marker, .. } => Cow::Borrowed(marker),
        }
    }

    /// A collision-resistant identity for "have I screened this exact piece before" — over the author
    /// label, the slot (kind + index, so the SAME text in a DIFFERENT slot is a distinct piece a
    /// guardrail must re-see), and the screenable text.
    ///
    /// The fields are LENGTH-PREFIX framed before hashing (the same discipline `audit::Digest` uses),
    /// so `("a","b")` can never hash-collide with `("ab","")`. A collision here would let one session's
    /// cleared-set skip-screen a *different* piece — a security-adjacent skip (design D4) — which is
    /// why this is a full SHA-256 over framed bytes, not a 64-bit fast hash. Used by the gate's
    /// incremental-scan tenant of [`crate::session`]: the digest is what a session's scanned-set holds.
    ///
    /// NOTE: an [`ContentItem::Opaque`] piece digests its MARKER, not real content — the caller must
    /// never cache an opaque piece as "cleared" (it is a presence signal, not screenable content); the
    /// digest is defined here for uniformity, and the caller enforces the never-cache-opaque rule.
    pub fn screening_digest(&self) -> String {
        fn framed(buf: &mut Vec<u8>, bytes: &[u8]) {
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(bytes);
        }
        let (slot_kind, slot_idx): (u8, u64) = match self.slot() {
            Slot::System => (0, 0),
            Slot::Turn(i) => (1, i as u64),
            Slot::ToolArgs(i) => (2, i as u64),
            Slot::ToolResult(i) => (3, i as u64),
        };
        let text = self.screenable_text();
        let mut buf = Vec::new();
        framed(&mut buf, &[slot_kind]);
        framed(&mut buf, &slot_idx.to_be_bytes());
        framed(&mut buf, self.author().as_bytes());
        framed(&mut buf, text.as_bytes());
        busbar_api::sha256_hex(&buf)
    }
}

/// Counts and sizes. NO content — this is the bucket every hook gets whether or not it holds a
/// content grant, so nothing in it may be derived from what the text SAYS.
///
/// One field per signal the hook wire already carries (`message_count`, `has_tools`, `total_chars`,
/// `max_tokens`), and no more: a speculative signal here is a wire key an operator will one day
/// depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Shape {
    /// Conversation turns, counted on the IR. **This is not the wire `messages.len()`** — every
    /// reader hoists system-role turns into the system slot, so a body that carries its system
    /// prompt in-band counts one lower here than it does on the wire. That difference is the
    /// divergence being fixed, and it is operator-visible.
    pub turn_count: usize,
    /// Did the caller declare any tools?
    pub has_tools: bool,
    /// How many tool definitions the caller declared, counted on the IR — so a dialect that spells
    /// its tool list differently counts the same as every other.
    pub tool_count: usize,
    /// Total chars of everything a content-granted hook would be shown, system slot included.
    /// Counts TEXT, never the separators a consumer joins items with — so a flattened rendering can
    /// be longer than this by one char per join, exactly as it is today.
    pub text_chars: usize,
    /// Chars of the SYSTEM slot alone, wherever the dialect put the system prompt. A subset of
    /// [`Shape::text_chars`] and summed in the SAME walk, so the two can never drift.
    pub system_chars: usize,
    /// The caller's output cap, normalized by the reader from whichever field its dialect spells it
    /// in. Reading this from the IR is a FIX, not merely a move: the raw-body projection is
    /// dialect-aware for exactly one dialect's spelling and returns `None` for a body that spells
    /// the cap in a nested config object, silently blinding any routing policy keyed on it.
    pub max_tokens: Option<u32>,
}

impl Shape {
    /// Sum the `text_chars` / `system_chars` size signals over an ALREADY-BUILT content projection —
    /// the ONE place a non-chat family's size counts are derived, so the size signal can never walk a
    /// different set of items than the gate is shown. The drift invariant `IrRequest`/`InvokeReq`
    /// state inline (a size signal and a content projection computed by two functions can drift); the
    /// non-chat families express the same invariant by summing over exactly the slice `content()`
    /// returned rather than by a second walk.
    pub fn counts_over(items: &[ContentItem<'_>]) -> (usize, usize) {
        let mut text_chars = 0usize;
        let mut system_chars = 0usize;
        for item in items {
            let n = item.screenable_text().chars().count();
            text_chars += n;
            if matches!(item.slot(), Slot::System) {
                system_chars += n;
            }
        }
        (text_chars, system_chars)
    }

    /// The shape of a request that carries no readable conversation facts at all — a multipart or
    /// binary body, or one whose protocol has no reader registered. Named rather than
    /// `Default::default()`d so a consumer reads "nothing here" as a decision rather than as a
    /// zero-initialized accident.
    pub const EMPTY: Shape = Shape {
        turn_count: 0,
        has_tools: false,
        tool_count: 0,
        text_chars: 0,
        system_chars: 0,
        max_tokens: None,
    };
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
pub trait IrFacts {
    /// The semantic operation — the same closed vocabulary the metrics label and the `paths:` config
    /// key use, so a consumer that switches on it is switching on something already enumerated.
    ///
    /// **THE ONE ITEM ON THIS SEAM WITH NO CALLER, AND IT IS NAMED RATHER THAN COVERED.** Dropping
    /// the module-wide `allow(dead_code)` left exactly this behind, which is what that allowance was
    /// hiding. It stays because it is the seam's DECLARED surface — both implementers answer it, and
    /// a family-blind consumer that needs to know which operation it is holding has no other way to
    /// ask — but the allowance is now ONE NAMED EXCEPTION instead of a blindfold over the module, so
    /// the next unreachable item here is a warning rather than a silence.
    #[cfg_attr(not(test), allow(dead_code))]
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

/// The empty projection over a bare [`Operation`] — the [`IrFacts`] a RESPONSE-side `IrHandle`
/// returns from its `facts()` default. It is never actually read (facts are a request-side seam:
/// `read_facts` runs only on the ingress request handle), so it answers with the operation it holds
/// and nothing else. Naming it here keeps the response handles from having to carry a real projection.
pub struct NeutralFacts(pub Operation);

impl IrFacts for NeutralFacts {
    fn verb(&self) -> Operation {
        self.0
    }
    fn wants_stream(&self) -> bool {
        false
    }
    fn end_user(&self) -> Option<&str> {
        None
    }
    fn shape(&self) -> Shape {
        Shape::default()
    }
    fn content(&self) -> Vec<ContentItem<'_>> {
        Vec::new()
    }
}
