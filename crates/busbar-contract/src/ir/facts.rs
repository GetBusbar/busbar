// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ir::facts` — THE ONE PROJECTION. What the shared pipeline is allowed to know about a request,

use crate::operation::OpVerb;
use serde_json::Value;
use std::borrow::Cow;

/// Fixed non-content marker substituted for content busbar cannot read. Busbar cannot decrypt
pub const OPAQUE_CONTENT_MARKER: &str = "[busbar:redacted_reasoning]";

/// Label for an opaque reasoning item. A stable, protocol-blind noun: three wire shapes across three
pub const LABEL_REASONING: &str = "reasoning";

/// Label for a structured, non-prose content member — the shape a tool result carries when it
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
    /// The request's system prompt as the dialect's own system field carries it. An in-band system
    /// turn is a [`Slot::Turn`], as a 1.5.5 hook saw it.
    System,
    /// Ordinary content of the conversation turn at this wire position.
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
    pub fn screenable_text(&self) -> Cow<'_, str> {
        match self {
            ContentItem::Text { text, .. } => Cow::Borrowed(text.as_ref()),
            ContentItem::Data { value, .. } => {
                #[cfg(test)]
                DATA_RENDERS.with(|c| c.set(c.get() + 1));
                Cow::Owned(value.to_string())
            }
            ContentItem::Opaque { marker, .. } => Cow::Borrowed(marker),
        }
    }

    /// A collision-resistant identity for "have I screened this exact piece before" — over the author
    pub fn screening_digest(&self) -> String {
        self.digest_of(&self.screenable_text())
    }

    /// [`Self::screening_digest`] over an ALREADY-RENDERED text — the body of the digest, so a
    pub fn digest_of(&self, text: &str) -> String {
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

        let variant: u8 = match self {
            ContentItem::Text { .. } => 0,
            ContentItem::Data { .. } => 1,
            ContentItem::Opaque { .. } => 2,
        };
        let author = self.author();

        let mut buf = Vec::with_capacity(5 * 8 + 1 + 1 + 8 + author.len() + text.len());
        framed(&mut buf, &[variant]);
        framed(&mut buf, &[slot_kind]);
        framed(&mut buf, &slot_idx.to_be_bytes());
        framed(&mut buf, author.as_bytes());
        framed(&mut buf, text.as_bytes());
        crate::sha256_hex(&buf)
    }
}

#[cfg(test)]
thread_local! {
    static DATA_RENDERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Zero the render tally and return what it held (test-only).
#[cfg(test)]
pub(crate) fn take_data_renders() -> usize {
    DATA_RENDERS.with(|c| c.replace(0))
}

/// A content projection with EVERY item's screenable text rendered ONCE, up front.
pub struct ScreenedContent<'a> {
    entries: Vec<(&'a ContentItem<'a>, Cow<'a, str>)>,
}

impl<'a> ScreenedContent<'a> {
    /// Render every item's screenable text once.
    pub fn over(items: &'a [ContentItem<'a>]) -> Self {
        Self {
            entries: items
                .iter()
                .map(|item| (item, item.screenable_text()))
                .collect(),
        }
    }

    /// The items and their rendered text, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&'a ContentItem<'a>, &str)> + '_ {
        self.entries.iter().map(|(item, text)| (*item, &**text))
    }

    /// How many items this projection carries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is this projection empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The subset `keep` accepts, carrying each kept item's ALREADY-RENDERED text across.
    pub fn select(&self, keep: impl Fn(&ContentItem<'a>, &str) -> bool) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(item, text)| keep(item, text))
                .cloned()
                .collect(),
        }
    }

    /// The `text_chars` / `system_chars` size signals, summed over exactly these items — the same
    pub fn counts(&self) -> (usize, usize) {
        let mut text_chars = 0usize;
        let mut system_chars = 0usize;
        for (item, text) in self.iter() {
            let n = text.chars().count();
            text_chars += n;
            if matches!(item.slot(), Slot::System) {
                system_chars += n;
            }
        }
        (text_chars, system_chars)
    }

    /// The [`ContentItem::screening_digest`] of the item at `i`, off the rendered text.
    pub fn digest(&self, i: usize) -> Option<String> {
        self.entries.get(i).map(|(item, text)| item.digest_of(text))
    }

    /// Every item's [`ContentItem::screening_digest`], in order.
    pub fn digests(&self) -> impl Iterator<Item = String> + '_ {
        self.entries.iter().map(|(item, text)| item.digest_of(text))
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
    /// Conversation turns, as the wire counts them: an in-band system turn is a turn (1.5.5).
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
    /// Chars of the SYSTEM slot alone: the dialect's own system field, never an in-band system
    /// turn, which is a turn (1.5.5). A subset of
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
    pub fn counts_over(items: &[ContentItem<'_>]) -> (usize, usize) {
        let mut text_chars = 0usize;
        let mut system_chars = 0usize;
        for item in items {
            let n = match item {
                ContentItem::Data { value, .. } => {
                    use std::fmt::Write as _;
                    struct CharCount(usize);
                    impl std::fmt::Write for CharCount {
                        fn write_str(&mut self, text: &str) -> std::fmt::Result {
                            self.0 += text.chars().count();
                            Ok(())
                        }
                    }
                    let mut count = CharCount(0);

                    write!(&mut count, "{value}").expect("the character counter cannot fail");
                    count.0
                }
                _ => {
                    let text = item.screenable_text();
                    let n = text.chars().count();
                    #[cfg(test)]
                    shape_custody_tests::retiring_count_text(&text);
                    n
                }
            };
            text_chars += n;
            if matches!(item.slot(), Slot::System) {
                system_chars += n;
            }
        }
        (text_chars, system_chars)
    }

    /// The shape of a request that carries no readable conversation facts at all — a multipart or
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
pub trait IrFacts {
    /// The semantic operation — the same closed vocabulary the metrics label and the `paths:` config
    #[cfg_attr(not(test), allow(dead_code))]
    fn verb(&self) -> OpVerb;

    /// Did the caller ask to stream?
    fn wants_stream(&self) -> bool;

    /// End-user identifier for provider-side abuse tracking, normalized by the reader from whichever
    fn end_user(&self) -> Option<&str>;

    /// Counts and sizes. No content.
    fn shape(&self) -> Shape;

    /// The content projection, in request order. Grant-gated at the seam that CALLS this, never
    fn content(&self) -> Vec<ContentItem<'_>>;
}

/// A SHARED projection is still a projection. `facts()` must hand back an OWNED
impl<T: IrFacts + ?Sized> IrFacts for std::sync::Arc<T> {
    fn verb(&self) -> OpVerb {
        (**self).verb()
    }
    fn wants_stream(&self) -> bool {
        (**self).wants_stream()
    }
    fn end_user(&self) -> Option<&str> {
        (**self).end_user()
    }
    fn shape(&self) -> Shape {
        (**self).shape()
    }
    fn content(&self) -> Vec<ContentItem<'_>> {
        (**self).content()
    }
}

/// The empty projection over a bare [`OpVerb`] — the [`IrFacts`] a RESPONSE-side `IrHandle`
pub struct NeutralFacts(pub OpVerb);

impl IrFacts for NeutralFacts {
    fn verb(&self) -> OpVerb {
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

#[cfg(test)]
#[path = "../tests/screening_tests.rs"]
mod screening_tests;

#[cfg(test)]
#[path = "tests/shape_custody_tests.rs"]
mod shape_custody_tests;
