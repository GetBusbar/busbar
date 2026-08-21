// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `impl IrFacts for IrRequest` + its `project` helper — the chat IR's projection, relocated to
//! busbar-llm with the concrete IR (G6 A4b). The neutral `IrFacts` trait + `Shape`/`ContentItem`/
//! `Slot` stay in `busbar_core::ir::facts`; this impl is for the moved `crate::ir::IrRequest`.

use super::{IrBlock, IrRequest, IrRole};
use busbar_core::ir::facts::{
    ContentItem, IrFacts, Shape, Slot, LABEL_JSON, LABEL_REASONING, OPAQUE_CONTENT_MARKER,
};
use busbar_core::operation::Operation;
use std::borrow::Cow;

impl IrFacts for IrRequest {
    fn verb(&self) -> Operation {
        Operation::CHAT
    }

    fn wants_stream(&self) -> bool {
        self.stream
    }

    fn end_user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    fn shape(&self) -> Shape {
        // ONE walk over the SAME items a content-granted hook is shown, so the total and the
        // system-only subtotal cannot drift from each other or from the content. See
        // `ContentItem::screenable_text` for why this is a sum and not a second walk.
        let mut text_chars = 0usize;
        let mut system_chars = 0usize;
        for item in project(self) {
            let n = item.screenable_text().chars().count();
            text_chars += n;
            if matches!(item.slot(), Slot::System) {
                system_chars += n;
            }
        }
        Shape {
            turn_count: self.messages.len(),
            has_tools: !self.tools.is_empty(),
            tool_count: self.tools.len(),
            text_chars,
            system_chars,
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
pub fn project(req: &IrRequest) -> Vec<ContentItem<'_>> {
    let mut out = Vec::new();
    walk(
        &req.system,
        author_of(IrRole::System),
        None,
        Slot::System,
        &mut out,
    );
    for (i, m) in req.messages.iter().enumerate() {
        let before = out.len();
        walk(
            &m.content,
            author_of(m.role),
            Some(i),
            Slot::Turn(i),
            &mut out,
        );
        if out.len() == before {
            // The empty-turn rule. See this function's doc comment.
            out.push(ContentItem::Text {
                author: author_of(m.role),
                slot: Slot::Turn(i),
                text: Cow::Borrowed(""),
            });
        }
    }
    out
}

/// The LLM family's author label for a chat role — the exact strings the hook wire has always
/// carried. This is the ONE place `IrRole` becomes the neutral opaque label, and it lives with the
/// walk (which moves to `busbar-llm` with the concrete IR), NOT with the neutral gate that reads the
/// label. Pinned byte-identical by `role_label_is_byte_identical_to_the_seam` in the ir role tests.
fn author_of(role: IrRole) -> &'static str {
    match role {
        IrRole::System => "system",
        IrRole::User => "user",
        IrRole::Assistant => "assistant",
        IrRole::Tool => "tool",
    }
}

/// One level of the block walk. `turn` is `None` for the system slot, where a tool call or tool
/// result has no turn to be attributed to and keeps the slot it was reached through.
fn walk<'a>(
    blocks: &'a [IrBlock],
    author: &'static str,
    turn: Option<usize>,
    slot: Slot,
    out: &mut Vec<ContentItem<'a>>,
) {
    for b in blocks {
        match b {
            IrBlock::Text { text, .. } => out.push(ContentItem::Text {
                author,
                slot,
                text: Cow::Borrowed(text.as_str()),
            }),
            IrBlock::Thinking { text, .. } => {
                if b.is_opaque() {
                    out.push(ContentItem::Opaque {
                        author,
                        slot,
                        label: LABEL_REASONING,
                        marker: OPAQUE_CONTENT_MARKER,
                    });
                } else {
                    // Reasoning busbar CAN read is ordinary screenable content and is shown as such:
                    // a client replaying a multi-turn body sends this text to the provider, so a
                    // gate that cannot see it is a gate with a hole in it.
                    out.push(ContentItem::Text {
                        author,
                        slot,
                        text: Cow::Borrowed(text.as_str()),
                    });
                }
            }
            IrBlock::ToolUse { name, input, .. } => out.push(ContentItem::Data {
                author,
                slot: turn.map_or(slot, Slot::ToolArgs),
                label: name.as_str(),
                value: input,
            }),
            IrBlock::ToolResult { content, .. } => walk(
                content,
                author,
                turn,
                turn.map_or(slot, Slot::ToolResult),
                out,
            ),
            // Structurally text-less and DELIBERATELY not widened here — see the module header.
            // `Media` (a document/audio/video attachment) joins `Image` on the SAME decision, made
            // explicitly rather than inherited: widening it would newly disclose attachment bytes,
            // mime types and filenames to every operator content hook and sidecar. That is a real
            // disclosure change, not a mechanical consequence of adding an IR variant, so it stays
            // closed until it is decided on its own terms in its own diff — exactly the reasoning
            // the module header records for image provenance.
            IrBlock::Image { .. } | IrBlock::Media { .. } => {}
            IrBlock::Json(v) => out.push(ContentItem::Data {
                author,
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
