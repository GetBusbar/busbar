// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INVOKE IR data — the `Operation::INVOKE` request/response pair.
//!
//! Named `ToolCall` through 1.5. `Invoke` is the same shape — a caller names a target, hands it
//! arguments, and gets content or an error back — under a name that does not belong to one protocol:
//! it carries A2A `message/send` and MCP `completion/complete` alongside MCP `tools/call`.
//!
//! ## THE TWO ERROR CHANNELS ARE NOT THE SAME CHANNEL
//!
//! A tool that RAN and FAILED is a successful call whose result carries `InvokeResp::is_error` — the
//! transport succeeded, the protocol succeeded, the tool did not. A call that could not be made at
//! all is a refusal and never reaches this type.
//!
//! The family-blind `IrFacts` projection over `InvokeReq` lives HERE (relocated beside its data at
//! Batch C-2, keeping the orphan rule satisfied now that the `IrFacts` trait is substrate-resident);
//! core re-exports both the type and the projection through `busbar_core::ir::invoke`.

use super::SourceScopedExtra;
use busbar_api::operation::Operation;
use serde_json::Value;

/// A CALL TO ONE NAMED TARGET. The request half of the `Invoke` operation.
#[derive(Debug, Clone, PartialEq)]
pub struct InvokeReq {
    /// THE TOOL BEING CALLED, in the caller's vocabulary — the name as PUBLISHED, which is not
    /// necessarily the name the upstream knows it by. The rename on the way out is
    /// `ProtocolWriter::rewrite_model`'s job on this operation, exactly as it is the model rename's
    /// job on chat: the writer owns the target identifier's egress spelling, so the engine never
    /// learns that a rename happened.
    pub tool: String,
    /// THE ARGUMENTS, verbatim as the caller sent them. An arbitrary JSON object by the protocol's
    /// own definition, so it is carried as a `Value` and not modelled further: busbar validates
    /// arguments against the tool's declared schema, and validating is not the same as reshaping.
    pub arguments: Value,
    /// Unmodelled request members, kept keyed so a cross-protocol hop cannot leak a source-only
    /// key into a foreign dialect. Same discipline as chat's `extra`.
    pub extra: SourceScopedExtra,
}

/// WHAT ONE TOOL CALL PRODUCED. The response half.
#[derive(Debug, Clone, PartialEq)]
pub struct InvokeResp {
    /// The content the tool returned, verbatim. busbar is content-blind on this operation: it
    /// decides WHETHER a call may happen and records THAT it happened, and rewriting a payload is
    /// not a gateway's job.
    pub content: Value,
    /// THE TOOL FAILED, BUT THE CALL DID NOT. See the module note on the two error channels: this
    /// is a successful protocol exchange reporting an unsuccessful tool. It must never be rendered
    /// as a protocol-level error, and a protocol-level error must never be rendered as this.
    pub is_error: bool,
    /// Structured output, when the tool declares an output schema and returned one. `None` when it
    /// does not — and note that busbar does not yet model output schemas at all, so this is
    /// carried rather than validated. Stated here rather than left to be discovered.
    pub structured: Option<Value>,
    /// Unmodelled response members, source-keyed for the same reason as the request's.
    pub extra: SourceScopedExtra,
}

/// THE INVOCATION FAMILY'S WALK — this IR's answer to [`crate::ir::facts::IrFacts`], the
/// family-blind seam the shared pipeline reads a request through.
///
/// It lives HERE, in the module that owns the IR, and not in `ir/facts.rs`: `facts.rs` carries the
/// CHAT family's walk beside the trait, and a second family folded in there would be a superset
/// across two families that never translate into one another. One IR, one walk, one file.
///
/// A tool call has no turns, no system prompt and no sampling controls. What it HAS is a target and
/// arguments, and the arguments are the untrusted part: caller-authored, sent upstream verbatim,
/// and the only thing on this operation a screening gate can act on. So the projection is ONE
/// [`crate::ir::facts::ContentItem::Data`] carrying the arguments `Value` itself, and its `label` is
/// the TARGET, which is how "which tool" reaches a consumer that never learns the protocol.
///
/// [`crate::ir::facts::Slot::ToolArgs`] and not [`crate::ir::facts::Slot::Turn`], deliberately: the
/// slot is a statement about PROVENANCE, and a consumer that treats a tool call's arguments as
/// ordinary conversation content is a consumer that trusts them like conversation content. There is
/// one invocation per request, so the turn index it is attributed to is `0`.
impl crate::ir::facts::IrFacts for InvokeReq {
    fn verb(&self) -> Operation {
        Operation::INVOKE
    }

    /// An invocation is one exchange. The streaming question belongs to the operations that can
    /// answer it, and answering `false` here is a fact rather than a default.
    fn wants_stream(&self) -> bool {
        false
    }

    /// NO END-USER IDENTIFIER, and this is a statement about the protocol rather than an omission:
    /// neither wire shape this IR is read from carries the provider-side abuse-tracking field the
    /// chat dialects spell `user` / `metadata.user_id`.
    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        // Summed over the SAME items a content-granted hook is shown, for the reason
        // `ContentItem::screenable_text` gives: a size signal and a content projection computed by
        // two functions is a size signal that can drift from what was screened. `system_chars` is
        // accumulated in THIS walk rather than by a second pass.
        let mut text_chars = 0usize;
        let mut system_chars = 0usize;
        for item in crate::ir::facts::IrFacts::content(self) {
            let n = item.screenable_text().chars().count();
            text_chars += n;
            if matches!(item.slot(), crate::ir::facts::Slot::System) {
                system_chars += n;
            }
        }
        crate::ir::facts::Shape {
            // ONE unit of work. An invocation is not a conversation, and reporting `0` would tell a
            // hook the request is empty.
            turn_count: 1,
            // The request IS a tool call: answering `false` for an invocation would be false.
            has_tools: true,
            // ONE tool is in play, named by `InvokeReq::tool`.
            tool_count: 1,
            text_chars,
            // Always `0` today, and computed rather than written down so it STAYS true. An
            // invocation projects one `Slot::ToolArgs` item and has no system slot at all.
            system_chars,
            // No output cap exists on this operation to normalise.
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        vec![crate::ir::facts::ContentItem::Data {
            // The invocation family's author label — its own word for "the caller", not an LLM role.
            author: "user",
            slot: crate::ir::facts::Slot::ToolArgs(0),
            label: self.tool.as_str(),
            value: &self.arguments,
        }]
    }
}
