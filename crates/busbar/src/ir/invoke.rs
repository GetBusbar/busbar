// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INVOKE IR — the `Operation::INVOKE` subclass of the parent [`crate::ir::variant::IrReq`]
//! / [`crate::ir::variant::IrResp`] enums.
//!
//! Named `ToolCall` through 1.5. `Invoke` is the same shape — a caller names a target, hands it
//! arguments, and gets content or an error back — under a name that does not belong to one protocol:
//! it carries A2A `message/send` and MCP `completion/complete` alongside MCP `tools/call`, and an
//! MCP-flavoured name would be a protocol branch waiting to happen at every site that reads it.
//!
//! ## WHY THIS IS AN OPERATION AND NOT A PLANE
//!
//! MCP was first built as a parallel ingress path BESIDE the pipeline: 13,069 implementation lines
//! under `mcp/`, with **zero** `ProtocolReader`/`ProtocolWriter` implementations and **zero**
//! occurrences of `IrBlock`. Every concern the core already owned — the guarded fetch, the ingress
//! admission, the outbound credential, the hash-chained audit, the config section container — was
//! written a second time inside that directory, which is what `structure-lint`'s plane ledger has
//! been counting.
//!
//! The corrective is not a better plane. It is to stop having one: a tool call is an OPERATION, in
//! the same sense that a chat completion, an embedding and a transcription are operations, and it
//! reaches the same operation-blind middle through the same `protocol × operation` codec matrix.
//! Governance, budgets, audit, metrics, the breaker and failover then apply to it because it is in
//! the matrix, not because someone re-wired each of them into a second directory.
//!
//! ## WHAT A TOOL CALL IS, REDUCED TO ITS INVARIANTS
//!
//! A caller names a tool, hands it arguments, and gets content back or an error. That is the whole
//! operation. It has no messages, no system prompt, no sampling controls — which is exactly why
//! `IrRequest` (the CHAT subclass) could never have carried it, and why the parent enum earns its
//! keep here rather than being a formality.
//!
//! ## THE TWO ERROR CHANNELS ARE NOT THE SAME CHANNEL
//!
//! This is the distinction the first implementation got wrong, and it is worth stating in the type
//! rather than in prose. A tool that RAN and FAILED is a successful call whose result carries
//! [`InvokeResp::is_error`] — the transport succeeded, the protocol succeeded, the tool did not.
//! A call that could not be made at all is a refusal and never reaches this type. Collapsing the
//! two tells a caller their request was malformed when their tool merely returned an error, and it
//! is also what makes an upstream failure indistinguishable from a policy refusal to the breaker.

use serde_json::Value;

/// A CALL TO ONE NAMED TARGET. The request half of the `Invoke` operation.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InvokeReq {
    /// THE TOOL BEING CALLED, in the caller's vocabulary — the name as PUBLISHED, which is not
    /// necessarily the name the upstream knows it by. The rename on the way out is
    /// `ProtocolWriter::rewrite_model`'s job on this operation, exactly as it is the model rename's
    /// job on chat: the writer owns the target identifier's egress spelling, so the engine never
    /// learns that a rename happened.
    pub(crate) tool: String,
    /// THE ARGUMENTS, verbatim as the caller sent them. An arbitrary JSON object by the protocol's
    /// own definition, so it is carried as a `Value` and not modelled further: busbar validates
    /// arguments against the tool's declared schema, and validating is not the same as reshaping.
    pub(crate) arguments: Value,
    /// Unmodelled request members, kept keyed so a cross-protocol hop cannot leak a source-only
    /// key into a foreign dialect. Same discipline as chat's `extra`.
    pub(crate) extra: crate::lossless::SourceScopedExtra,
}

/// THE INVOCATION FAMILY'S WALK — this IR's answer to [`crate::ir::facts::IrFacts`], the
/// family-blind seam the shared pipeline reads a request through.
///
/// It lives HERE, in the module that owns the IR, and not in `ir/facts.rs`: `facts.rs` carries the
/// CHAT family's walk beside the trait, and a second family folded in there would be a superset
/// across two families that never translate into one another — the standing rule this file's own
/// header states. One IR, one walk, one file.
///
/// ## What a hook is shown for an invocation, and why it is exactly this
///
/// A tool call has no turns, no system prompt and no sampling controls. What it HAS is a target and
/// arguments, and the arguments are the untrusted part: caller-authored, sent upstream verbatim,
/// and the only thing on this operation a screening gate can act on. So the projection is ONE
/// [`crate::ir::facts::ContentItem::Data`] carrying the arguments `Value` itself — not a pre-flattened string, so a
/// gate that wants to walk the structure can, and one that wants text calls `screenable_text` — and
/// its `label` is the TARGET, which is how "which tool" reaches a consumer that never learns the
/// protocol.
///
/// [`crate::ir::facts::Slot::ToolArgs`] and not [`crate::ir::facts::Slot::Turn`], deliberately: the slot is a statement about
/// PROVENANCE, and a consumer that treats a tool call's arguments as ordinary conversation content
/// is a consumer that trusts them like conversation content. There is one invocation per request,
/// so the turn index it is attributed to is `0`.
impl crate::ir::facts::IrFacts for InvokeReq {
    fn verb(&self) -> crate::operation::Operation {
        crate::operation::Operation::INVOKE
    }

    /// An invocation is one exchange. The streaming question belongs to the operations that can
    /// answer it, and answering `false` here is a fact rather than a default.
    fn wants_stream(&self) -> bool {
        false
    }

    /// NO END-USER IDENTIFIER, and this is a statement about the protocol rather than an omission:
    /// neither wire shape this IR is read from carries the provider-side abuse-tracking field the
    /// chat dialects spell `user` / `metadata.user_id`. The CALLER's identity still reaches a
    /// granted hook — it comes from the resolved governance key at the firing site, which is where
    /// it comes from on every plane.
    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        // Summed over the SAME items a content-granted hook is shown, for the reason
        // [`crate::ir::facts::ContentItem::screenable_text`] gives: a size signal and a content
        // projection computed by two functions is a size signal that can drift from what was
        // screened. `system_chars` is accumulated in THIS walk rather than by a second pass, which
        // is the invariant [`crate::ir::facts::Shape::system_chars`] states: it is a subset of
        // `text_chars` and the two cannot drift because nothing walks twice.
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
            // The request IS a tool call: whatever else `has_tools` means to a consumer, answering
            // `false` for an invocation would be false.
            has_tools: true,
            // ONE tool is in play, named by [`InvokeReq::tool`]. This is the coherent partner of
            // `has_tools: true` above: a consumer handed `has_tools` with a count of zero would be
            // reading a contradiction. The count is of tools the request puts in play, and an
            // invocation puts exactly the one it targets.
            tool_count: 1,
            text_chars,
            // Always `0` today, and computed rather than written down so it STAYS true. An
            // invocation projects one [`crate::ir::facts::Slot::ToolArgs`] item and has no system
            // slot at all — a hardcoded `0` would silently become a lie the day this projection
            // grows an item, which is the whole reason the sum shares the walk above.
            system_chars,
            // No output cap exists on this operation to normalise.
            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        vec![crate::ir::facts::ContentItem::Data {
            role: crate::ir::IrRole::User,
            slot: crate::ir::facts::Slot::ToolArgs(0),
            label: self.tool.as_str(),
            value: &self.arguments,
        }]
    }
}

/// WHAT ONE TOOL CALL PRODUCED. The response half.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InvokeResp {
    /// The content the tool returned, verbatim. busbar is content-blind on this operation: it
    /// decides WHETHER a call may happen and records THAT it happened, and rewriting a payload is
    /// not a gateway's job.
    pub(crate) content: Value,
    /// THE TOOL FAILED, BUT THE CALL DID NOT. See the module note on the two error channels: this
    /// is a successful protocol exchange reporting an unsuccessful tool. It must never be rendered
    /// as a protocol-level error, and a protocol-level error must never be rendered as this.
    pub(crate) is_error: bool,
    /// Structured output, when the tool declares an output schema and returned one. `None` when it
    /// does not — and note that busbar does not yet model output schemas at all, so this is
    /// carried rather than validated. Stated here rather than left to be discovered.
    pub(crate) structured: Option<Value>,
    /// Unmodelled response members, source-keyed for the same reason as the request's.
    pub(crate) extra: crate::lossless::SourceScopedExtra,
}
