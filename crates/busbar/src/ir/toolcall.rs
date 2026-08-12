// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOOL-CALL IR — the `Operation::ToolCall` subclass of the parent [`crate::ir::variant::IrReq`]
//! / [`crate::ir::variant::IrResp`] enums.
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
//! [`ToolCallResp::is_error`] — the transport succeeded, the protocol succeeded, the tool did not.
//! A call that could not be made at all is a refusal and never reaches this type. Collapsing the
//! two tells a caller their request was malformed when their tool merely returned an error, and it
//! is also what makes an upstream failure indistinguishable from a policy refusal to the breaker.

use serde_json::Value;

/// A CALL TO ONE TOOL. The request half of the `ToolCall` operation.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolCallReq {
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

/// WHAT ONE TOOL CALL PRODUCED. The response half.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolCallResp {
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
