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
//! The family-blind `IrFacts` projection over `InvokeReq` lives in `busbar-core` (`crate::ir::invoke`),
//! beside the engine seam it feeds; core re-exports these types from that path.

use super::SourceScopedExtra;
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
