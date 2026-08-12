// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP `RequestHandler` AND ITS ONE CELL — MCP as a protocol in the matrix, not a plane beside
//! it.
//!
//! ## WHAT THIS FILE IS EVIDENCE FOR
//!
//! MCP was first built as a parallel ingress path: 13,069 implementation lines under `mcp/`, with
//! zero `ProtocolReader`/`ProtocolWriter` implementations and zero `IrBlock`. Every concern the core
//! already owned — the guarded fetch, ingress admission, outbound credentials, the hash-chained
//! audit, the config-section container — was written a second time in that directory, which is what
//! the plane ledger in `scripts/structure-lint.sh` counts.
//!
//! This file is the other way of doing it, and it is deliberately the same size and shape as
//! `responses.rs`: a protocol declares which operations it serves, and the operations it does not
//! serve return `None`, which is a `404` through the standard no-handler path. Being IN the matrix
//! is what makes governance, budgets, audit, metrics, the breaker and failover apply — not a second
//! wiring of each.
//!
//! ## THE ONE GENUINELY MCP-SHAPED THING
//!
//! MCP frames every call in a JSON-RPC 2.0 envelope: `{jsonrpc, id, method, params}` in, and
//! `{jsonrpc, id, result}` or `{jsonrpc, id, error}` back. That framing is this protocol's dialect,
//! exactly as `{"messages": [...]}` is OpenAI's and `{"contents": [...]}` is Gemini's, and it is the
//! codec's whole job. It is NOT a reason for the engine to know MCP exists.
//!
//! **The envelope is read by [`crate::ingress::jsonrpc`], not re-implemented here.** That module
//! exists because the envelope had previously been parsed in two places that disagreed — the A2A
//! reader checked no `jsonrpc` member at all, and a malformed envelope was relayed to a backend
//! agent. One reader, two protocols.
//!
//! ## WHAT IS NOT BUILT HERE, STATED RATHER THAN DISCOVERED
//!
//! This cell reads and writes the `tools/call` shape. It does NOT yet carry the catalogue, the
//! schema pinning, the per-call audit chain or the arguments guard — those live in `mcp/` today and
//! are ported onto the core in their own units, each proven against the conformance suite. A cell
//! that quietly reimplemented them would be the original mistake a second time.

use bytes::Bytes;

use crate::handlers::IngressReject;
use crate::handlers::{CodecError, EgressCtx, OperationHandler, RequestHandler, WireBody};
use crate::ir::toolcall::{ToolCallReq, ToolCallResp};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;

/// The single mount path. MCP names the operation in the BODY (`method`), not the path — the
/// opposite of OpenAI, and the reason [`McpRequestHandler::resolve_operation`] reads the body.
const PATH_MCP: &str = "/mcp";

/// The JSON-RPC method this cell serves.
const METHOD_TOOLS_CALL: &str = "tools/call";

pub(crate) struct McpRequestHandler;

/// The `(mcp, ToolCall)` cell. One protocol, one operation, one codec.
static TOOL_CALL: ToolCallOperation = ToolCallOperation;

impl RequestHandler for McpRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "mcp"
    }

    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::ToolCall => Some(&TOOL_CALL),
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate.
            //
            // AND THIS IS THE "NO MCP TO CHAT" RULE, in the only place it needs to exist. MCP does
            // not serve chat, so there is no cell to translate a tool call into a chat completion
            // through; the pair is UNREPRESENTABLE rather than refused at runtime. The six chat
            // protocols say the mirror image about `ToolCall`.
            Operation::Chat
            | Operation::Embeddings
            | Operation::Moderation
            | Operation::Image
            | Operation::Transcription
            | Operation::Speech
            | Operation::Rerank => None,
        }
    }

    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        PATH_MCP.into()
    }

    /// THE OPERATION IS IN THE BODY, not the path — so this is one of the handlers that reads it.
    /// The signature already allowed for this (`body: &[u8]`); Bedrock and Cohere use it too.
    ///
    /// An unparseable body or an unknown method is `None`, which is the standard no-operation
    /// `404`. It is deliberately NOT a JSON-RPC error from here: this function answers "which
    /// operation is this", and a body that names no operation busbar serves has not yet reached the
    /// point where a protocol-shaped refusal would be meaningful.
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation> {
        if !path.ends_with(PATH_MCP) {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(body).ok()?;
        (v.get("method")?.as_str()? == METHOD_TOOLS_CALL).then_some(Operation::ToolCall)
    }
}

/// The `tools/call` codec. Feed it wire, assert the IR; feed it IR, assert the wire.
pub(crate) struct ToolCallOperation;

impl OperationHandler for ToolCallOperation {
    /// A tool call is one exchange, so every capability default (no streaming, no stream intent, no
    /// affinity, no usage tap) is already correct and none is overridden. That is the matrix
    /// working: the restrictive defaults mean a new cell cannot accidentally claim a behaviour.
    ///
    /// `taps_usage` stays FALSE deliberately. A tool server reports no tokens, so there is no usage
    /// to tap out of the body — a tool call is flat-metered, which `IrResp::usage` states.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        // The envelope's own validity is `ingress::jsonrpc`'s business and has already been decided
        // before a body reaches a codec; what this reader owns is the `params` shape.
        let params = v.get("params").ok_or_else(|| {
            IngressReject::BadRequest("a tools/call carries a `params` member".to_string())
        })?;
        let tool = params
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                IngressReject::BadRequest(
                    "a tools/call names the tool in `params.name`".to_string(),
                )
            })?
            .to_string();
        Ok(IrReq::ToolCall(ToolCallReq {
            tool,
            // ABSENT ARGUMENTS ARE AN EMPTY OBJECT, not an error: a tool that takes none is called
            // with none, and rejecting that would refuse a legal call.
            arguments: params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            extra: Default::default(),
        }))
    }

    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::ToolCall(r) = ir else {
            // A cell is only ever handed its own operation's IR — the matrix lookup is what
            // guarantees it. Reaching this arm means the matrix was bypassed, which is a bug in the
            // engine and not something to paper over with a plausible default.
            return Bytes::new();
        };
        // The `id` is the ENGINE's, not the caller's: correlation is decided on the way out and
        // read back by `ingress::jsonrpc::read_response`, which refuses an answer that names a
        // different request. A relay that echoed the caller's id would let a backend's reply to one
        // conversation be served as another's.
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": METHOD_TOOLS_CALL,
                "params": { "name": r.tool, "arguments": r.arguments },
            }))
            .unwrap_or_default(),
        )
    }

    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: serde_json::Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let result = v
            .get("result")
            .ok_or_else(|| CodecError::Malformed("no `result` member".to_string()))?;
        Ok(IrResp::ToolCall(ToolCallResp {
            content: result
                .get("content")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            // THE TOOL'S OWN VERDICT, and it is not the protocol's. `isError` on a successful
            // exchange means the tool ran and failed; a call that could not be made at all is a
            // refusal that never produces an `IrResp`. Collapsing the two tells a caller their
            // request was malformed when their tool merely returned an error.
            is_error: result
                .get("isError")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            structured: result.get("structuredContent").cloned(),
            extra: Default::default(),
        }))
    }

    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::ToolCall(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let mut result = serde_json::json!({ "content": r.content, "isError": r.is_error });
        // Carried, never synthesised: busbar models no output schema, so it emits structured
        // content only when the tool produced some.
        if let Some(s) = &r.structured {
            result["structuredContent"] = s.clone();
        }
        WireBody::json(Bytes::from(
            serde_json::to_vec(&serde_json::json!({ "jsonrpc": "2.0", "result": result }))
                .unwrap_or_default(),
        ))
    }
}

#[cfg(test)]
#[path = "tests/mcp_tests.rs"]
mod tests;
