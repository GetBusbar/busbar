// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `(mcp, Invoke)` CELL — the `tools/call` codec. Feed it wire, assert the IR; feed it IR,
//! assert the wire.

use bytes::Bytes;

use busbar_core::handlers::{CodecError, IngressReject, OperationHandler, WireBody};
use busbar_core::ir::invoke::{InvokeReq, InvokeResp};
use busbar_core::ir::variant::{IrReq, IrResp};

use super::METHOD_TOOLS_CALL;

/// The `tools/call` codec.
pub struct InvokeOperation;

impl OperationHandler for InvokeOperation {
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
        Ok(IrReq::Invoke(InvokeReq {
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
        let IrReq::Invoke(r) = ir else {
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
        Ok(IrResp::Invoke(InvokeResp {
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
        let IrResp::Invoke(r) = ir else {
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
