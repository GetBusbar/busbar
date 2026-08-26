// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `(mcp, Invoke)` CELL — the `tools/call` codec. Feed it wire, assert the IR; feed it IR,
//! assert the wire.

// `Bytes`/`WireBody` are used only by the cfg-gated write free fns below (writes inverted off the
// trait onto the handle at the G6 A4b dissolve; Invoke's neutral handle uses the empty default).
#[cfg(any(test, feature = "test-support"))]
use bytes::Bytes;

use busbar_core::handlers::{CodecError, IngressReject, OperationHandler};
use busbar_substrate::ir::handle::IrHandle;
use busbar_substrate::ir::invoke::{InvokeReq, InvokeResp};
use busbar_substrate::ir::neutral_handles::{InvokeReqHandle, InvokeRespHandle};
#[cfg(any(test, feature = "test-support"))]
use busbar_substrate::wire::WireBody;

#[cfg(any(test, feature = "test-support"))]
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
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(InvokeReqHandle(read_invoke_request(body)?)) as Box<dyn IrHandle>)
    }

    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(InvokeRespHandle(read_invoke_response(wire)?)) as Box<dyn IrHandle>)
    }
}

/// Wire -> concrete `InvokeReq` parse, extracted from `InvokeOperation::read_request` so the
/// dissolved `(mcp, Invoke)` round-trip test can recover the concrete IR without a downcast. Used in
/// production by the trait `read_request` above.
pub(crate) fn read_invoke_request(body: &[u8]) -> Result<InvokeReq, IngressReject> {
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
            IngressReject::BadRequest("a tools/call names the tool in `params.name`".to_string())
        })?
        .to_string();
    Ok(InvokeReq {
        tool,
        // ABSENT ARGUMENTS ARE AN EMPTY OBJECT, not an error: a tool that takes none is called
        // with none, and rejecting that would refuse a legal call.
        arguments: params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        extra: Default::default(),
    })
}

/// Wire -> concrete `InvokeResp` parse (see [`read_invoke_request`]).
pub(crate) fn read_invoke_response(wire: &[u8]) -> Result<InvokeResp, CodecError> {
    let v: serde_json::Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let result = v
        .get("result")
        .ok_or_else(|| CodecError::Malformed("no `result` member".to_string()))?;
    Ok(InvokeResp {
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
    })
}

/// IR → `tools/call` request wire — the former `InvokeOperation::write_request` body, moved to a
/// free fn behind the `(mcp, Invoke)` codec (G6 A4b: writes inverted off the trait onto the handle,
/// but Invoke is same-protocol-only so its handle uses the empty default; this preserves the
/// round-trip codec logic for the `(mcp, Invoke)` fidelity tests). Byte-identical to the inline write.
///
/// The `id` is the ENGINE's, not the caller's: correlation is decided on the way out and read back
/// by `ingress::jsonrpc::read_response`, which refuses an answer that names a different request.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn invoke_write_request(r: &InvokeReq) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_TOOLS_CALL,
            "params": { "name": r.tool, "arguments": r.arguments },
        }))
        .unwrap_or_default(),
    )
}

/// IR → `tools/call` response wire — the former `InvokeOperation::write_response` body, moved to a
/// free fn (see [`invoke_write_request`]). Byte-identical to the inline write.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn invoke_write_response(r: &InvokeResp) -> WireBody {
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
