// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `(mcp, Invoke)` CELL — the `tools/call` codec. Feed it wire, assert the IR; feed it IR,
//! assert the wire.

// `Bytes`/`WireBody` are used only by the cfg-gated write free fns below (writes inverted off the
// trait onto the handle at the G6 A4b dissolve; Invoke's neutral handle uses the empty default).
#[cfg(any(test, feature = "test-support"))]
use bytes::Bytes;

use busbar_substrate_values::handlers::{CodecError, IngressReject, OperationHandler};
use busbar_substrate_values::ir::handle::IrHandle;
use busbar_substrate_values::ir::invoke::{InvokeReq, InvokeResp};
use busbar_substrate_values::ir::neutral_handles::{InvokeReqHandle, InvokeRespHandle};
use busbar_substrate_values::ir::SourceScopedExtra;
#[cfg(any(test, feature = "test-support"))]
use busbar_substrate_values::wire::WireBody;

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
        Ok(
            Box::new(InvokeReqHandle(std::sync::Arc::new(read_invoke_request(
                body,
            )?))) as Box<dyn IrHandle>,
        )
    }

    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(InvokeRespHandle(read_invoke_response(wire)?)) as Box<dyn IrHandle>)
    }
}

/// Wire -> concrete `InvokeReq` parse, extracted from `InvokeOperation::read_request` so the
/// dissolved `(mcp, Invoke)` round-trip test can recover the concrete IR without a downcast. Used in
/// production by the trait `read_request` above.
pub(crate) fn read_invoke_request(body: &[u8]) -> Result<InvokeReq, IngressReject> {
    // MUTABLE because the document is this function's OWN and is dropped on the way out: every
    // member the IR keeps is MOVED out of it with `Value::take` rather than deep-cloned. Arguments
    // are caller-authored and arbitrarily large, so cloning them copied a whole tree only to free
    // the original a line later.
    let mut v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    // The envelope's own validity is `ingress::jsonrpc`'s business and has already been decided
    // before a body reaches a codec; what this reader owns is the `params` shape.
    let params = v.get_mut("params").ok_or_else(|| {
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
            .get_mut("arguments")
            .map(serde_json::Value::take)
            .unwrap_or_else(|| serde_json::json!({})),
        extra: Default::default(),
    })
}

/// Wire -> concrete `InvokeResp` parse (see [`read_invoke_request`]).
pub(crate) fn read_invoke_response(wire: &[u8]) -> Result<InvokeResp, CodecError> {
    // MOVED, never cloned — see [`read_invoke_request`]. Tool output is the larger of the two
    // documents on this operation.
    let mut v: serde_json::Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let result = v
        .get_mut("result")
        .ok_or_else(|| CodecError::Malformed("no `result` member".to_string()))?;
    let content = result
        .get_mut("content")
        .map(serde_json::Value::take)
        .unwrap_or_else(|| serde_json::json!([]));
    // THE TOOL'S OWN VERDICT, and it is not the protocol's. `isError` on a successful
    // exchange means the tool ran and failed; a call that could not be made at all is a
    // refusal that never produces an `IrResp`. Collapsing the two tells a caller their
    // request was malformed when their tool merely returned an error.
    //
    // A NON-BOOLEAN `isError` IS UNREADABLE, NOT FALSE. Absent means the ordinary successful call,
    // but a peer that puts a string, a number or an object there has not said the tool succeeded;
    // treating it as `false` serves a failure as a success, which is precisely the collapse this
    // separation exists to prevent, so it is refused instead.
    let is_error = match result.get("isError") {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(other) => {
            return Err(CodecError::Malformed(format!(
                "`isError` is the tool's own verdict and is a boolean, not {other}"
            )))
        }
    };
    let structured = result
        .get_mut("structuredContent")
        .map(serde_json::Value::take);

    // AN EXCHANGE THAT IS NOT OVER SAYS SO IN THESE THREE MEMBERS, and busbar models none of them
    // first-class — so they are kept under the source protocol's own namespace rather than dropped.
    // `requestState` in particular is the ONLY thing that can resume the exchange; discarding it
    // ends a conversation the peer believes is still open.
    let mut carried = serde_json::Map::new();
    for key in INTERIM_MEMBERS {
        if let Some(v) = result.get_mut(key).map(serde_json::Value::take) {
            carried.insert((*key).to_string(), v);
        }
    }
    let unfinished = carried
        .get("resultType")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|t| t != RESULT_TYPE_COMPLETE);
    // AN ANSWER THAT IS NOT AN ANSWER YET IS NOT AN EMPTY SUCCESSFUL CALL. With nothing in it and a
    // `resultType` that declares it unfinished, the only reading left is "the tool ran and returned
    // nothing", which is a different fact from the one on the wire. Refusing is the honest answer:
    // busbar serves what it can attribute, and it cannot attribute this one yet.
    if unfinished && !is_error && structured.is_none() && is_empty_content(&content) {
        return Err(CodecError::Malformed(
            "the result declares itself unfinished and carries no content, which is not a \
             successful tool call"
                .to_string(),
        ));
    }
    let mut extra = SourceScopedExtra::new();
    if !carried.is_empty() {
        extra.insert(crate::PLANE_KEY.to_string(), carried);
    }
    Ok(InvokeResp {
        content,
        is_error,
        structured,
        extra,
    })
}

/// The `result` members that describe an exchange busbar's IR does not model — whether the result is
/// final, what the peer is waiting for, and the opaque token that resumes it.
const INTERIM_MEMBERS: &[&str] = &["resultType", "requestState", "inputRequests"];

/// The one `resultType` that means the exchange is over.
const RESULT_TYPE_COMPLETE: &str = "complete";

/// Is this `content` nothing at all? Absent and `[]` are the same fact; anything else is content.
fn is_empty_content(content: &serde_json::Value) -> bool {
    content.as_array().is_some_and(|items| items.is_empty())
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
