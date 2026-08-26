// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `(mcp, Subscribe)` CELL — `resources/subscribe` and `resources/unsubscribe`, on `rmcp`'s own
//! parameter types.

// `Bytes`/`WireBody` are used only by the cfg-gated write free fns below (writes inverted off the
// trait onto the handle at the G6 A4b dissolve; Subscribe's neutral handle uses the empty default).
#[cfg(any(test, feature = "test-support"))]
use bytes::Bytes;

use rmcp::model::{SubscribeRequestParams, UnsubscribeRequestParams};

use busbar_core::handlers::{CodecError, IngressReject, OperationHandler};
use busbar_substrate::ir::handle::IrHandle;
use busbar_substrate::ir::neutral_handles::{SubscribeReqHandle, SubscribeRespHandle};
use busbar_substrate::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};
#[cfg(any(test, feature = "test-support"))]
use busbar_substrate::wire::WireBody;

use super::{METHOD_RESOURCES_SUBSCRIBE, METHOD_RESOURCES_UNSUBSCRIBE};

/// The subscription codec.
///
/// ## WHY THE TWO METHODS SHARE ONE CELL
///
/// They are the same request with the registration pointing the other way: the same target name,
/// the same acknowledgement, the same admission question. Two cells would be two places to decide
/// what a target name is, and the pair is meaningless the moment those two answers differ.
///
/// ## WHY THE PARAMS ARE DESERIALIZED INTO `rmcp`'s STRUCTS RATHER THAN READ FIELD BY FIELD
///
/// A hand-read `params["uri"]` accepts shapes the specification does not — a missing member read as
/// an empty string, a number read as a name — and each acceptance is a difference between what
/// busbar serves and what the specification says. Deserializing into the SDK's own parameter type
/// makes the SDK's schema the acceptance test, so a body busbar admits is a body the protocol
/// admits. The `_meta` member rides along on those types for the same reason.
pub struct SubscribeOperation;

impl SubscribeOperation {
    /// The wire method name for an intent. The pair is decided in exactly one place so the reader
    /// and the writer cannot come to disagree about which name means which direction. Consumed by
    /// the cfg-gated `subscribe_write_request` free fn (the read side matches the `METHOD_*` consts
    /// directly), so it is gated to the same builds to stay dead-code-free in production.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    fn method_for(intent: SubscribeIntent) -> &'static str {
        match intent {
            SubscribeIntent::Register => METHOD_RESOURCES_SUBSCRIBE,
            SubscribeIntent::Deregister => METHOD_RESOURCES_UNSUBSCRIBE,
        }
    }
}

impl OperationHandler for SubscribeOperation {
    /// A registration is one exchange, so every capability default is already correct: no
    /// streaming, no stream intent, no affinity, no usage tap. `taps_usage` stays FALSE because
    /// there are no tokens to tap — the response is an acknowledgement, and `IrResp::usage` states
    /// the flat meter that applies instead.
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(SubscribeReqHandle(read_subscribe_request(body)?)) as Box<dyn IrHandle>)
    }

    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(SubscribeRespHandle(read_subscribe_response(wire)?)) as Box<dyn IrHandle>)
    }
}

/// Wire -> concrete `SubscribeReq` parse, extracted from `SubscribeOperation::read_request` so the
/// dissolved `(mcp, Subscribe)` round-trip test can recover the concrete IR without a downcast. Used
/// in production by the trait `read_request` above.
pub(crate) fn read_subscribe_request(body: &[u8]) -> Result<SubscribeReq, IngressReject> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    // The envelope's own validity is `ingress::jsonrpc`'s business and is decided before a body
    // reaches a codec. What this reader owns is which of the two verbs was named, and the
    // `params` shape that goes with it.
    let method = v
        .get("method")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            IngressReject::BadRequest(
                "a subscription request names its method in `method`".to_string(),
            )
        })?;
    let params = v.get("params").cloned().ok_or_else(|| {
        IngressReject::BadRequest("a subscription request carries a `params` member".to_string())
    })?;
    // The SDK's parameter type IS the acceptance test — see the note on this struct. A body it
    // refuses is a body the protocol refuses, and the error it gives is the reason why.
    let (intent, target) = match method {
        METHOD_RESOURCES_SUBSCRIBE => {
            let p: SubscribeRequestParams = serde_json::from_value(params)
                .map_err(|e| IngressReject::BadRequest(e.to_string()))?;
            (SubscribeIntent::Register, p.uri)
        }
        METHOD_RESOURCES_UNSUBSCRIBE => {
            let p: UnsubscribeRequestParams = serde_json::from_value(params)
                .map_err(|e| IngressReject::BadRequest(e.to_string()))?;
            (SubscribeIntent::Deregister, p.uri)
        }
        other => {
            return Err(IngressReject::BadRequest(format!(
                "`{other}` is not a subscription method"
            )))
        }
    };
    // AN EMPTY TARGET NAMES NOTHING. A subscription to the empty string is not a narrower
    // subscription, it is an unanswerable one, and admitting it would hand the admission layer
    // a name it cannot judge.
    if target.is_empty() {
        return Err(IngressReject::BadRequest(
            "a subscription request names a non-empty target in `params.uri`".to_string(),
        ));
    }
    Ok(SubscribeReq {
        intent,
        target,
        extra: Default::default(),
    })
}

/// Wire -> concrete `SubscribeResp` parse (see [`read_subscribe_request`]).
pub(crate) fn read_subscribe_response(wire: &[u8]) -> Result<SubscribeResp, CodecError> {
    let v: serde_json::Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let result = v
        .get("result")
        .ok_or_else(|| CodecError::Malformed("no `result` member".to_string()))?;
    // AN EMPTY RESULT IS THE ACKNOWLEDGEMENT, NOT A MISSING ONE. MCP answers both verbs with an
    // empty object; a peer whose wire returns a registration record gets that record carried
    // through untouched. The two are kept distinct so neither has to be inferred later.
    let empty = result.as_object().is_some_and(serde_json::Map::is_empty) || result.is_null();
    Ok(SubscribeResp {
        registration: (!empty).then(|| result.clone()),
        extra: Default::default(),
    })
}

/// IR → subscription request wire — the former `SubscribeOperation::write_request` body, moved to a
/// free fn behind the `(mcp, Subscribe)` codec (G6 A4b: writes inverted off the trait onto the
/// handle, but Subscribe is same-protocol-only so its handle uses the empty default; this preserves
/// the round-trip codec logic for the `(mcp, Subscribe)` fidelity tests). Byte-identical.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn subscribe_write_request(r: &SubscribeReq) -> Bytes {
    // Built through the SDK's own constructor, so the member names and the `_meta` handling are
    // the SDK's rather than a second spelling of them here.
    let params = match r.intent {
        SubscribeIntent::Register => {
            serde_json::to_value(SubscribeRequestParams::new(r.target.clone()))
        }
        SubscribeIntent::Deregister => {
            serde_json::to_value(UnsubscribeRequestParams::new(r.target.clone()))
        }
    }
    .unwrap_or_else(|_| serde_json::json!({ "uri": r.target }));
    // The `id` is the ENGINE's, not the caller's, for the reason the invocation codec states:
    // correlation is decided on the way out and read back by `ingress::jsonrpc::read_response`.
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": SubscribeOperation::method_for(r.intent),
            "params": params,
        }))
        .unwrap_or_default(),
    )
}

/// IR → subscription response wire — the former `SubscribeOperation::write_response` body, moved to
/// a free fn (see [`subscribe_write_request`]). Byte-identical.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn subscribe_write_response(r: &SubscribeResp) -> WireBody {
    WireBody::json(Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            // Carried, never synthesised: a peer that returned no record does not acquire one
            // by passing through busbar, and the empty object is what the protocol asks for.
            "result": r.registration.clone().unwrap_or_else(|| serde_json::json!({})),
        }))
        .unwrap_or_default(),
    ))
}
