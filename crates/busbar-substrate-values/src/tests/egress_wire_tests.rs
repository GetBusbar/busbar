// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the write-default's terminal (`ir/handle.rs`, `wire.rs`, `handlers.rs`).

use crate::handlers::{
    CodecError, IngressReject, OperationHandler, TranslateCodec, TranslateReqInput,
    TranslateReqReject,
};
use crate::ir::egress_prep::EgressPrep;
use crate::ir::handle::IrHandle;
use crate::ir::invoke::InvokeReq;
use crate::ir::neutral_handles::InvokeReqHandle;
use crate::wire::EgressWire;

fn prep<'a>() -> EgressPrep<'a> {
    EgressPrep {
        ingress_protocol: "a-dialect",
        egress_requires_max_tokens: false,
        lane_default_max_tokens: None,
        global_default_max_tokens: 0,
        reasoning_allowed: true,
        reasoning_budgets: [0; 4],
        prompt_caching_allowed: true,
        cache_control_cap: None,
        thought_signature_fill: false,
    }
}

fn a_request() -> InvokeReqHandle {
    InvokeReqHandle(std::sync::Arc::new(InvokeReq {
        tool: "search".to_string(),
        arguments: serde_json::json!({"q": "the caller's own words"}),
        extra: Default::default(),
    }))
}

/// A handle that does not override the JSON egress write cannot write itself onto ANY dialect, and
/// says so. It used to answer with an empty body, which is not this request — it is a DIFFERENT
/// request forwarded upstream in the caller's name, whose first symptom is the backend's complaint
/// about a body busbar invented.
#[test]
fn the_write_default_is_unrepresentable_and_names_the_dialect() {
    let mut handle = a_request();
    match handle.write_egress_request("some-other-dialect", "a-model") {
        EgressWire::Unrepresentable { reason } => assert!(
            reason.contains("some-other-dialect"),
            "the refusal must name the dialect it could not be written onto, got: {reason}"
        ),
        EgressWire::Json(v) => panic!("the write default must not invent a body, got {v}"),
        EgressWire::Bytes(b) => panic!(
            "the write default must not answer with a body, got {} bytes",
            b.len()
        ),
    }
}

/// A codec whose read yields a handle that keeps the write default — the shape the translate seam
/// must refuse rather than forward.
struct DefaultWriteCodec;

impl OperationHandler for DefaultWriteCodec {
    fn read_request_value(
        &self,
        _v: &serde_json::Value,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(a_request()))
    }
    fn read_request(
        &self,
        _body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(a_request()))
    }
    fn read_response(&self, _wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Err(CodecError::Malformed("not a response codec".to_string()))
    }
}

/// The seam turns the unrepresentable write into the SAME refusal the pre-write representability
/// guard raises — a 4xx carrying the reason — instead of handing the router an empty body to send.
#[test]
fn the_translate_seam_refuses_an_unrepresentable_write() {
    let body = serde_json::json!({"tool": "search"});
    let reject = DefaultWriteCodec
        .translate_request(
            TranslateReqInput::Json(&body),
            Some("some-other-dialect"),
            &prep(),
            "a-model",
        )
        .err()
        .expect("a handle that cannot write itself must not yield an egress wire");
    match reject {
        TranslateReqReject::Unrepresentable(reason) => assert!(
            reason.contains("some-other-dialect"),
            "the reject carries the writer's own reason, got: {reason}"
        ),
        TranslateReqReject::Ingress(_) => panic!("the body parsed; this is not an ingress reject"),
        TranslateReqReject::EgressUnsupported => {
            panic!("the egress dialect was supplied; this is not the 404 terminal")
        }
    }
}
