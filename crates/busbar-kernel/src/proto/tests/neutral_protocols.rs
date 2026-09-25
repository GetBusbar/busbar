// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL TEST BINARY'S PROTOCOL SET — seven SYNTHETIC declarations with neutral names, so the
//! kernel's own `#[cfg(test)]` binary has a protocol registry to validate, route and frame over
//! without naming a plane crate ("a plugin tests itself; the kernel never tests or names a plugin").
//!
//! Each row carries only the SHAPE the kernel's tests exercise, never a dialect's bytes: six rows
//! with a trivial passthrough codec (the codec protocols `known_protocols()` lists) and one
//! codec-less row serving `invoke`. Between them they declare every family verb, one residual
//! default, one lane-constant and one request-signing egress builder, and one SigV4-ingress row
//! claiming the `/model/` residual path. THE ORDER IS FIXED: tests read these rows by position.

use axum::http::{header::AUTHORIZATION, HeaderName, HeaderValue, StatusCode};
use busbar_api::operation::Operation;
use busbar_substrate_values::breaker::{CanonicalSignal, RawUpstreamError};
use busbar_substrate_values::handlers::{
    CodecError, IngressReject, OperationHandler, RequestHandler,
};
use busbar_substrate_values::ir::handle::IrHandle;
use busbar_substrate_values::proto::{
    ArrayStreamFramer, ClaimStrength, DialectCodec, IngressAuth, ProtocolDecl, SigningContext,
    ERR_TYPE_PERMISSION,
};
use busbar_substrate_values::{billing::TokenUsage, wire::EgressCtx};
use serde_json::{json, Map, Value};

/// The passthrough codec: says nothing a dialect would say, and changes no body.
struct Passthrough;

impl DialectCodec for Passthrough {
    fn probe_body(&self, _model: &str) -> Vec<u8> {
        b"{}".to_vec()
    }
    fn apply_rewrite_to_ingress_body(
        &self,
        _: &mut Map<String, Value>,
        _: &[Value],
        _: &[Value],
    ) -> bool {
        false
    }
    fn recover_truncated_usage(&self, _tail: &[u8]) -> Option<TokenUsage> {
        None
    }
    fn ingress_response_request_id(&self, _: Option<&str>) -> Option<(&'static str, String)> {
        None
    }
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> Value {
        json!({ "error": { "type": kind, "message": message } })
    }
    fn requested_candidate_count(&self, _body: &Value) -> Option<u64> {
        None
    }
    fn write_response_exception(&self, _: &CanonicalSignal) -> Option<(String, String)> {
        None
    }
    fn write_error_frame(&self, _: &CanonicalSignal) -> Option<(String, Value)> {
        None
    }
    fn wants_array_stream(&self, _body: &Value) -> bool {
        false
    }
    fn inject_response_metrics(&self, _value: &mut Value, _elapsed_ms: Option<u64>) {}
    fn attach_error_response_headers(&self, _: &mut axum::http::HeaderMap, _: &str, _: &Value) {}
    fn extract_error(&self, status: u16, _body: &[u8]) -> RawUpstreamError {
        RawUpstreamError::from_status(status)
    }
    fn make_array_stream_framer(&self) -> Option<Box<dyn ArrayStreamFramer>> {
        None
    }
    fn upstream_path_for_stream(&self, _model: &str, _stream: bool) -> String {
        "/".to_string()
    }
    fn rewrite_model_if_needed(&self, _body: &mut Value, _model: &str) -> bool {
        false
    }
    fn reshape_for_path_base(&self, _body: &mut Value) -> bool {
        false
    }
}

/// The one operation cell every verb of every row answers with: the trait's defaults, and a wire it
/// never decodes (no kernel-lib test drives a body through a synthetic cell).
struct Cell;

impl OperationHandler for Cell {
    fn read_request(&self, _: &[u8], _: &str) -> Result<Box<dyn IrHandle>, IngressReject> {
        Err(IngressReject::BadRequest("synthetic protocol".into()))
    }
    fn read_response(&self, _wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Err(CodecError::Malformed("synthetic protocol".into()))
    }
}

/// A row's request handler: its name, and a cell for each verb it declares.
struct Handler(&'static str, &'static [Operation]);

impl RequestHandler for Handler {
    fn protocol_name(&self) -> &'static str {
        self.0
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        self.1
            .contains(&op)
            .then_some(&Cell as &dyn OperationHandler)
    }
    fn resolve_operation(&self, _path: &str, _body: &[u8]) -> Option<Operation> {
        None
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        "/".to_string()
    }
}

/// A static scheme: the credential in one header, whatever the request.
fn static_header(cred: &str, _: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
    vec![(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {cred}")).expect("header"),
    )]
}

/// A request signer: the header covers the body, the time and the path.
fn signed_header(cred: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
    let sig = format!(
        "{cred}/{}/{}/{}",
        ctx.body.len(),
        ctx.timestamp_epoch,
        ctx.canonical_uri
    );
    vec![(
        HeaderName::from_static("x-test-signature"),
        HeaderValue::from_str(&sig).expect("header"),
    )]
}

fn claims_model_prefix(path: &str) -> Option<ClaimStrength> {
    path.starts_with("/model/").then_some(ClaimStrength(1))
}

const FAMILY: &[Operation] = &[
    Operation::CHAT,
    Operation::EMBEDDINGS,
    Operation::MODERATION,
    Operation::IMAGE,
    Operation::TRANSCRIPTION,
    Operation::SPEECH,
    Operation::RERANK,
];
const CHAT: &[Operation] = &[Operation::CHAT];
const INVOKE: &[Operation] = &[Operation::INVOKE];

/// A codec row: the passthrough codec, a handler serving `verbs`.
const fn codec_row(name: &'static str, handler: &'static Handler) -> ProtocolDecl {
    ProtocolDecl {
        codec: Some(&Passthrough),
        handler: Some(handler),
        verbs: handler.1,
        ..ProtocolDecl::named(name)
    }
}

static A: ProtocolDecl = ProtocolDecl {
    egress_auth_headers: Some(static_header),
    egress_auth_lane_constant: true,
    ..codec_row("proto-a", &Handler("proto-a", CHAT))
};
static B: ProtocolDecl = ProtocolDecl {
    residual_default: true,
    ..codec_row("proto-b", &Handler("proto-b", FAMILY))
};
static C: ProtocolDecl = codec_row("proto-c", &Handler("proto-c", CHAT));
static D: ProtocolDecl = ProtocolDecl {
    ingress_auth: IngressAuth::SigV4,
    auth_failure_status_and_kind: (StatusCode::FORBIDDEN, ERR_TYPE_PERMISSION),
    egress_auth_headers: Some(signed_header),
    residual_claims: Some(claims_model_prefix),
    ..codec_row("proto-d", &Handler("proto-d", CHAT))
};
static E: ProtocolDecl = codec_row("proto-e", &Handler("proto-e", CHAT));
static F: ProtocolDecl = codec_row("proto-f", &Handler("proto-f", CHAT));
static G: ProtocolDecl = ProtocolDecl {
    handler: Some(&Handler("proto-g", INVOKE)),
    verbs: INVOKE,
    ..ProtocolDecl::named("proto-g")
};

/// The seven rows, in their fixed order.
pub(crate) static NEUTRAL_PROTOCOLS: &[&ProtocolDecl] = &[&A, &B, &C, &D, &E, &F, &G];
