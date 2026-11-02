// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::billing::TokenUsage;
use busbar_contract::codec::{
    CodecError, CodecHost, EgressCtx, IngressReject, OperationHandler, RequestHandler,
};
use busbar_contract::ir::handle::IrHandle;
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::{
    ArrayStreamFramer, ClaimStrength, DialectCodec, IngressAuth, ProtocolDecl, SigningContext,
    ERR_TYPE_PERMISSION,
};
use busbar_contract::upstream::{CanonicalSignal, RawUpstreamError};
use serde_json::{json, Map, Value};

struct Passthrough;

impl DialectCodec for Passthrough {
    fn probe_body(&self, _: &dyn CodecHost, _model: &str) -> Vec<u8> {
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
    fn ingress_response_request_id(
        &self,
        _: &dyn CodecHost,
        _: Option<&str>,
    ) -> Option<(&'static str, String)> {
        None
    }
    fn write_error(&self, _: &dyn CodecHost, _status: u16, kind: &str, message: &str) -> Value {
        json!({ "error": { "type": kind, "message": message } })
    }
    fn requested_candidate_count(&self, _body: &Value) -> Option<u64> {
        None
    }
    fn write_response_exception(
        &self,
        _: &dyn CodecHost,
        _: &CanonicalSignal,
    ) -> Option<(String, String)> {
        None
    }
    fn write_error_frame(&self, _: &dyn CodecHost, _: &CanonicalSignal) -> Option<(String, Value)> {
        None
    }
    fn wants_array_stream(&self, _body: &Value) -> bool {
        false
    }
    fn inject_response_metrics(&self, _value: &mut Value, _elapsed_ms: Option<u64>) {}
    fn error_response_fields(
        &self,
        _: &dyn CodecHost,
        _: &str,
        _: &Value,
    ) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }
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

struct Cell;

impl OperationHandler for Cell {
    fn read_request(&self, _: &[u8], _: &str) -> Result<Box<dyn IrHandle>, IngressReject> {
        Err(IngressReject::BadRequest("synthetic protocol".into()))
    }
    fn read_response(
        &self,
        _host: &dyn CodecHost,
        _wire: &[u8],
    ) -> Result<Box<dyn IrHandle>, CodecError> {
        Err(CodecError::Malformed("synthetic protocol".into()))
    }
}

struct Handler(&'static str, &'static [OpVerb]);

impl RequestHandler for Handler {
    fn protocol_name(&self) -> &'static str {
        self.0
    }
    fn operation_handler(&self, op: OpVerb) -> Option<&dyn OperationHandler> {
        self.1
            .contains(&op)
            .then_some(&Cell as &dyn OperationHandler)
    }
    fn resolve_operation(&self, _path: &str, _body: &[u8]) -> Option<OpVerb> {
        None
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        "/".to_string()
    }
}

fn static_header(cred: &str, _: &SigningContext) -> Vec<(String, Vec<u8>)> {
    vec![(
        "authorization".to_string(),
        format!("Bearer {cred}").into_bytes(),
    )]
}

fn signed_header(cred: &str, ctx: &SigningContext) -> Vec<(String, Vec<u8>)> {
    let sig = format!(
        "{cred}/{}/{}/{}",
        ctx.body.len(),
        ctx.timestamp_epoch,
        ctx.canonical_uri
    );
    vec![("x-test-signature".to_string(), sig.into_bytes())]
}

fn claims_model_prefix(path: &str) -> Option<ClaimStrength> {
    path.starts_with("/model/").then_some(ClaimStrength(1))
}

const FAMILY: &[OpVerb] = &[
    OpVerb::CHAT,
    OpVerb::EMBEDDINGS,
    OpVerb::MODERATION,
    OpVerb::IMAGE,
    OpVerb::TRANSCRIPTION,
    OpVerb::SPEECH,
    OpVerb::RERANK,
];
const CHAT: &[OpVerb] = &[OpVerb::CHAT];
const INVOKE: &[OpVerb] = &[OpVerb::INVOKE];

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
    egress_scheme: None,
    ..codec_row("proto-a", &Handler("proto-a", CHAT))
};
static B: ProtocolDecl = ProtocolDecl {
    residual_default: true,
    ..codec_row("proto-b", &Handler("proto-b", FAMILY))
};
static C: ProtocolDecl = codec_row("proto-c", &Handler("proto-c", CHAT));
static D: ProtocolDecl = ProtocolDecl {
    ingress_auth: IngressAuth::SigV4,
    auth_failure_status_and_kind: (403, ERR_TYPE_PERMISSION),
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

pub(crate) static NEUTRAL_PROTOCOLS: &[&ProtocolDecl] = &[&A, &B, &C, &D, &E, &F, &G];
