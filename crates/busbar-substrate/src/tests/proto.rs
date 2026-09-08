//! Tests for `proto.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! ONE assertion, and it is the whole reason the fold exists: a declaration whose model is in the URL
//! path must arrive with an arrival. The success path is NOT tested here — both installs behind it are
//! set-once per process and this crate's test binary is shared — and it does not need to be: the two
//! installs are the leaf's and this crate's own, each already covered where it is defined. What is only
//! true HERE is that the parity is checked BEFORE either of them, so the refusal leaves both seams
//! unwritten rather than one of the two.

use super::*;

/// A name-only declaration with the one field this fold reads. Everything else is the neutral zero: the
/// parity check consults `name` and `has_model_in_url` and nothing more.
const fn path_model_decl(name: &'static str, has_model_in_url: bool) -> ProtocolDecl {
    ProtocolDecl {
        name,
        codec: None,
        handler: None,
        verbs: &[],
        head_keys: &[],
        streaming_content_type: None,
        array_stream_shim_key: None,
        native_tool_id_prefix: None,
        ingress_auth: IngressAuth::Bearer,
        egress_auth_headers: None,
        egress_auth_lane_constant: false,
        stream_usage_requires_opt_in: false,
        requires_max_tokens: false,
        stop_sequence_cap: None,
        cache_markers_model_gated: false,
        fills_thought_signature: false,
        frame_after_message_start: None,
        reshapes_body_at_path_base: false,
        max_cache_control_breakpoints: None,
        quota_exceeded_status: http::StatusCode::TOO_MANY_REQUESTS,
        ingress_is_eventstream: false,
        emits_sse_done_terminator: false,
        max_citations_per_delta: None,
        egress_user_agent: crate::proxy::EGRESS_UA_DEFAULT,
        has_model_in_url,
        auth_failure_status_and_kind: (
            http::StatusCode::UNAUTHORIZED,
            busbar_substrate_values::proto::ERR_TYPE_AUTHENTICATION,
        ),
        ingress_relays_amzn_headers: false,
        ingress_relayed_response_header_names: &[],
        auth_failure_message: "authentication failed",
        uses_array_stream_shim: false,
        has_native_path_not_found: false,
        egress_stream_accept: crate::proxy::TEXT_EVENT_STREAM,
        models_list_envelope: None,
        claims: None,
        residual_claims: None,
        residual_default: false,
        vendor_response_metadata: None,
        list_models_fingerprint_headers: &[],
    }
}

static URL_MODEL_WITHOUT_ARRIVAL: ProtocolDecl = path_model_decl("telex", true);

/// A path-model declaration installed with NO arrival would resolve no arrival and fall through to the
/// body-model branch — a silent, 404-shaped wrong answer on a protocol the operator did install. The
/// fold refuses the boot instead, and refuses it BEFORE either seam is written: this test's process
/// never reaches `install_protocols`, so a panic here is the guard and not an install.
#[test]
#[should_panic(expected = "registered no path_ingress arrival")]
fn a_url_model_declaration_without_its_arrival_refuses_the_boot() {
    install_protocols_with_path_ingress(vec![&URL_MODEL_WITHOUT_ARRIVAL], Vec::new());
}
