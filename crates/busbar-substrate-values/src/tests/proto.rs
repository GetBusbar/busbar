//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// A name-only declaration: the boot fold and the test seam read nothing but `name`.
const fn named_decl(name: &'static str) -> ProtocolDecl {
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
        has_model_in_url: false,
        auth_failure_status_and_kind: (http::StatusCode::UNAUTHORIZED, ERR_TYPE_AUTHENTICATION),
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

static ROOTED: ProtocolDecl = named_decl("rooted");
static TEST_ONLY: ProtocolDecl = named_decl("test-only");

/// The interned-name fast path compares the two `&str`s' DATA POINTERS. A pointer alone does
/// not identify a string: a SUBSLICE of an interned name starts at the same address and is a
/// different name, so `as_ptr()` equality without a LENGTH check resolves `"root"` to the
/// declaration filed under `"rooted"` — a protocol name nothing declared, answered with another
/// protocol's codec, auth scheme and verbs.
#[test]
fn a_prefix_of_an_interned_name_is_not_that_name() {
    let reg = Registry::new([&ROOTED]);
    let prefix = &ROOTED.name[..4];
    assert_eq!(prefix, "root");
    assert_eq!(prefix.as_ptr(), ROOTED.name.as_ptr());
    assert!(
        reg.decl(prefix).is_none(),
        "a prefix of an interned protocol name resolved to the declaration it is a prefix of"
    );
    // The whole name still resolves, by pointer identity and by value alike.
    assert!(reg.decl(ROOTED.name).is_some());
    assert!(reg.decl(&String::from("rooted")).is_some());
}

/// The one test in this binary that installs a root: `install_protocols` is once per process.
/// A test-built binary with a real composition root must fold to the same declaration list
/// as the shipped one, with no re-declaration for the boot fold to skip audibly.
#[test]
fn the_test_seam_does_not_redeclare_what_the_root_installed() {
    install_protocols(vec![&ROOTED]);
    register_test_protocol(&ROOTED);
    register_test_protocol(&TEST_ONLY);
    let names: Vec<&str> = test_registered_protocols().iter().map(|d| d.name).collect();
    assert_eq!(
        names,
        ["test-only"],
        "a root-installed name must not enter the test set"
    );
    let folded: Vec<&str> = registry().decls().iter().map(|d| d.name).collect();
    assert_eq!(
        folded,
        ["rooted", "test-only"],
        "installed first, each name once"
    );
}
