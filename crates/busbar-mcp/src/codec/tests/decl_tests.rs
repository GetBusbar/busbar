// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP'S DECLARATION, PINNED FIELD BY FIELD. [`DECL`] states only its handler and its two verbs and
//! takes every other field from the substrate's neutral row (`ProtocolDecl::named`). That keeps the
//! declaration from restating forty "no"s, and it also means a change to the neutral row would
//! reach MCP without anyone touching this crate. So every value MCP declared when it wrote each field
//! out is asserted here as a LITERAL, not compared against the neutral row. A drift in the row that
//! would move MCP's registry entry fails this test rather than shipping.

use super::*;
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::ProtocolDecl;

#[test]
fn the_mcp_decl_is_the_neutral_row_but_for_its_handler_and_verbs() {
    let d = &DECL;
    assert_eq!(d.name, busbar_plane_mcp::PLANE_KEY);
    assert!(d.codec.is_none(), "MCP declares no codec");
    assert!(d.handler.is_some(), "MCP declares its request handler");
    assert_eq!(d.verbs, &[OpVerb::INVOKE, OpVerb::SUBSCRIBE]);
    assert!(d.head_keys.is_empty());
    assert!(d.array_stream_shim_key.is_none());
    assert!(d.native_tool_id_prefix.is_none());
    // The ingress scheme is the one every protocol but the signed-request dialect declares — the
    // neutral row's own value, which is what MCP wrote out.
    assert_eq!(
        d.ingress_auth,
        ProtocolDecl::named("neutral-row").ingress_auth
    );
    assert!(
        d.egress_auth_headers.is_none(),
        "no egress credential builder"
    );
    assert!(!d.egress_auth_lane_constant);
    assert!(!d.stream_usage_requires_opt_in);
    assert!(!d.requires_max_tokens);
    assert!(d.stop_sequence_cap.is_none());
    assert!(!d.cache_markers_model_gated);
    assert!(!d.fills_thought_signature);
    assert!(d.frame_after_message_start.is_none());
    assert!(!d.reshapes_body_at_path_base);
    assert!(d.max_cache_control_breakpoints.is_none());
    assert_eq!(d.quota_exceeded_status, http::StatusCode::TOO_MANY_REQUESTS);
    assert!(!d.ingress_is_eventstream);
    assert!(!d.emits_sse_done_terminator);
    assert!(d.max_citations_per_delta.is_none());
    assert_eq!(
        d.egress_user_agent,
        busbar_contract::protocol::EGRESS_UA_DEFAULT
    );
    assert!(
        !d.has_model_in_url,
        "the model is in the BODY: no path ingress"
    );
    assert_eq!(
        d.auth_failure_status_and_kind,
        (
            http::StatusCode::UNAUTHORIZED,
            busbar_contract::protocol::ERR_TYPE_AUTHENTICATION
        )
    );
    assert!(!d.ingress_relays_amzn_headers);
    assert!(d.ingress_relayed_response_header_names.is_empty());
    assert_eq!(d.auth_failure_message, "authentication failed");
    assert!(!d.uses_array_stream_shim);
    assert!(!d.has_native_path_not_found);
    assert_eq!(
        d.egress_stream_accept,
        busbar_contract::protocol::TEXT_EVENT_STREAM
    );
    assert!(
        d.models_list_envelope.is_none(),
        "no model discovery surface"
    );
    assert!(d.claims.is_none(), "identified by its mount, never sniffed");
    assert!(d.residual_claims.is_none());
    assert!(!d.residual_default);
    assert!(d.vendor_response_metadata.is_none());
    assert!(d.list_models_fingerprint_headers.is_empty());
}

/// THE PLANE'S OPERATOR-VISIBLE IDENTITY, pinned as LITERALS by the plane that declares it: the key
/// metrics, logs and record prefixes carry, the audit resource kind every recorded action word is
/// built from (`mcp_server.connect`), the grant kinds, and the ONE wire format its three transports
/// carry (so the plane has earned no superset IR). Moved here from busbar-kernel's
/// `registry_cross_plane.rs` / `plane_dispatch_cross_plane.rs` (K3; architect ruling N02): the kernel
/// now asserts its by-key surfaces answer whatever each linked plane declares, and each plane pins
/// what it declares.
#[test]
fn the_plane_declares_its_published_identity_and_one_wire_format() {
    let d = &crate::PLANE_DECLARATION;
    assert_eq!(d.key, "mcp");
    assert!(!d.fallback, "a mounted plane, never the catch-all");
    assert_eq!(d.config_section, "tools");
    assert_eq!(d.owned_config_sections, &["mcp"]);
    assert_eq!(d.audit_kind, "mcp_server");
    assert_eq!(
        format!("{}.connect", d.audit_kind),
        "mcp_server.connect",
        "the connect action word is a published audit string and may not change shape"
    );
    assert_eq!(d.scope_kinds, &["mcp_server", "mcp_tool"]);
    assert_eq!(d.subject_noun, "MCP server");
    assert_eq!(
        (crate::PLANE_HOOKS.wire_format_names)(),
        &[busbar_contract::transport::transport::plane::WIRE_JSONRPC],
        "three transports, ONE wire format"
    );
}
