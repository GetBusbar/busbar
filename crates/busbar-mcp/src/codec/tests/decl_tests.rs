// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP'S DECLARATION, PINNED FIELD BY FIELD. [`DECL`] states only its handler and its two verbs and
//! takes every other field from the substrate's neutral row (`ProtocolDecl::named`). That keeps the
//! declaration from restating forty "no"s, and it also means a change to the neutral row would
//! reach MCP without anyone touching this crate. So every value MCP declared when it wrote each field
//! out is asserted here as a LITERAL, not compared against the neutral row. A drift in the row that
//! would move MCP's registry entry fails this test rather than shipping.

use super::*;
use busbar_api::operation::Operation;
use busbar_substrate_values::proto::ProtocolDecl;

#[test]
fn the_mcp_decl_is_the_neutral_row_but_for_its_handler_and_verbs() {
    let d = &DECL;
    assert_eq!(d.name, busbar_plane_mcp::PLANE_KEY);
    assert!(d.codec.is_none(), "MCP declares no codec");
    assert!(d.handler.is_some(), "MCP declares its request handler");
    assert_eq!(d.verbs, &[Operation::INVOKE, Operation::SUBSCRIBE]);
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
        busbar_substrate_values::proxy::EGRESS_UA_DEFAULT
    );
    assert!(
        !d.has_model_in_url,
        "the model is in the BODY: no path ingress"
    );
    assert_eq!(
        d.auth_failure_status_and_kind,
        (
            http::StatusCode::UNAUTHORIZED,
            busbar_substrate_values::proto::ERR_TYPE_AUTHENTICATION
        )
    );
    assert!(!d.ingress_relays_amzn_headers);
    assert!(d.ingress_relayed_response_header_names.is_empty());
    assert_eq!(d.auth_failure_message, "authentication failed");
    assert!(!d.uses_array_stream_shim);
    assert!(!d.has_native_path_not_found);
    assert_eq!(
        d.egress_stream_accept,
        busbar_substrate_values::proxy::TEXT_EVENT_STREAM
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
