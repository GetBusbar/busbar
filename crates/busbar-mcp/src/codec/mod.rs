// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PROTOCOL CODEC — the `codec` module of `busbar-mcp`.
//!
//! The MCP dialect, on the seam the LLM protocol crate proved. The files here are the per-dialect
//! template `one-core-mcp-a2a-as-protocols.md` bars — this file (the declaration, the dialect's
//! wire vocabulary and the notification codec), `handler.rs` (which operations it serves),
//! `invoke.rs` and `subscribe.rs` (the two cells), and `tests/` (its own tests, nobody else's).
//! Everything it consumes from the engine comes through `busbar-core`'s public surface; nothing in
//! `busbar-core` names this crate in production (`git grep busbar_mcp crates/busbar-core/src` is
//! pinned at zero) — the `busbar` BINARY, the composition root, links `busbar-mcp` and hands
//! [`DECL`] (which `busbar-mcp` re-exports as its `PROTO_DECL`) to
//! the substrate's protocol registry (`busbar_substrate_values::proto::install_protocols`) at boot. Delete the dependency edge and busbar
//! still builds, boots, refuses `protocol: mcp` config with the unknown-protocol refusal, and
//! serves the remaining dialects — that build is a gate, not a thought experiment.
//!
//! ## WHAT THIS MODULE IS, AND — SAID PLAINLY — WHAT IT IS NOT
//!
//! This module is MCP **the protocol**: the registry declaration, the JSON-RPC dialect, and the two
//! operation cells (`tools/call` and the subscription pair) that core resolves through the support
//! matrix. That is the whole of what `handlers/mcp.rs` was, and it moved here intact.
//!
//! It is distinct from the `mcp` PLANE — the sibling `mcp` module of `busbar-mcp` (~18k lines:
//! the catalogue, the call log, the client pool and its transports, the config sections, the
//! ask/approval state, the admin projections). That surface once wired into core through `AppState`
//! fields, the `tools:` config section, boot hydration, the router mount and the admin API — call
//! edges none of which a `&'static ProtocolDecl` could carry, because a `ProtocolDecl` deliberately
//! takes a handle to nothing (`design/protocol-plugin-abi.md` §"Not one method takes a handle to
//! anything"). The plane extraction neutralized every one of those edges onto the neutral
//! `busbar-substrate` seams (the plane-host trait, the config-section split, the hostless-egress and
//! task seams), and the plane folded into `busbar-mcp` beside this codec — ONE plugin per protocol.
//! MCP the protocol and MCP the plane are the same protocol, behind the one `plane-mcp` switch.
//!
//! **The consequence for the deletion gate, stated rather than discovered:** compiling this crate
//! out removes MCP as a *protocol* — `protocol: mcp` stops resolving and its two cells stop
//! existing. It does not remove the `tools:` plane's `/mcp` mount, which is gated by its own config
//! section. Deleting the plane is the plane-kind seam's job, not this codec's, and the gate here
//! measures exactly the edge this codec owns.
//!
//! ## DUAL COMPILATION
//!
//! Stated so the `#[path]` in core is not read as a leak: `busbar-core`'s test/`test-support`
//! builds compile these same sources back in as `handlers::mcp` (via `extern crate self as
//! busbar_kernel`), so the pre-extraction fixture surface keeps proving what it always proved without
//! core's PRODUCTION build knowing this dialect exists. That is why every core reference in these
//! files is spelled through the neutral crates (`busbar_substrate_values::` / `busbar_api::`) and every self
//! reference is relative.

pub mod handler;
mod invoke;
mod subscribe;

/// MCP'S DECLARATION — and the asymmetry in it is the point. MCP declares a HANDLER and NO CODEC:
/// its IR is its own, there is no cross-dialect translation into or out of it, and it point-reads no
/// top-level body key on the pre-materialized path (its method lives in the JSON-RPC envelope, which
/// `busbar_substrate_values::ingress::jsonrpc` parses). A registry that could only hold six-of-a-kind would have
/// had to grow a special case for it; this one holds a declaration that says `None` four times.
///
/// Handed to `install_protocols` by the composition root (the `busbar` binary); in `busbar-core`'s
/// test/`test-support` builds it is instead the cfg-gated built-in row, so the fixture registry the
/// tests see matches the registry a shipped binary has.
pub const DECL: busbar_substrate_values::proto::ProtocolDecl =
    busbar_substrate_values::proto::ProtocolDecl {
        name: busbar_plane_mcp::PLANE_KEY,
        codec: None,
        handler: Some(&handler::McpRequestHandler),
        verbs: &[
            busbar_api::operation::Operation::INVOKE,
            busbar_api::operation::Operation::SUBSCRIBE,
        ],
        head_keys: &[],
        streaming_content_type: None,
        array_stream_shim_key: None,
        native_tool_id_prefix: None,
        ingress_auth: busbar_substrate_values::proto::IngressAuth::Bearer,
        // The shared bearer/api-key/SigV4 schemes stay in `egress_auth::resolve`: MCP presents no
        // dialect-specific egress credential shaping of its own, so it declares no builder — unlike
        // Anthropic, whose api-key/Bearer disambiguation retired its arm in core.
        egress_auth_headers: None,
        egress_auth_lane_constant: false,
        // NO PATH INGRESS (model in the BODY): `has_model_in_url` is false below, so this dialect
        // registers no arrival and the catch-all resolves its operation through the `RequestHandler`
        // on the universal ingress. The arrival is no longer a decl field (Batch C-6).
        stream_usage_requires_opt_in: false,
        // ── Promoted writer facts (G6 step A1): MCP declares NO codec and has no writer, so every
        //    promoted fact is the `ProtocolWriter` trait DEFAULT — the same value core read for a
        //    protocol with no override. These are inert for MCP (its facts are never consulted through a
        //    writer that does not exist) but the declaration must state them.
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
        egress_user_agent: busbar_substrate_values::proxy::EGRESS_UA_DEFAULT,
        has_model_in_url: false,
        auth_failure_status_and_kind: (
            http::StatusCode::UNAUTHORIZED,
            busbar_substrate_values::proto::ERR_TYPE_AUTHENTICATION,
        ),
        ingress_relays_amzn_headers: false,
        ingress_relayed_response_header_names: &[],
        auth_failure_message: "authentication failed",
        uses_array_stream_shim: false,
        has_native_path_not_found: false,
        // MCP ships no cross-dialect codec, so this is never consulted for a translated egress; it
        // carries the neutral SSE default the by-name `egress_accept` fallback would have returned.
        egress_stream_accept: busbar_substrate_values::proxy::TEXT_EVENT_STREAM,
        // MCP is not an LLM chat dialect and serves no `/v1/models` discovery surface.
        models_list_envelope: None,
        // MCP is identified by its EXPLICIT mount (`/mcp`), never by a wire fingerprint — so it claims
        // no router or residual rung, and core's detection fold never resolves to it from a path/header
        // sniff. It contributes no untranslatable vendor response metadata and is not the residual
        // default.
        claims: None,
        residual_claims: None,
        residual_default: false,
        vendor_response_metadata: None,
        // MCP serves no model-discovery surface, so it declares no list-models fingerprint header.
        list_models_fingerprint_headers: &[],
    };

#[cfg(test)]
#[path = "tests/mcp_tests.rs"]
mod tests;
