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
//! [`crate::PROTO_DECL`] (this module's [`DECL`]) to
//! `busbar_core::proto::registry::install_protocols` at boot. Delete the dependency edge and busbar
//! still builds, boots, refuses `protocol: mcp` config with the unknown-protocol refusal, and
//! serves the remaining dialects — that build is a gate, not a thought experiment.
//!
//! ## WHAT THIS MODULE IS, AND — SAID PLAINLY — WHAT IT IS NOT
//!
//! This module is MCP **the protocol**: the registry declaration, the JSON-RPC dialect, and the two
//! operation cells (`tools/call` and the subscription pair) that core resolves through the support
//! matrix. That is the whole of what `handlers/mcp.rs` was, and it moved here intact.
//!
//! It is **not** the `mcp/` PLANE (`crates/busbar-core/src/mcp`, ~18k lines): the catalogue, the
//! call log, the client pool and its transports, the config sections, the ask/approval state, the
//! admin projections. That surface is wired into core through `AppState` fields, the `tools:`
//! config section, boot hydration, the router mount and the admin API — 62 production call edges,
//! none of which a `&'static ProtocolDecl` can carry, because a `ProtocolDecl` deliberately takes a
//! handle to nothing (`design/protocol-plugin-abi.md` §"Not one method takes a handle to
//! anything"). There is no plane-kind seam in core to leave through yet, so the plane stays in core
//! for now — it folds into `busbar-mcp` beside this codec in a later plane-split step, and this
//! module does not pretend it has already arrived.
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
//! busbar_core`), so the pre-extraction fixture surface keeps proving what it always proved without
//! core's PRODUCTION build knowing this dialect exists. That is why every core reference in these
//! files is spelled `busbar_core::` and every self reference is relative.

pub mod handler;
mod invoke;
mod subscribe;

use rmcp::model::{
    CallToolRequestMethod, ConstString, ResourceUpdatedNotificationMethod,
    ResourceUpdatedNotificationParam, SubscribeRequestMethod, ToolListChangedNotificationMethod,
    UnsubscribeRequestMethod,
};

use bytes::Bytes;

/// The single mount path. MCP names the operation in the BODY (`method`), not the path — the
/// opposite of OpenAI, and the reason [`handler::McpRequestHandler::resolve_operation`] reads the
/// body.
pub(crate) const PATH_MCP: &str = "/mcp";

/// The JSON-RPC method names this dialect serves, each read off `rmcp`'s own const-string type
/// rather than spelled again here. `ConstString::VALUE` is a `const`, so these are compile-time
/// literals with no runtime cost — and a name the SDK retires stops compiling instead of being
/// served.
pub(crate) const METHOD_TOOLS_CALL: &str = CallToolRequestMethod::VALUE;
pub(crate) const METHOD_RESOURCES_SUBSCRIBE: &str = SubscribeRequestMethod::VALUE;
pub(crate) const METHOD_RESOURCES_UNSUBSCRIBE: &str = UnsubscribeRequestMethod::VALUE;
/// `allow(dead_code)` under `not(test)` for the DUAL-COMPILED shape only: in this crate's own
/// build these are `pub` and reachable, but core's `test-support` build compiles them into a
/// private module where the notification half has no caller until the server-to-client channel
/// is mounted. Same attribute the pre-extraction file carried, for the same reason.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const METHOD_NOTIFY_TOOLS_LIST_CHANGED: &str = ToolListChangedNotificationMethod::VALUE;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const METHOD_NOTIFY_RESOURCES_UPDATED: &str = ResourceUpdatedNotificationMethod::VALUE;

/// MCP'S DECLARATION — and the asymmetry in it is the point. MCP declares a HANDLER and NO CODEC:
/// its IR is its own, there is no cross-dialect translation into or out of it, and it point-reads no
/// top-level body key on the pre-materialized path (its method lives in the JSON-RPC envelope, which
/// `busbar_substrate::ingress::jsonrpc` parses). A registry that could only hold six-of-a-kind would have
/// had to grow a special case for it; this one holds a declaration that says `None` four times.
///
/// Handed to `install_protocols` by the composition root (the `busbar` binary); in `busbar-core`'s
/// test/`test-support` builds it is instead the cfg-gated built-in row, so the fixture registry the
/// tests see matches the registry a shipped binary has.
pub const DECL: busbar_core::proto::ProtocolDecl = busbar_core::proto::ProtocolDecl {
    name: "mcp",
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
    ingress_auth: busbar_core::proto::IngressAuth::Bearer,
    // The shared bearer/api-key/SigV4 schemes stay in `egress_auth::resolve`: MCP presents no
    // dialect-specific egress credential shaping of its own, so it declares no builder — unlike
    // Anthropic, whose api-key/Bearer disambiguation retired its arm in core.
    egress_auth_headers: None,
    // NO PATH INGRESS: this dialect keeps its model in the BODY, so the catch-all resolves the
    // operation through the `RequestHandler` and serves it on the universal ingress.
    path_ingress: None,
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
    quota_exceeded_status: axum::http::StatusCode::TOO_MANY_REQUESTS,
    ingress_is_eventstream: false,
    emits_sse_done_terminator: false,
    max_citations_per_delta: None,
    egress_user_agent: busbar_core::proxy::EGRESS_UA_DEFAULT,
    has_model_in_url: false,
    auth_failure_status_and_kind: (
        axum::http::StatusCode::UNAUTHORIZED,
        busbar_core::proto::openai_family::ERR_TYPE_AUTHENTICATION,
    ),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[],
    auth_failure_message: "authentication failed",
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    // MCP ships no cross-dialect codec, so this is never consulted for a translated egress; it
    // carries the neutral SSE default the by-name `egress_accept` fallback would have returned.
    egress_stream_accept: busbar_substrate::proxy::TEXT_EVENT_STREAM,
    // MCP is not an LLM chat dialect and serves no `/v1/models` discovery surface.
    models_list_envelope: None,
};

// ══ THE NOTIFICATION HALF ════════════════════════════════════════════════════════════════════════

/// THE SERVER-ORIGINATED NOTIFICATIONS THIS PROTOCOL CARRIES, and the reason a subscription is worth
/// registering at all.
///
/// ## WHY THIS IS NOT AN `OperationHandler`
///
/// A notification has no id, no answer and no correlation: JSON-RPC 2.0 section 4.1 forbids replying
/// to one. It is therefore not a request/response codec and modelling it as one would give it a
/// response half that must never be produced. It sits beside the codecs, in the protocol's own
/// crate, because the thing it is specific to is the DIALECT — the same reason the JSON-RPC envelope
/// itself is read once, in one place, for every plane that speaks it.
///
/// ## BOTH DIRECTIONS READ THE SAME BYTES
///
/// When busbar is the server it EMITS these to its caller; when busbar is the client it RECEIVES
/// them from an upstream. That is one wire message and two directions of travel, so it is one
/// reader and one writer here rather than a pair per direction — which is exactly the arrangement
/// that stopped the JSON-RPC envelope from being parsed two ways that disagreed.
///
/// ## WHAT A RECEIVED `notifications/tools/list_changed` MAY AND MAY NOT DO
///
/// It is a HINT, and it arrives from a party whose timing and content are not busbar's to trust. It
/// may prompt a re-read of a catalogue through the ordinary approval path; it may never itself
/// install, approve or promote anything, because that would let the party being catalogued decide
/// when its own catalogue is believed. This type carries the message and takes no such action, which
/// is what keeps that decision at the call site that has the approval context.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpNotification {
    /// The peer's tool list is no longer what it was.
    ToolsListChanged,
    /// A subscribed resource changed. The delivery half of [`subscribe::SubscribeOperation`].
    ResourceUpdated {
        /// The resource that changed, in the peer's vocabulary.
        uri: String,
    },
}

#[cfg_attr(not(test), allow(dead_code))]
impl McpNotification {
    /// The wire method name, off `rmcp`'s const-string types.
    pub fn method(&self) -> &'static str {
        match self {
            McpNotification::ToolsListChanged => METHOD_NOTIFY_TOOLS_LIST_CHANGED,
            McpNotification::ResourceUpdated { .. } => METHOD_NOTIFY_RESOURCES_UPDATED,
        }
    }

    /// Read a notification that has ALREADY been established as a JSON-RPC notification envelope by
    /// `busbar_substrate::ingress::jsonrpc`. `None` means "a notification this protocol does not carry",
    /// which is the correct answer to give and the correct thing to do nothing about: section 4.1
    /// forbids replying, so an unknown notification is dropped rather than refused.
    pub fn read(method: &str, params: Option<&serde_json::Value>) -> Option<Self> {
        match method {
            METHOD_NOTIFY_TOOLS_LIST_CHANGED => Some(McpNotification::ToolsListChanged),
            METHOD_NOTIFY_RESOURCES_UPDATED => {
                // The SDK's parameter type is the acceptance test here too: a notification that
                // names no resource says a resource changed without saying which, and acting on it
                // would mean guessing.
                let p: ResourceUpdatedNotificationParam =
                    serde_json::from_value(params?.clone()).ok()?;
                (!p.uri.is_empty()).then_some(McpNotification::ResourceUpdated { uri: p.uri })
            }
            _ => None,
        }
    }

    /// The complete JSON-RPC notification envelope for this message.
    ///
    /// **There is no `id` member and there must never be one.** Section 4.1 makes the absence of
    /// `id` the definition of a notification; an id would make this a request, and a request obliges
    /// the receiver to answer something busbar is not waiting for.
    pub fn write(&self) -> Bytes {
        let mut envelope = serde_json::json!({ "jsonrpc": "2.0", "method": self.method() });
        if let McpNotification::ResourceUpdated { uri } = self {
            // `params` is emitted only where the message has any, so the notification that carries
            // none stays byte-identical to what the specification describes.
            envelope["params"] =
                serde_json::to_value(ResourceUpdatedNotificationParam::new(uri.clone()))
                    .unwrap_or_else(|_| serde_json::json!({ "uri": uri }));
        }
        Bytes::from(serde_json::to_vec(&envelope).unwrap_or_default())
    }
}

#[cfg(test)]
#[path = "tests/mcp_tests.rs"]
mod tests;
