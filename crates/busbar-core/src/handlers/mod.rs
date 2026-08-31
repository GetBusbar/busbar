// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol handlers — the design's middle, in one module:
//!
//! `Router → RequestHandler → OperationHandler → IR`
//!
//! - [`RequestHandler`] — ONE per protocol (`openai.rs`, `anthropic.rs`, …). Dumb and
//!   protocol-specific: reads path+body to decide WHICH operation a request asks for
//!   (`resolve_operation`), owns the `(protocol, operation) → path template` (`upstream_path`), and
//!   holds its row of the support matrix (`operation_handler`; `None` = the no-handler 404).
//! - [`OperationHandler`] — ONE per (protocol × operation). A pure codec: wire ↔ IR, both
//!   directions, plus the operation-capability surface the engine reads. It never routes, fails
//!   over, checks auth, bills, or knows another protocol exists.
//! - [`OpDispatch`] — the thin `(operation, transport, OperationHandler)` handle the streaming
//!   engine threads: the framed cell, built by [`crate::handlers::frame`] and by
//!   nothing else. It mostly delegates to the `RequestHandler` vtable; its one bit of logic is
//!   honoring a per-lane `path` override in `upstream_path` before falling back to the protocol
//!   default. [`request_handler`] is the registry the catch-all dispatch resolves through.
//!
//! Adding a protocol: a Router ID line, a `RequestHandler` impl here, its OperationHandlers, and a
//! `CELLS` table naming the verbs it speaks. Adding an OPERATION: an OperationHandler plus a row in
//! the `CELLS` table of each protocol that speaks it — a row, not a match arm, and only in the
//! protocols that speak it, because a verb is that protocol's vocabulary and not a core enum's
//! variant (see [`Cell`], and `operation.rs` for what the core kept: the SHAPE). Adding a
//! TRANSPORT: a variant in `transport.rs` and an arrival that frames these same codecs — no codec
//! changes, because a codec never learns which channel it is speaking over. Nothing else moves.
//!
//! THE CODEC-CELL MATRIX ITSELF LIVES IN `busbar-substrate` (`busbar_substrate::handlers`): the
//! [`OperationHandler`] / [`RequestHandler`] / [`TranslateCodec`] traits, the [`Cell`] / [`cell_of`]
//! / [`path_of`] row helpers, the [`IngressReject`] / [`CodecError`] reject enums and the translate
//! value enums are all re-exported below at their historical `busbar_core::handlers::…` paths so the
//! dialect crates and core's own call sites are unchanged. What STAYS in core is the engine dispatch
//! handle [`OpDispatch`] and the registry-resolved [`chat`] / [`op_for`] / [`protocol_error`]
//! resolvers — those name the core registry singleton.

// EVERY LLM DIALECT'S HANDLER LIVES IN THE `busbar-llm` PLUGIN CRATE — anthropic, openai-chat,
// gemini, bedrock, cohere and openai-responses — each in its own dialect module's `handler.rs`.
// They are reachable in the builds that compile the dialects back in as
// `crate::proto::<dialect>::handler`, and in production only through the registry's
// `ProtocolDecl::handler`, which is the point. `ChatOperation` RELOCATED to the plugin too at the
// G6 A4b dissolve (`busbar-llm/src/chat_handle.rs`, netted as `crate::proto::chat_handle`): once
// `IrReq`/`IrResp` dissolved onto `Box<dyn IrHandle>`, the chat codec names the concrete chat IR
// that now lives in the plugin, so it cannot stay in core. Core names no chat codec in production;
// chat resolves through the registry like every other operation (see `chat` below).
// THE EXTRACTED MCP PROTOCOL CODEC lives wholly in the `busbar-mcp` plugin crate
// (`crates/busbar-mcp/src/codec`). Its `#[path]` witness re-include into core (which let the
// pre-extraction fixture surface reach the real MCP codec from inside core's own test binary, back
// when a `ProtocolDecl` was a `busbar-core` type an external crate could not hand to the registry)
// was DELETED: `ProtocolDecl` now lives in `busbar-substrate`, so core's test binary reads
// `busbar_mcp::PROTO_DECL` directly (dev-dependency). NOTE THE SCOPE: this was MCP the PROTOCOL; the
// `mcp/` PLANE (`crate::mcp`) never travelled with the codec and is still core's.

// THE CODEC-CELL MATRIX, relocated to `busbar-substrate` (`busbar_substrate::handlers`) so the
// dialect crates implement it without reaching into `busbar-core`, and re-exported here at its
// historical `busbar_core::handlers::…` paths so every in-core call site (and the netted
// dual-compile test build) is unchanged. `usage_tap_decode_fail_should_warn` (the usage-tap
// warn-once latch) travels with the `extract_usage` default that calls it; the
// `busbar_core::metrics::BILLING_TAP_DECODE_FAIL_TOTAL` metric name it increments moved with it and
// is re-exported from `metrics.rs`.
pub use busbar_substrate::handlers::{
    cell_of, path_of, usage_tap_decode_fail_should_warn, Cell, CodecError, IngressReject,
    OperationHandler, RequestHandler, TranslateCodec, TranslateReqInput, TranslateReqReject,
    TranslateRespInput, TranslatedRequest,
};

/// The protocol's `RequestHandler`, by name (matches `router` / `proto::Protocol::name()`). A
/// registered handler may still return `None` from `operation_handler` for an op it lacks — that IS
/// the no-handler 404.
///
/// THIS WAS THE SECOND MATCH ON A PROTOCOL NAME IN CORE, and it was the one on the DISPATCH path:
/// `match protocol { "openai" => …, "mcp" => … }`, seven arms, each naming a protocol core had to
/// have been edited to know about. It is now a read of `ProtocolDecl::handler` — the cell a protocol
/// DECLARES, beside the codec, the verbs and the head keys it declares in the same struct.
pub fn request_handler(protocol: &str) -> Option<&'static dyn RequestHandler> {
    crate::proto::decl_for(protocol).and_then(|d| d.handler)
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;

use crate::operation::Operation;
use serde_json::Value;

// `WireBody` (a serialized wire body + its content-type) RELOCATED to `busbar-substrate` as a
// neutral wire value type a plane crate names directly; re-exported here so core's call sites and the
// `busbar-llm` handlers that name `busbar_core::handlers::WireBody` are unchanged.
pub use busbar_substrate::wire::WireBody;

// `EgressCtx` (the resolved-primitives egress context routing hands a `RequestHandler`) RELOCATED to
// `busbar-substrate` as a neutral egress value type a plane crate names directly; re-exported here so
// core's call sites and the `busbar-llm` handlers that name `busbar_core::handlers::EgressCtx` are
// unchanged.
pub use busbar_substrate::wire::EgressCtx;

// `EgressWire` (a hop's egress request wire — JSON `Value` still to be shim/model-shaped, or a FINAL
// serialized body) RELOCATED to `busbar-substrate` at Batch C-3 as a neutral value type a plane crate
// names directly (it is a return type on the sealed neutral `IrHandle`); re-exported here so core's
// call sites and the `busbar-llm` handlers that name `busbar_core::handlers::EgressWire` are unchanged.
pub use busbar_substrate::wire::EgressWire;

// `TranslatedResponse` (the neutral outcome of a non-stream cross-protocol response translation)
// RELOCATED to `busbar-substrate` at Batch C-3 as a neutral value type a plane crate names directly
// (a return type on the sealed neutral `IrHandle`); re-exported here so core's call sites and the
// `busbar-llm` handlers that name `busbar_core::handlers::TranslatedResponse` are unchanged.
pub use busbar_substrate::wire::TranslatedResponse;

#[cfg(test)]
#[path = "tests/contract_tests.rs"]
mod contract_tests;

use crate::state::Lane;

/// A `(operation, transport, OperationHandler)` dispatch handle — ONE CELL of the matrix, framed —
/// threaded through the forward engine by value (`Copy`). The engine reads operation behavior off it
/// without ever naming an operation, and now carries the transport the request arrived on without
/// ever naming one of those either.
///
/// BUILT THROUGH [`crate::handlers::frame`] — the framing constructor, and the only
/// thing that builds one in this tree. The three axes meet here and nowhere else: routing picks the
/// protocol, the `RequestHandler` picks the operation (and with it the codec), and the ARRIVAL
/// picks the transport. What the compiler enforces is the part that matters — no site can hold a
/// codec without having said which channel it is speaking over, which is the shape whose absence
/// let a stdio `tools:` entry sit in config with no dispatch arm to reach it.
#[derive(Clone, Copy)]
pub struct OpDispatch {
    pub operation: Operation,
    /// The channel this exchange rides. A VALUE, like `operation`: the engine labels with it and
    /// hands it on, and never compares or matches it (that would be a transport-identity branch,
    /// which `scripts/structure-lint.sh` refuses outside a `proto/` arm, its handler and its codec).
    pub(crate) transport: crate::transport::Transport,
    pub op_handler: &'static dyn OperationHandler,
}

/// The engine's operation handle. (Kept as `Op` so the engine's signatures read unchanged.)
pub(crate) type Op = OpDispatch;

/// Build one framed dispatch cell. This is the free-function form of what was `Transport::frame`;
/// it moved here (core) when `Transport` itself moved to the neutral substrate, because framing
/// names `OpDispatch`/`OperationHandler` — the engine dispatch types, which stay in core. The
/// transport is handed in whole and is not consulted, wrapped or re-implemented: a transport decides
/// how a codec's bytes reach and leave a peer, never what those bytes say.
pub(crate) const fn frame(
    transport: crate::transport::Transport,
    operation: Operation,
    op_handler: &'static dyn OperationHandler,
) -> OpDispatch {
    OpDispatch {
        operation,
        transport,
        op_handler,
    }
}

impl OpDispatch {
    /// Stable identifier — a bounded metric label / tracing span field. VALUE use only; the engine
    /// must never compare or `match` on it (that would be an operation-identity branch).
    pub(crate) fn name(&self) -> &'static str {
        self.operation.name()
    }
    /// The transport this exchange rides — a bounded label, the third axis's counterpart to
    /// [`Self::name`]. VALUE use only, for exactly the reason [`Self::name`] is.
    pub(crate) fn transport(&self) -> crate::transport::Transport {
        self.transport
    }
    /// WHAT THIS ATTEMPT'S FAILURE MEANT — the attributed outcome the breaker classifies, read by
    /// THIS cell's own codec ([`OperationHandler::extract_error`]). It needs nothing but the cell,
    /// so a caller that holds no `Lane` attributes a failure the same way the lane path does.
    pub(crate) fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> crate::breaker::RawUpstreamError {
        self.op_handler.extract_error(status, body)
    }
    /// Can this cell produce a client-facing incremental stream?
    ///
    /// THE SHAPE IS A FLOOR UNDER THE CELL'S ANSWER, and it is the one place the operation axis is
    /// a decision rather than a label. `OpShape::may_stream` says whether an exchange of this shape
    /// has anything to stream at all; the cell says whether IT does. A cell may always say less —
    /// MCP's `tools/call` is `Invoke` and answers `false` — and it may never say more, because a
    /// shape whose reply is one message (a catalogue page, a fetched document, a subscription
    /// acknowledgement, a handshake) streamed by an over-eager cell leaves the engine holding a
    /// response open for a body that is never coming.
    ///
    /// This is a floor and not a replacement deliberately: it removes a failure the cell cannot be
    /// trusted to prevent, and removes nothing the cell legitimately decides.
    pub(crate) fn streaming(&self) -> bool {
        self.operation.shape().may_stream() && self.op_handler.streaming()
    }
    /// The caller's stream INTENT, under the same shape floor and for the same reason: a caller
    /// cannot ask for an incremental answer to an exchange that has no increments.
    pub(crate) fn wants_stream(&self, body: &Value) -> bool {
        self.operation.shape().may_stream() && self.op_handler.wants_stream(body)
    }
    pub(crate) fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        self.op_handler.body_affinity_key(body)
    }
    pub(crate) fn taps_nonstream_usage(&self) -> bool {
        self.op_handler.taps_usage()
    }
    pub(crate) fn extract_usage(
        &self,
        ingress_protocol: &str,
        body: &[u8],
    ) -> Option<crate::billing::TokenUsage> {
        self.op_handler.extract_usage(ingress_protocol, body)
    }
    pub(crate) fn egress_accept(&self, egress_protocol: &str, wants_stream: bool) -> &'static str {
        // The registry read the trait default used to do, hoisted here so the relocated substrate
        // `OperationHandler::egress_accept` names no core registry. Resolve the egress protocol's
        // declared streaming `Accept` and hand it in; the trait picks it (streaming) or the universal
        // `application/json` (non-streaming) — the exact `if/map/unwrap_or` the old default computed,
        // so the returned `&'static str` is identical for every `(protocol, wants_stream)`.
        let egress_stream_accept = crate::proto::decl_for(egress_protocol)
            .map(|d| d.egress_stream_accept)
            .unwrap_or(crate::proxy::TEXT_EVENT_STREAM);
        self.op_handler
            .egress_accept(egress_stream_accept, wants_stream)
    }
    /// The (protocol × operation) upstream path: lane override, else the lane's protocol
    /// `RequestHandler` renders it from resolved primitives (never the `Lane`). `None` only if the
    /// protocol has no registered handler — impossible for chat (all six are registered).
    ///
    /// NO LONGER on the request path: the forward/degraded paths read the lane's boot-precomputed
    /// `egress_targets` table instead (`proxy::build_egress_targets`). This stays as the REFERENCE
    /// composition the differential test (`egress_target_tests`) proves the table byte-identical
    /// to — if the two ever drift, that test is the tripwire.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn upstream_path(&self, lane: &Lane, wants_stream: bool) -> Option<String> {
        if let Some(p) = &lane.path {
            return Some(p.clone());
        }
        crate::handlers::request_handler(lane.protocol).map(|rh| {
            rh.upstream_path(&EgressCtx {
                operation: self.operation,
                model: lane.wire_model(),
                stream: wants_stream,
                path_base: lane.path_base.as_deref(),
            })
        })
    }
}

/// Chat — operation #1. A const handle to the shared chat `OperationHandler`, for core's own tests.
/// TEST-BINARY ONLY: `ChatOperation` lives in the `busbar-llm` plugin (it names the concrete chat IR
/// that moved there at the G6 A4b dissolve), so production core has no chat codec to name and the
/// neutral source may not spell the plugin. The fixture is therefore DEFINED in a `tests/` file the
/// neutral-purity lint excludes (`chat_fixture`, which names `busbar_llm::chat_handle::ChatOperation`)
/// and re-exported here at its historical `crate::handlers::CHAT` path. Prefer [`chat`] on the request
/// path so the `RequestHandler` actually decides the handler.
#[cfg(test)]
#[path = "tests/chat_fixture.rs"]
mod chat_fixture;
#[cfg(test)]
pub(crate) use chat_fixture::CHAT;

/// Resolve the chat dispatch THROUGH the registry — the same path every other operation takes:
/// `request_handler(protocol).operation_handler(Chat)`. This is how "the RequestHandler decides which
/// OperationHandler handles the request" is honored for chat too, not just the JSON ops.
///
/// Post-G6-A4b the chat codec lives in the `busbar-llm` plugin, so this resolves it through the
/// registry the composition root populated — there is no in-core const fallback to name anymore (that
/// codec is gone from core's production build). The `expect` can only fire in a build that links no
/// chat-serving protocol at all, which no shipped configuration is: the LLM plugin registers `openai`
/// and its five siblings, and the sole production caller (`mcp::sampling`) asks for `openai`. The one
/// caller that used the old const fallback purely for a chat cell's error vocabulary (`health.rs`)
/// now calls the neutral `protocol_error` directly (byte-identical to `ChatOperation::extract_error`).
///
/// The TRANSPORT is the caller's to state, not this resolver's: which channel an exchange arrived on
/// is a fact about the arrival, and a protocol has no opinion about it (that is what A2A's three
/// bindings of one agent mean). So it is a parameter, and every caller decides.
pub fn chat(protocol: &str, transport: crate::transport::Transport) -> Op {
    op_for(protocol, Operation::CHAT, transport).unwrap_or_else(|| {
        // Unreachable in any shipped configuration: a chat plugin always registers the residual chat
        // protocol and its siblings, and the sole production caller asks for that residual name. The
        // diagnostic names the registry's residual-default protocol (whatever the plugin declared)
        // rather than a hard-coded dialect, so core spells no dialect here.
        panic!(
            "a chat-serving protocol is registered (registry residual chat protocol: {:?})",
            crate::proto::residual_default_dialect()
        )
    })
}

/// THE FRAMED CELL FOR ONE EXCHANGE — `(protocol, operation)` resolved through the registry and
/// framed by the channel it rides. `None` when the protocol does not serve the operation: on the
/// ingress side that is the no-handler 404, and on the egress side it is a pair that never dispatched.
///
/// This is what a site holding an upstream RESPONSE reaches for. The engine and the health prober
/// both use it to find the codec that will read what came back, so neither has to know that a `Lane`
/// is where an LLM upstream's protocol happens to be recorded.
/// A verb a protocol did NOT declare is refused here, and that is the registry's rule rather than a
/// new one: `ProtocolDecl::verbs` is what the protocol advertises (bounded at load, enumerable at
/// boot, and therefore safe as a metric label), so a cell reachable through a verb the declaration
/// does not name would be a capability core could not have known about from the declaration alone.
/// It is not a second answer to "does this protocol serve this operation" — the declaration and the
/// handler are pinned EQUAL in both directions by
/// `registry_tests::the_declared_verbs_are_the_verbs_the_handler_serves`, so this check can only
/// ever fire on a decl that is lying, never on a legitimate route.
pub(crate) fn op_for(
    protocol: &str,
    operation: Operation,
    transport: crate::transport::Transport,
) -> Option<Op> {
    let decl = crate::proto::decl_for(protocol)?;
    if !decl.verbs.contains(&operation) {
        return None;
    }
    decl.handler
        .and_then(|rh| rh.operation_handler(operation))
        .map(|op_handler| frame(transport, operation, op_handler))
}

/// ONE HTTP LLM PROTOCOL'S ERROR ENVELOPE, SHARED BY EVERY OPERATION IT SERVES.
///
/// The six LLM protocols wrap every operation's failure in the same provider envelope — an OpenAI
/// 429 on `/v1/embeddings` carries the `{"error": {…}}` shape it carries on `/v1/chat/completions`
/// — so that vocabulary is a fact about the PROTOCOL, stated once in its `proto::ProtocolReader`,
/// and each of that protocol's cells answers [`OperationHandler::extract_error`] through here. A
/// protocol whose operations do NOT share one envelope never calls this and keeps the status-only
/// default, which is why the capability belongs to the cell even though these six answer it alike.
///
/// Falls back to the status alone when the name resolves to no protocol: claiming a provider
/// vocabulary busbar could not read would be worse than saying only what is known.
pub fn protocol_error(
    protocol: &str,
    status: u16,
    body: &[u8],
) -> crate::breaker::RawUpstreamError {
    // Through the neutral dialect seam: the concrete reader (whose `extract_error` this delegates to)
    // relocated to the busbar-llm plugin at A4b, so core names it by protocol only.
    match crate::proto::decl_for(protocol).and_then(|d| d.dialect()) {
        Some(dc) => dc.extract_error(status, body),
        None => crate::breaker::RawUpstreamError::from_status(status),
    }
}

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;
