// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol handlers — the design's middle, in one module:
//!
//! `Router → RequestHandler → OperationHandler → IR`
//!
//! - [`RequestHandler`](busbar_contract::codec::RequestHandler) — ONE per protocol (`openai.rs`, `anthropic.rs`, …). Dumb and
//!   protocol-specific: reads path+body to decide WHICH operation a request asks for
//!   (`resolve_operation`), owns the `(protocol, operation) → path template` (`upstream_path`), and
//!   holds its row of the support matrix (`operation_handler`; `None` = the no-handler 404).
//! - [`OperationHandler`](busbar_contract::codec::OperationHandler) — ONE per (protocol × operation). A pure codec: wire ↔ IR, both
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
//! variant (see [`Cell`](busbar_contract::codec::Cell), and `operation.rs` for what the core kept: the SHAPE). Adding a
//! TRANSPORT: a variant in `transport.rs` and an arrival that frames these same codecs — no codec
//! changes, because a codec never learns which channel it is speaking over. Nothing else moves.
//!
//! THE CODEC-CELL SHAPES LIVE IN THE CONTRACT (`busbar_contract::codec`, #83a SD-2b): the
//! `OperationHandler` / `RequestHandler` traits, the `Cell` / `cell_of` / `path_of` row helpers and
//! the `IngressReject` / `CodecError` reject enums, named there by every caller. The cross-dialect
//! translate pipeline is the LLM plane's own. What lives HERE is the engine dispatch handle
//! [`OpDispatch`], the registry-resolved [`chat`] / [`op_for`] / [`protocol_error`] resolvers — those
//! name the registry singleton — and the host's usage-tap fault reporting the install arms.

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

// THE USAGE-TAP FAULT HOST SERVICES the protocol install arms for every codec cell (#83a HOST):
// the warn-once latch and the decode reporter, both counting on
// `busbar_kernel::metrics::BILLING_TAP_DECODE_FAIL_TOTAL`.

/// Process-lifetime warn-once latch for the usage-tap decode fault class, keyed `protocol:reason`. A
/// live protocol/dialect the tap reader cannot decode fails on EVERY 2xx body of that shape, so an
/// unlatched `warn!` spams per request; [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::metrics::BILLING_TAP_DECODE_FAIL_TOTAL) carries the per-request
/// volume. This records the fault (increments the counter) and returns `true` only the FIRST time a
/// given `(protocol, reason)` is seen, so the caller warns once and logs `debug!` thereafter.
pub fn usage_tap_decode_fail_should_warn(protocol: &str, reason: &'static str) -> bool {
    metrics::counter!(
        crate::metrics::BILLING_TAP_DECODE_FAIL_TOTAL,
        "protocol" => protocol.to_string(),
        "reason" => reason,
    )
    .increment(1);
    static SEEN: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    seen.insert(format!("{protocol}:{reason}"))
}

/// THE HOST'S USAGE-TAP FAULT REPORTER — what [`OperationHandler::extract_usage`](busbar_contract::codec::OperationHandler::extract_usage)'s default reports
/// through when a cell's own reader refuses a same-protocol 2xx body (the request bills 0 tokens).
/// Counted on [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::metrics::BILLING_TAP_DECODE_FAIL_TOTAL) and warned once per `(protocol, reason)`, exactly as
/// the default did inline before the trait moved into the contract, which takes no logging or metrics
/// dependency. Installed by [`crate::proto::install_protocols`] and the test registration seams, so
/// it is armed before any cell is reachable.
pub fn report_usage_tap_decode_failure(
    ingress_protocol: &str,
    e: &busbar_contract::codec::CodecError,
) {
    if usage_tap_decode_fail_should_warn(ingress_protocol, "decode") {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = ingress_protocol,
            error = ?e,
            "usage tap: read_response failed to decode a same-protocol 2xx body; \
             billing 0 tokens for this request"
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = ingress_protocol,
            error = ?e,
            "usage tap: read_response still failing to decode a same-protocol 2xx body; \
             billing 0 tokens for this request"
        );
    }
}

/// The protocol's `RequestHandler`, by name (matches `router` / `proto::Protocol::name()`). A
/// registered handler may still return `None` from `operation_handler` for an op it lacks — that IS
/// the no-handler 404.
///
/// THIS WAS THE SECOND MATCH ON A PROTOCOL NAME IN CORE, and it was the one on the DISPATCH path:
/// `match protocol { "openai" => …, "mcp" => … }`, seven arms, each naming a protocol core had to
/// have been edited to know about. It is now a read of `ProtocolDecl::handler` — the cell a protocol
/// DECLARES, beside the codec, the verbs and the head keys it declares in the same struct.
pub fn request_handler(
    protocol: &str,
) -> Option<&'static dyn busbar_contract::codec::RequestHandler> {
    crate::proto::decl_for(protocol).and_then(|d| d.handler)
}

// The handler test modules (`use super::*`) name the verb vocabulary; production code here spells
// it by path.
#[cfg(test)]
use crate::operation::OpVerb;

// `WireBody`, `EgressCtx`, `EgressWire` and `TranslatedResponse` are codec-cell SHAPES
// (`busbar_contract::codec`, #83a SD-2b) that every caller names through the contract or its
// substrate re-export; this module no longer re-exports them.

#[cfg(test)]
#[path = "tests/contract_tests.rs"]
mod contract_tests;

/// A `(operation, transport, OperationHandler)` dispatch handle — ONE CELL of the matrix, framed —
/// threaded through the forward engine by value (`Copy`). The engine reads operation behavior off it
/// without ever naming an operation, and carries the transport the request arrived on without ever
/// naming one of those either.
#[derive(Clone, Copy)]
pub struct OpDispatch {
    pub operation: busbar_contract::operation::OpVerb,
    /// The channel this exchange rides. A VALUE, like `operation`: the engine labels with it and hands
    /// it on, and never compares or matches it (that would be a transport-identity branch).
    pub(crate) transport: crate::transport::Transport,
    pub op_handler: &'static dyn busbar_contract::codec::OperationHandler,
}

/// The engine's operation handle. (Kept as `Op` so the engine's signatures read unchanged.)
pub type Op = OpDispatch;

/// Build one framed dispatch cell. The free-function form of what was `Transport::frame`. The
/// transport is handed in whole and is not consulted, wrapped or re-implemented: a transport decides
/// how a codec's bytes reach and leave a peer, never what those bytes say.
pub const fn frame(
    transport: crate::transport::Transport,
    operation: busbar_contract::operation::OpVerb,
    op_handler: &'static dyn busbar_contract::codec::OperationHandler,
) -> OpDispatch {
    OpDispatch {
        operation,
        transport,
        op_handler,
    }
}

impl OpDispatch {
    /// Stable identifier — a bounded metric label / tracing span field. VALUE use only.
    pub fn name(&self) -> &'static str {
        self.operation.name()
    }
    /// The transport this exchange rides — a bounded label. VALUE use only.
    pub fn transport(&self) -> crate::transport::Transport {
        self.transport
    }
    /// WHAT THIS ATTEMPT'S FAILURE MEANT — the attributed outcome the breaker classifies, read by THIS
    /// cell's own codec. It needs nothing but the cell.
    pub fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        self.op_handler.extract_error(status, body)
    }
    /// Can this cell produce a client-facing incremental stream? `OpShape::may_stream` is the floor;
    /// the cell may always say less and never more.
    pub fn streaming(&self) -> bool {
        self.operation.shape().may_stream() && self.op_handler.streaming()
    }
    /// The caller's stream INTENT, under the same shape floor.
    pub fn wants_stream(&self, body: &serde_json::Value) -> bool {
        self.operation.shape().may_stream() && self.op_handler.wants_stream(body)
    }
    pub fn body_affinity_key<'a>(&self, body: &'a serde_json::Value) -> Option<&'a str> {
        self.op_handler.body_affinity_key(body)
    }
    pub fn taps_nonstream_usage(&self) -> bool {
        self.op_handler.taps_usage()
    }
    pub fn extract_usage(
        &self,
        ingress_protocol: &str,
        body: &[u8],
    ) -> Option<busbar_contract::billing::TokenUsage> {
        self.op_handler.extract_usage(ingress_protocol, body)
    }
    pub fn egress_accept(&self, egress_protocol: &str, wants_stream: bool) -> &'static str {
        // The registry read the trait default used to do, hoisted here so the `OperationHandler`
        // relocation names no core registry. Resolve the egress protocol's declared streaming `Accept`
        // and hand it in; the trait picks it (streaming) or the universal `application/json`.
        let egress_stream_accept = crate::proto::decl_for(egress_protocol)
            .map(|d| d.egress_stream_accept)
            .unwrap_or(crate::ingress::errors::TEXT_EVENT_STREAM);
        self.op_handler
            .egress_accept(egress_stream_accept, wants_stream)
    }
}

// The former `#[cfg(test)]` `CHAT` const (a hand-framed cell over the plugin's chat handler type,
// defined in a `tests/chat_fixture.rs` that named the plugin crate) is GONE: its one reader,
// `dispatch_tests`, resolves the same cell the way production does — [`op_for`] over the registry —
// so core's test binary names no plugin handler type to build a chat cell.

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
    op_for(
        protocol,
        busbar_contract::operation::OpVerb::CHAT,
        transport,
    )
    .unwrap_or_else(|| {
        // Unreachable in any shipped configuration: a chat plugin always registers the residual chat
        // protocol and its siblings, and the sole production caller asks for that residual name. The
        // diagnostic names the registry's residual-default protocol rather than a hard-coded dialect,
        // so the substrate spells no dialect here.
        panic!(
            "a protocol serving `{}` is registered (registry residual default protocol: {:?})",
            busbar_contract::operation::OpVerb::CHAT.name(),
            crate::proto::residual_default_protocol()
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
pub fn op_for(
    protocol: &str,
    operation: busbar_contract::operation::OpVerb,
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
/// and each of that protocol's cells answers [`busbar_contract::codec::OperationHandler::extract_error`] through here. A
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
    match crate::proto::decl_for(protocol).and_then(|d| d.dialect()) {
        Some(dc) => dc.extract_error(status, body),
        None => crate::breaker::RawUpstreamError::from_status(status),
    }
}

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;
