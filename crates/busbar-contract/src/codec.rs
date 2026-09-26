// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CODEC-CELL SHAPES (DECISIONS #83: contract = shapes) — the traits a protocol's codec cells
//! implement ([`RequestHandler`] one per protocol, [`OperationHandler`] one per protocol ×
//! operation, the support-matrix row [`Cell`]) and the values they and the kernel's dispatch hand
//! each other: the resolved-primitives egress context a request handler renders the upstream path
//! from, the two refusals a cell reports, and the wire carriers a cell's handle writes itself out as
//! ([`WireBody`], [`EgressWire`], [`TranslatedResponse`]).
//!
//! Relocated from `busbar-substrate-values` (`wire` and `handlers`), which re-exports each under its
//! historical path. The wire carriers are RE-EXPRESSED over this crate's own [`SlabBytes`]: the
//! reference-counted foreign buffer they used to carry is banned from this surface
//! (`tests/bounded_limits.rs`), so a body is a shared slab here and the host adopts it as its own
//! buffer, without copying, at its transport boundary.

use crate::billing::TokenUsage;
use crate::bounded::SlabBytes;
use crate::ir::handle::IrHandle;
use crate::operation::Operation;
use serde_json::Value;

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub struct WireBody {
    pub bytes: SlabBytes,
    pub content_type: http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub fn json(bytes: SlabBytes) -> Self {
        Self {
            bytes,
            content_type: http::HeaderValue::from_static(crate::protocol::APPLICATION_JSON),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub fn typed(bytes: SlabBytes, content_type: &str) -> Self {
        let content_type = http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
}

/// The egress request wire a hop produced: a JSON `Value` still to be shim/model-shaped by the
/// router before serialization, or a FINAL body (a non-JSON egress wire — multipart transcription /
/// audio). Mirrors the pre-cutover `write_request_value` `Some(Value)` / `None`→`write_request` split.
pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(SlabBytes),
    /// NO egress body could be written, and `reason` says why. The loud arm: a handle that cannot
    /// write itself onto the target dialect says so, and the seam turns that into a refusal the
    /// caller sees. The alternative — answering with an empty body — sends a request upstream that
    /// is not the caller's request, and the first sign of it is the backend's own error.
    Unrepresentable { reason: String },
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the
/// pre-cutover buffered-response arm: a delivered body (JSON / typed / synthesized native frames), or
/// one of the two read-succeeded-but-undelivered terminals the caller still renders (404 / 500).
pub enum TranslatedResponse {
    /// A JSON ingress body (`application/json`) the caller still post-processes (native response-metrics
    /// injection, a dialect's JSON-array wrap) before delivery.
    Json(Value),
    /// A final ingress body + its own content-type (a non-JSON ingress wire — speech audio — or the
    /// opaque egress→ingress bridge).
    Typed(WireBody),
    /// Synthesized native stream frames (a wants-stream ingress answered by a BUFFERED upstream — e.g.
    /// an event-stream client served a non-SSE buffered body). Delivered under the ingress stream
    /// content-type.
    StreamFrames(Vec<u8>),
    /// JSON path only: the ingress protocol does not serve this operation → the caller renders the 404
    /// (`DETAIL_ENDPOINT_UNSUPPORTED_OPERATION`). The egress read succeeded, but NO completion reaches
    /// the client, so the caller does NOT bill this and leaves its spend guard armed to refund — a
    /// response the client never receives is not charged (mirrors the streaming refund-on-non-delivery).
    IngressUnsupported,
    /// Opaque path only: the egress read succeeded but the ingress handler is absent, so no client body
    /// could be written → the caller falls through to its ingress-native untranslatable 500. NO
    /// completion reaches the client, so the caller does NOT bill this and leaves its spend guard armed
    /// to refund — same non-delivery posture as `IngressUnsupported`.
    Untranslatable,
}

/// What routing hands a request handler so it can render the upstream URL path. RESOLVED PRIMITIVES
/// ONLY — never the `Lane` or a config handle: a codec/handler touching routing state is exactly the
/// coupling this fixes. Grows a field (region, api-version, …) when a protocol needs more; the trait
/// signature does not. Routing populates it from the lane and applies any `lane.path` override itself.
pub struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub operation: Operation,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for protocols that carry the
    /// model in the URL path rather than the body.
    pub model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub stream: bool,
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols it
    /// replaces the protocol's hardcoded base segment (e.g. `/v1beta/models`) so a provider can be
    /// pointed at a different layout — a host that serves the same dialect under a
    /// project/location-scoped path. `None` uses the protocol default.
    /// Distinct from the full-path `path` override, which is static and ignores the per-request model.
    pub path_base: Option<&'a str>,
}

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `proxy::ingress_error`). `UnsupportedSubOp` is the second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from handler-absence, same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: Operation, model: String },
}

/// An upstream response body this OperationHandler could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Malformed(String),
}

/// The host's USAGE-TAP FAULT REPORTER: told when a cell's own reader refused a same-protocol 2xx body
/// in [`OperationHandler::extract_usage`]'s default, so the request billed 0 tokens. The host counts
/// it (a per-request volume signal) and warns once per `(protocol, reason)`; the contract carries
/// only the shape of the call, because counting and logging are the host's, not the cell's.
pub type UsageTapFaultReporter = fn(ingress_protocol: &str, error: &CodecError);

static USAGE_TAP_FAULT_REPORTER: std::sync::OnceLock<UsageTapFaultReporter> =
    std::sync::OnceLock::new();

/// Install the host's [`UsageTapFaultReporter`]. The first install wins and later ones are ignored:
/// one process has one host. The host installs it where it installs the protocols whose cells report
/// through it, so no cell is reachable before it is armed.
pub fn install_usage_tap_fault_reporter(reporter: UsageTapFaultReporter) {
    let _ = USAGE_TAP_FAULT_REPORTER.set(reporter);
}

/// Report a usage-tap decode failure to the installed host reporter; a no-op in a process whose host
/// installed none (a bare codec test).
pub fn report_usage_tap_decode_failure(ingress_protocol: &str, error: &CodecError) {
    if let Some(report) = USAGE_TAP_FAULT_REPORTER.get() {
        report(ingress_protocol, error);
    }
}

/// ONE ROW OF A PROTOCOL'S SUPPORT MATRIX — a verb the protocol speaks and the codec that speaks it.
///
/// **THE ROW IS DATA, AND THAT IS THE CHANGE 1.6.0 MADE.** It used to be a `match` arm per verb in
/// every `RequestHandler`, which meant a verb was a variant of a CORE enum and adding one was a
/// compile error in every protocol — including the six that will never speak it. That gate was the
/// right mechanism pointed at the wrong tag: what a protocol must not be able to duck is a decision
/// about the SHAPE of an exchange (`Operation`'s `OpShape`, still closed, still exhaustively
/// matched, still with no catch-all anywhere), not a decision about another family's method names.
///
/// A protocol's vocabulary now lives beside its codecs, so deleting a protocol deletes its verbs
/// with it and no core type mentions them — which is the deletion test the plugin seam is measured
/// by. A verb absent from a row is the no-handler 404, exactly as an arm returning `None` was.
pub type Cell = (Operation, &'static dyn OperationHandler);

/// THE ROW LOOKUP every [`RequestHandler::operation_handler`] is — stated once so there are not
/// seven copies of a linear scan. Rows are single-digit in length, so this is a handful of pointer
/// comparisons and is not worth a map.
pub fn cell_of(cells: &'static [Cell], op: Operation) -> Option<&'static dyn OperationHandler> {
    cells
        .iter()
        .find(|(candidate, _)| *candidate == op)
        .map(|(_, handler)| *handler)
}

/// THE (verb → upstream path) LOOKUP, for the protocols whose egress paths are constants rather
/// than templates. Same table shape, same reason it is data: `resolve_operation` reads these very
/// constants on the ingress side, so the two directions cannot drift.
pub fn path_of(paths: &'static [(Operation, &'static str)], op: Operation) -> Option<&'static str> {
    paths
        .iter()
        .find(|(candidate, _)| *candidate == op)
        .map(|(_, path)| *path)
}

/// A pure per-(protocol × operation) codec. Feed it wire, assert the IR; feed it IR, assert the wire.
/// That is the entire contract — the load-bearing discipline that makes the matrix scale. It knows
/// NOTHING about routing: no `Lane`, no path, no model. The path is the `RequestHandler`'s concern.
pub trait OperationHandler: Send + Sync {
    // OperationHandler capabilities: the operation-behavior surface the forward engine reads (never branching on
    // operation identity). Every default is the MOST RESTRICTIVE behavior — no streaming, no stream
    // intent, no affinity, no usage tap. Chat overrides them; the JSON ops keep the defaults. This is
    // exactly the old `OpSpec` surface, now living on the OperationHandler so there is ONE operation mechanism.

    /// WHAT THIS UPSTREAM'S FAILURE MEANT — the attributed outcome of one outbound attempt, which
    /// is what the breaker classifies and what failover needs in order to distinguish "this target
    /// is sick" from "this caller may not do that".
    ///
    /// IT LIVES HERE, ON THE OPERATION CODEC, AND THAT PLACEMENT IS THE POINT. It was previously
    /// only on `proto::ProtocolReader`, which reads as a general protocol trait but is not one: its
    /// `read_request` returns `IrRequest` and its `read_response` returns `IrResponse` — the CHAT
    /// subclass types, not the parent enums. So it is the chat codec, and anything hung off it is
    /// available to chat protocols alone. That is the real reason the breaker never spanned the
    /// tool and agent protocols: not an oversight, but a capability attached to a trait a non-chat protocol cannot
    /// implement.
    ///
    /// The default is deliberately the most restrictive USEFUL answer rather than the most
    /// restrictive possible one: the status alone, with no provider vocabulary claimed. A cell that
    /// can read its upstream's error shape overrides this and says more; a cell that cannot still
    /// gives the breaker a status to classify, which is strictly better than the silence that made
    /// a non-2xx invisible on the planes built outside the matrix.
    ///
    /// `retry_after_secs` stays `None` here for the same reason it always has: this sees only the
    /// body, and the forwarding layer — which holds the response headers — fills it in afterwards.
    ///
    /// EVERY NON-2XX THE TREE ATTRIBUTES ARRIVES HERE. Both sites that classify an upstream failure
    /// — the forward engine and the active health prober — resolve the cell that spoke to the
    /// upstream (`op_for`) and ask it, rather than reaching a chat vtable through a `Lane`. An
    /// outbound attempt with no `Lane` behind it therefore attributes its failures exactly as a
    /// lane's does, which is what lets the breaker span the tool and agent paths at all.
    fn extract_error(&self, status: u16, _body: &[u8]) -> crate::upstream::RawUpstreamError {
        crate::upstream::RawUpstreamError::from_status(status)
    }

    /// Can this operation produce a client-facing incremental stream?
    fn streaming(&self) -> bool {
        false
    }
    /// Should the non-stream 2xx body be buffered so [`Self::extract_usage`] can read it?
    fn taps_usage(&self) -> bool {
        false
    }
    /// The caller's stream intent, from the parsed ingress body. Chat reads the body's top-level
    /// `"stream"` boolean; a non-streaming op never asks upstream to stream.
    fn wants_stream(&self, _body: &Value) -> bool {
        false
    }
    /// A body-derived session-affinity key (used only when no affinity header is present). Chat uses
    /// a top-level `system` string.
    fn body_affinity_key<'a>(&self, _body: &'a Value) -> Option<&'a str> {
        None
    }
    /// Extract billable usage from a complete same-protocol non-stream 2xx body (called once at stream
    /// end, only when [`Self::taps_usage`] is true). Default: run THIS operation's own reader over the
    /// body and project its token usage — so a token-metered non-chat op (embeddings) bills the same
    /// as the cross-protocol path. Chat overrides this to run the egress protocol's chat reader.
    fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<TokenUsage> {
        match self.read_response(body) {
            Ok(r) => r.token_usage(),
            Err(e) => {
                // A same-protocol 2xx body the op's own codec cannot decode: record it (like the
                // cross-protocol seam) rather than silently bill 0 tokens with no operator signal.
                // The host's reporter counts it and warns once per (protocol, reason).
                report_usage_tap_decode_failure(ingress_protocol, &e);
                None
            }
        }
    }
    /// The Content-Type of THIS operation's egress request wire (what `write_request` emits).
    /// JSON for every JSON-bodied operation; a multipart operation overrides with its boundary.
    fn egress_request_content_type(&self) -> &'static str {
        crate::protocol::APPLICATION_JSON
    }

    /// The egress `Accept` header for the upstream request. `egress_stream_accept` is the egress
    /// protocol's declared streaming `Accept` (resolved by the core caller off `ProtocolDecl`, so
    /// this trait names no registry); the non-streaming value is universally `application/json`. A
    /// binary-response op (audio speech) overrides to `*/*`.
    fn egress_accept(
        &self,
        egress_stream_accept: &'static str,
        wants_stream: bool,
    ) -> &'static str {
        if wants_stream {
            egress_stream_accept
        } else {
            crate::protocol::APPLICATION_JSON
        }
    }

    /// Value-level codec bridge (request) — for engine seams that already hold a PARSED JSON body
    /// (the streaming chat engine parses once for shim/intent reads). Default round-trips through the
    /// byte reader; chat overrides to call its proto reader directly (no re-serialize on the hot
    /// path). The WRITE half of the old bridge inverted onto the handle at the G6 A4b dissolve
    /// (`IrHandle::write_egress_request`/`write_ingress_response`), so only the read side remains here.
    fn read_request_value(&self, v: &Value) -> Result<Box<dyn IrHandle>, IngressReject> {
        let bytes = serde_json::to_vec(v).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        self.read_request(&bytes, crate::protocol::APPLICATION_JSON)
    }
    /// Value-level codec bridge (response).
    fn read_response_value(&self, v: &Value) -> Result<Box<dyn IrHandle>, CodecError> {
        let bytes = serde_json::to_vec(v).map_err(|e| CodecError::Malformed(e.to_string()))?;
        self.read_response(&bytes)
    }

    /// Wire → IR HANDLE (request). The OperationHandler owns the ENTIRE wire format: it receives RAW
    /// bytes + the request content-type and decides how to parse — JSON for JSON ops, multipart for
    /// transcription, etc. The engine never parses; "JSON vs opaque" is the codec's private business.
    /// The handle it yields carries chat's/leaf's cross-protocol prep + self-write (the dissolved
    /// `IrReq` arms); the WRITE seam (`write_request`) is gone — the handle writes itself by protocol.
    fn read_request(
        &self,
        body: &[u8],
        content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject>;
    /// Egress wire → IR HANDLE (response) — for the usage tap or a cross-protocol translation. Raw
    /// bytes: binary responses (audio) were always fine here.
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError>;
}

/// A protocol's dialect + its OperationHandlers (one impl per protocol).
pub trait RequestHandler: Send + Sync {
    /// Stable protocol identity (matches the dialect's own protocol name). Called only from `busbar-core`'s
    /// own tests (`contract_tests.rs`, `registry_tests.rs`) — it is the registry-key/impl-identity
    /// binding that `registry_tests.rs` asserts (`request_handler()` is a string-keyed registry;
    /// nothing in the type system otherwise binds an impl to the key it is filed under). A
    /// legitimate test hook whose purpose is being a test hook.
    fn protocol_name(&self) -> &'static str;

    /// This protocol's row of the support matrix. `None` ⇒ the protocol does not serve the operation
    /// ⇒ the no-handler 404. The OperationHandler, when present, is a pure codec.
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler>;

    /// WHICH operation this request asks for — the RequestHandler knows its protocol and reads the
    /// path (and, where the protocol multiplexes one endpoint, the body: one generate endpoint may
    /// serve chat AND audio, one invoke endpoint embeddings AND images) and says "this is
    /// audio, this is chat". The Router only picks the protocol; THIS decides the operation.
    /// `None` ⇒ the path is not an operation this protocol serves.
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation>;

    /// The model named in the PATH, for path-model dialects (`models/{m}:action`,
    /// `/model/{m}/...`). `None` (the default) for body-model dialects — the dispatch then reads the
    /// JSON body `model` / multipart form instead.
    fn path_model(&self, _path: &str) -> Option<String> {
        None
    }

    /// The `(protocol, operation) → path template` map: this protocol's upstream URL for the operation
    /// in `ctx`, built from RESOLVED PRIMITIVES ([`EgressCtx`]) — never the `Lane`. One `match op` per
    /// protocol. Routing applies any `lane.path` override BEFORE calling this (so this is the default).
    /// This is the sole path mechanism; chat uses it too.
    fn upstream_path(&self, ctx: &EgressCtx) -> String;
}
