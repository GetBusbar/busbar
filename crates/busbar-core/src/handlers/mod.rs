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
//!   engine threads: the framed cell, built by [`crate::transport::Transport::frame`] and by
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

// EVERY LLM DIALECT'S HANDLER LIVES IN THE `busbar-llm` PLUGIN CRATE — anthropic, openai-chat,
// gemini, bedrock, cohere and openai-responses — each in its own dialect module's `handler.rs`.
// They are reachable in the builds that compile the dialects back in as
// `crate::proto::<dialect>::handler`, and in production only through the registry's
// `ProtocolDecl::handler`, which is the point. `ChatOperation` RELOCATED to the plugin too at the
// G6 A4b dissolve (`busbar-llm/src/chat_handle.rs`, netted as `crate::proto::chat_handle`): once
// `IrReq`/`IrResp` dissolved onto `Box<dyn IrHandle>`, the chat codec names the concrete chat IR
// that now lives in the plugin, so it cannot stay in core. Core names no chat codec in production;
// chat resolves through the registry like every other operation (see `chat` below).
/// THE EXTRACTED MCP DIALECT, compiled back in for TEST BUILDS ONLY. The sources live in
/// `crates/busbar-mcp/src/codec` (the MCP plugin's codec half; the `busbar` binary registers its
/// `PROTO_DECL` through `crate::proto::registry::install_protocols`), and core's PRODUCTION build
/// knows nothing of them — this decl exists so the pre-extraction fixture surface (the
/// `protocol: mcp` configs and the `(mcp, Invoke)`/`(mcp, Subscribe)` matrix fixtures across the
/// core suite) keeps exercising the real codec from inside this crate's test binary, where an
/// externally-linked copy could not reach the registry (its `ProtocolDecl` would be a different
/// crate's type). The dialect's sources are written against `busbar_core::` paths, which the
/// `extern crate self as busbar_core` alias in lib.rs resolves here.
///
/// NOTE THE SCOPE: this is MCP the PROTOCOL. The `mcp/` PLANE (`crate::mcp`) did not travel with
/// the codec and is still core's — see the crate docs in `busbar-mcp/src/codec/mod.rs`.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-mcp/src/codec/mod.rs"]
pub(crate) mod mcp;

/// Process-lifetime warn-once latch for the usage-tap decode fault class, keyed `protocol:reason`. A
/// live protocol/dialect the tap reader cannot decode fails on EVERY 2xx body of that shape, so an
/// unlatched `warn!` spams per request; [`crate::metrics::BILLING_TAP_DECODE_FAIL_TOTAL`] carries the
/// per-request volume. This records the fault (increments the counter) and returns `true` only the
/// FIRST time a given `(protocol, reason)` is seen, so the caller warns once and logs `debug!`
/// thereafter.
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

use crate::diagnostics::{diag_debug, diag_warn, USAGE_TAP_DECODE_FAILED};
use crate::ir::handle::IrHandle;
use crate::operation::Operation;
use bytes::Bytes;
use serde_json::Value;

/// ONE ROW OF A PROTOCOL'S SUPPORT MATRIX — a verb the protocol speaks and the codec that speaks it.
///
/// **THE ROW IS DATA, AND THAT IS THE CHANGE 1.6.0 MADE.** It used to be a `match` arm per verb in
/// every `RequestHandler`, which meant a verb was a variant of a CORE enum and adding one was a
/// compile error in every protocol — including the six that will never speak it. That gate was the
/// right mechanism pointed at the wrong tag: what a protocol must not be able to duck is a decision
/// about the SHAPE of an exchange (`crate::operation::OpShape`, still closed, still exhaustively
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

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub struct WireBody {
    pub bytes: Bytes,
    pub content_type: axum::http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub fn json(bytes: Bytes) -> Self {
        Self {
            bytes,
            content_type: axum::http::HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub fn typed(bytes: Bytes, content_type: &str) -> Self {
        let content_type = axum::http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
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

/// What routing hands a `RequestHandler` so it can render the upstream URL path. RESOLVED PRIMITIVES
/// ONLY — never the `Lane` or a config handle: a codec/handler touching routing state is exactly the
/// coupling this fixes. Grows a field (region, api-version, …) when a protocol needs more; the trait
/// signature does not. Routing populates it from the lane and applies any `lane.path` override itself.
pub struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub operation: Operation,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for URL-model protocols
    /// (Gemini `models/{model}:…`, Bedrock `model/{model}/invoke`).
    pub model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub stream: bool,
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols
    /// (Gemini) it replaces the protocol's hardcoded base segment (e.g. `/v1beta/models`) so a
    /// provider can be pointed at a different layout — e.g. Vertex AI's
    /// `/v1/projects/{p}/locations/{l}/publishers/google/models`. `None` uses the protocol default.
    /// Distinct from the full-path `path` override, which is static and ignores the per-request model.
    pub path_base: Option<&'a str>,
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
    /// available to chat protocols alone. That is the real reason the breaker never spanned MCP and
    /// A2A: not an oversight, but a capability attached to a trait a non-chat protocol cannot
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
    /// upstream ([`op_for`]) and ask it, rather than reaching a chat vtable through a `Lane`. An
    /// outbound attempt with no `Lane` behind it therefore attributes its failures exactly as a
    /// lane's does, which is what lets the breaker span the tool and agent paths at all.
    fn extract_error(&self, status: u16, _body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::breaker::RawUpstreamError::from_status(status)
    }

    /// Can this operation produce a client-facing incremental stream?
    fn streaming(&self) -> bool {
        false
    }
    /// Should the non-stream 2xx body be buffered so [`Self::extract_usage`] can read it?
    fn taps_usage(&self) -> bool {
        false
    }
    /// The caller's stream intent, from the parsed ingress body. Chat reads the OpenAI-family
    /// `"stream"` boolean; a non-streaming op never asks upstream to stream.
    fn wants_stream(&self, _body: &Value) -> bool {
        false
    }
    /// A body-derived session-affinity key (used only when no affinity header is present). Chat uses
    /// the top-level Anthropic-shaped `system` string.
    fn body_affinity_key<'a>(&self, _body: &'a Value) -> Option<&'a str> {
        None
    }
    /// Extract billable usage from a complete same-protocol non-stream 2xx body (called once at stream
    /// end, only when [`Self::taps_usage`] is true). Default: run THIS operation's own reader over the
    /// body and project its token usage — so a token-metered non-chat op (embeddings) bills the same
    /// as the cross-protocol path. Chat overrides this to run the egress protocol's chat reader.
    fn extract_usage(
        &self,
        ingress_protocol: &str,
        body: &[u8],
    ) -> Option<crate::billing::TokenUsage> {
        match self.read_response(body) {
            Ok(r) => r.token_usage(),
            Err(e) => {
                // A same-protocol 2xx body the op's own codec cannot decode: record it (like the
                // cross-protocol seam) rather than silently bill 0 tokens with no operator signal.
                // Warn-once-per-(protocol,reason); the BILLING_TAP_DECODE_FAIL_TOTAL counter carries
                // the per-request volume so the log does not spam.
                if usage_tap_decode_fail_should_warn(ingress_protocol, "decode") {
                    diag_warn!(
                        USAGE_TAP_DECODE_FAILED,
                        protocol = ingress_protocol,
                        error = ?e,
                        "usage tap: read_response failed to decode a same-protocol 2xx body; \
                         billing 0 tokens for this request"
                    );
                } else {
                    diag_debug!(
                        USAGE_TAP_DECODE_FAILED,
                        protocol = ingress_protocol,
                        error = ?e,
                        "usage tap: read_response still failing to decode a same-protocol 2xx body; \
                         billing 0 tokens for this request"
                    );
                }
                None
            }
        }
    }
    /// The Content-Type of THIS operation's egress request wire (what `write_request` emits).
    /// JSON for every JSON-bodied operation; a multipart operation overrides with its boundary.
    fn egress_request_content_type(&self) -> &'static str {
        crate::proxy::APPLICATION_JSON
    }

    /// The egress `Accept` header for the upstream request, resolved from the egress protocol's
    /// declaration (`ProtocolDecl::egress_stream_accept` when streaming, universal `application/json`
    /// otherwise) — the pure per-protocol constant read off the declaration instead of an allocated
    /// writer vtable. A binary-response op (audio speech) overrides to `*/*`.
    fn egress_accept(&self, egress_protocol: &str, wants_stream: bool) -> &'static str {
        if wants_stream {
            crate::proto::decl_for(egress_protocol)
                .map(|d| d.egress_stream_accept)
                .unwrap_or(crate::proxy::TEXT_EVENT_STREAM)
        } else {
            crate::proxy::APPLICATION_JSON
        }
    }

    /// Value-level codec bridge (request) — for engine seams that already hold a PARSED JSON body
    /// (the streaming chat engine parses once for shim/intent reads). Default round-trips through the
    /// byte reader; chat overrides to call its proto reader directly (no re-serialize on the hot
    /// path). The WRITE half of the old bridge inverted onto the handle at the G6 A4b dissolve
    /// (`IrHandle::write_egress_request`/`write_ingress_response`), so only the read side remains here.
    fn read_request_value(&self, v: &Value) -> Result<Box<dyn IrHandle>, IngressReject> {
        let bytes = serde_json::to_vec(v).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        self.read_request(&bytes, crate::proxy::APPLICATION_JSON)
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

/// What a request-translation hop reads FROM — the two body shapes a hop can hold: a parsed JSON
/// object `Value` (the value-codec fast path chat overrides to avoid a re-serialize), or opaque
/// bytes + their content-type (a multipart/binary wire the byte codec owns). The [`TranslateCodec`]
/// entrypoint branches on this exactly as the two pre-cutover call sites did.
pub enum TranslateReqInput<'a> {
    /// A JSON-object body — routed through the value codecs.
    Json(&'a Value),
    /// An opaque/binary body (multipart transcription, audio speech) — routed through the byte codecs.
    Opaque {
        bytes: &'a [u8],
        content_type: &'a str,
    },
}

/// The egress request wire a hop produced: a JSON `Value` still to be shim/model-shaped by the
/// router before serialization, or a FINAL body (a non-JSON egress wire — multipart transcription /
/// audio). Mirrors the pre-cutover `write_request_value` `Some(Value)` / `None`→`write_request` split.
pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(Bytes),
}

/// The neutral result of a cross-protocol request translation: the egress wire plus the caller
/// controls the egress dialect dropped (surfaced for the seam's audit-and-allow event; empty on the
/// opaque path, which carries no droppable controls).
pub struct TranslatedRequest {
    pub wire: EgressWire,
    pub dropped_controls: Vec<&'static str>,
}

/// Why a cross-protocol request translation could not proceed — the three terminal outcomes the
/// pre-cutover wire seam mapped to a response. The seam owns the projection into an ingress-native
/// error (`ingress_reject_response` / 404 / 400) so the codec entrypoint names no HTTP shape.
pub enum TranslateReqReject {
    /// The ingress reader refused the body → the caller renders `ingress_reject_response`.
    Ingress(IngressReject),
    /// The egress protocol does not serve this operation → the caller renders the 404
    /// (`DETAIL_MODEL_UNSUPPORTED_OPERATION`). Surfaced only AFTER read+prepare, preserving the exact
    /// ordering the JSON branch always had (a malformed body still rejects as a 400, not a 404).
    EgressUnsupported,
    /// The egress dialect cannot represent the request without silent loss → the caller renders a 400
    /// carrying `reason`.
    Unrepresentable(String),
}

/// What a non-stream response-translation hop reads FROM — the upstream 2xx body, either a parsed
/// JSON `Value` (the value-codec path) or opaque bytes (a non-JSON upstream wire — speech audio).
/// The engine parses the body ONCE and branches into these, exactly as the pre-cutover arm did.
pub enum TranslateRespInput<'a> {
    Json(&'a Value),
    Opaque(&'a [u8]),
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the
/// pre-cutover buffered-response arm: a delivered body (JSON / typed / synthesized native frames), or
/// one of the two read-succeeded-but-undelivered terminals the caller still renders (404 / 500).
pub enum TranslatedResponse {
    /// A JSON ingress body (`application/json`) the caller still post-processes (native response-metrics
    /// injection, gemini JSON-array wrap) before delivery.
    Json(Value),
    /// A final ingress body + its own content-type (a non-JSON ingress wire — speech audio — or the
    /// opaque egress→ingress bridge).
    Typed(WireBody),
    /// Synthesized native stream frames (a wants-stream ingress answered by a BUFFERED upstream — e.g.
    /// a Bedrock ConverseStream client served a non-SSE Converse body). Delivered under the ingress
    /// stream content-type.
    StreamFrames(Vec<u8>),
    /// JSON path only: the ingress protocol does not serve this operation → the caller renders the 404
    /// (`DETAIL_ENDPOINT_UNSUPPORTED_OPERATION`). The egress read still succeeded, so its usage bills.
    IngressUnsupported,
    /// Opaque path only: the egress read succeeded but the ingress handler is absent, so no client body
    /// could be written → the caller falls through to its ingress-native untranslatable 500. The usage
    /// still bills (the pre-cutover arm records it before this fall-through).
    Untranslatable,
}

/// THE SINGLE NEUTRAL TRANSLATE ENTRYPOINT ON THE CODEC CELL (G6 step 4).
///
/// Every request/response hop flows through this trait so core never orchestrates the concrete
/// read→prepare→write pipeline itself: `wire.rs`'s cross-protocol request seam calls
/// [`Self::translate_request`], the engine's non-stream cross-protocol response arm calls
/// [`Self::translate_response`], and the hook / lazy-body read side calls [`Self::read_facts`] /
/// [`Self::read_facts_value`]. The streaming half already routes through the registry
/// [`crate::proto::new_stream_translator`] factory (G6 step 3).
///
/// It is a NEUTRAL ENTRYPOINT wrapping the EXISTING concrete `IrReq`/`IrResp` codec pipeline
/// UNCHANGED — the default methods read/prepare/write through the very same `OperationHandler`
/// methods the pre-cutover call sites named inline, so every hop stays byte-identical. The concrete
/// IR is dissolved onto `Box<dyn IrHandle>` in the ATOMIC relocation (step 5); here the internals are
/// deliberately concrete.
///
/// Blanket-implemented for every [`OperationHandler`], so any codec cell (`&dyn OperationHandler`) is
/// also a `TranslateCodec` with no per-cell wiring.
pub trait TranslateCodec: OperationHandler {
    /// CROSS-PROTOCOL request translation: `self` is the INGRESS codec (it reads), `egress` is the
    /// lane's codec (it writes). Reproduces the pre-cutover pipeline exactly:
    ///   - Opaque: read → `prepare_for_egress` → `set_model` → egress `write_request` (bytes). No
    ///     representability guard / dropped-controls (an opaque body carries none); `egress` is
    ///     resolved+404-checked by the caller before this is reached, so it is always `Some` here.
    ///   - JSON: read → `prepare_for_egress` → (egress absent ⇒ [`TranslateReqReject::EgressUnsupported`])
    ///     → representability guard → collect dropped controls → egress `write_request_value`
    ///     (`Some` ⇒ a JSON body the router still post-shapes; `None` ⇒ `set_model` + `write_request`
    ///     bytes).
    ///
    /// `prep` is the router-built neutral param bag; `model` is the resolved lane wire model.
    fn translate_request(
        &self,
        input: TranslateReqInput<'_>,
        egress_proto: Option<&str>,
        prep: &crate::ir::egress_prep::EgressPrep,
        model: &str,
    ) -> Result<TranslatedRequest, TranslateReqReject> {
        match input {
            TranslateReqInput::Opaque {
                bytes,
                content_type,
            } => {
                let mut ir = self
                    .read_request(bytes, content_type)
                    .map_err(TranslateReqReject::Ingress)?;
                ir.prepare_for_egress(prep);
                // The opaque caller resolves + 404-checks `egress` before calling, so it is always
                // `Some`; the guard preserves total-safety without a panic on the request path.
                let egress_proto = egress_proto.ok_or(TranslateReqReject::EgressUnsupported)?;
                // A4b: the handle writes ITSELF onto the egress dialect (by protocol string) after
                // `set_model` — byte-identical to the former `set_model(model); egress.write_request`.
                Ok(TranslatedRequest {
                    wire: EgressWire::Bytes(ir.write_egress_request_bytes(egress_proto, model)),
                    dropped_controls: Vec::new(),
                })
            }
            TranslateReqInput::Json(v) => {
                let mut ir = self
                    .read_request_value(v)
                    .map_err(TranslateReqReject::Ingress)?;
                ir.prepare_for_egress(prep);
                // Egress-absent surfaces only AFTER read+prepare, so a malformed body still rejects as
                // a 400 (via `Ingress` above) rather than a 404, exactly as the pre-cutover branch did.
                let egress_proto = egress_proto.ok_or(TranslateReqReject::EgressUnsupported)?;
                if let Err(reason) = ir.egress_representable(egress_proto) {
                    return Err(TranslateReqReject::Unrepresentable(reason));
                }
                let dropped_controls = ir.egress_dropped_controls(egress_proto);
                // A4b: the handle owns the value-first / set-model+bytes write onto the egress dialect.
                let wire = ir.write_egress_request(egress_proto, model);
                Ok(TranslatedRequest {
                    wire,
                    dropped_controls,
                })
            }
        }
    }

    /// Read the request facts the hook seam / lazy-body projects from — the ONE read, through this
    /// codec's own reader, projected to the neutral [`crate::ir::facts::IrFacts`]. The value-codec
    /// path (chat overrides it to call its proto reader directly — no re-serialize on the hot path).
    fn read_facts_value(
        &self,
        v: &Value,
    ) -> Result<Box<dyn crate::ir::facts::IrFacts + Send + Sync>, IngressReject> {
        Ok(self.read_request_value(v)?.facts())
    }

    /// Byte-codec sibling of [`Self::read_facts_value`], for an opaque/multipart body whose caller
    /// text is reachable only through the byte reader.
    fn read_facts(
        &self,
        wire: &[u8],
        content_type: &str,
    ) -> Result<Box<dyn crate::ir::facts::IrFacts + Send + Sync>, IngressReject> {
        Ok(self.read_request(wire, content_type)?.facts())
    }

    /// CROSS-PROTOCOL non-stream response translation: `self` is the EGRESS codec (it reads the
    /// upstream 2xx body), `ingress_op`/`ingress_writer` write the caller's dialect. Reproduces the
    /// pre-cutover buffered-response pipeline exactly:
    ///   - read (`read_response` / `read_response_value`, `Err` ⇒ [`CodecError`]) → capture the
    ///     billable usage from the PRE-`prepare_for_ingress` IR (byte-identical to the old
    ///     `record_resp_usage(&ir)` placement) → `prepare_for_ingress` →
    ///   - JSON, wants-stream: `wrap_buffered_as_stream` `Some` ⇒ [`TranslatedResponse::StreamFrames`];
    ///   - JSON: ingress absent ⇒ [`TranslatedResponse::IngressUnsupported`]; else
    ///     `write_response_value` (`Some` ⇒ [`TranslatedResponse::Json`], `None` ⇒
    ///     [`TranslatedResponse::Typed`]);
    ///   - Opaque: ingress present ⇒ [`TranslatedResponse::Typed`], absent ⇒
    ///     [`TranslatedResponse::Untranslatable`].
    ///
    /// The returned usage is ALWAYS the read IR's usage (`ir.usage()`), which the caller bills before
    /// rendering the outcome — so a read-succeeded-but-undelivered terminal (404 / 500) still bills,
    /// exactly as the pre-cutover arm did. The caller keeps telemetry, the untranslatable-metadata warn,
    /// billing, budget accounting, native response-metrics injection, the gemini-array wrap, and all
    /// response building — none of which is the codec's business.
    fn translate_response(
        &self,
        input: TranslateRespInput<'_>,
        // Does the caller's INGRESS protocol serve this operation? (Resolved by the engine via
        // `op_for`; replaces the former `ingress_op: Option<&dyn OperationHandler>`.)
        ingress_serves_op: bool,
        ingress_protocol: &str,
        now: u64,
        wants_stream: bool,
        elapsed_ms: Option<u64>,
    ) -> Result<(Option<crate::billing::Billing>, TranslatedResponse), CodecError> {
        match input {
            TranslateRespInput::Opaque(bytes) => {
                let mut ir = self.read_response(bytes)?;
                let usage = ir.billing();
                ir.prepare_for_ingress(ingress_protocol, now);
                // A4b: the handle writes ITSELF onto the ingress dialect — present=>Typed /
                // absent=>Untranslatable, keyed by `ingress_protocol` + `ingress_serves_op`.
                Ok((
                    usage,
                    ir.write_ingress_response_bytes(ingress_protocol, ingress_serves_op),
                ))
            }
            TranslateRespInput::Json(v) => {
                let mut ir = self.read_response_value(v)?;
                let usage = ir.billing();
                ir.prepare_for_ingress(ingress_protocol, now);
                // Buffered-2xx-to-native-stream synthesis (a wants-stream ingress served a non-SSE
                // upstream): try first; `None` falls through to the normal write. The handle resolves
                // the ingress writer by `ingress_protocol` internally.
                if wants_stream {
                    if let Some(frames) = ir.wrap_buffered_as_stream(ingress_protocol, elapsed_ms) {
                        return Ok((usage, TranslatedResponse::StreamFrames(frames)));
                    }
                }
                // A4b: the handle owns the absent=>IngressUnsupported / value-first=>Json / else
                // Typed(WireBody) write onto the ingress dialect.
                Ok((
                    usage,
                    ir.write_ingress_response(ingress_protocol, ingress_serves_op),
                ))
            }
        }
    }
}

impl<T: OperationHandler + ?Sized> TranslateCodec for T {}

/// A protocol's dialect + its OperationHandlers (one impl per protocol).
pub trait RequestHandler: Send + Sync {
    /// Stable protocol identity (matches `proto::Protocol::name()`). Called only from this crate's
    /// own tests (`contract_tests.rs`, `registry_tests.rs`) — it is the registry-key/impl-identity
    /// binding that `registry_tests.rs` asserts (`request_handler()` is a string-keyed registry;
    /// nothing in the type system otherwise binds an impl to the key it is filed under). A
    /// legitimate test hook whose purpose is being a test hook.
    #[cfg_attr(not(test), allow(dead_code))]
    fn protocol_name(&self) -> &'static str;

    /// This protocol's row of the support matrix. `None` ⇒ the protocol does not serve the operation
    /// ⇒ the no-handler 404. The OperationHandler, when present, is a pure codec.
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler>;

    /// WHICH operation this request asks for — the RequestHandler knows its protocol and reads the
    /// path (and, where the protocol multiplexes one endpoint, the body: Gemini `generateContent`
    /// serves chat AND audio; Bedrock `InvokeModel` serves embeddings AND images) and says "this is
    /// audio, this is chat". The Router only picks the protocol; THIS decides the operation.
    /// `None` ⇒ the path is not an operation this protocol serves.
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation>;

    /// The model named in the PATH, for path-model dialects (gemini `models/{m}:action`, bedrock
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

#[cfg(test)]
#[path = "tests/contract_tests.rs"]
mod contract_tests;

use crate::state::Lane;

/// A `(operation, transport, OperationHandler)` dispatch handle — ONE CELL of the matrix, framed —
/// threaded through the forward engine by value (`Copy`). The engine reads operation behavior off it
/// without ever naming an operation, and now carries the transport the request arrived on without
/// ever naming one of those either.
///
/// BUILT THROUGH [`crate::transport::Transport::frame`] — the framing constructor, and the only
/// thing that builds one in this tree. The three axes meet here and nowhere else: routing picks the
/// protocol, the `RequestHandler` picks the operation (and with it the codec), and the ARRIVAL
/// picks the transport. What the compiler enforces is the part that matters — no site can hold a
/// codec without having said which channel it is speaking over, which is the shape whose absence
/// let a stdio `tools:` entry sit in config with no dispatch arm to reach it.
#[derive(Clone, Copy)]
pub(crate) struct OpDispatch {
    pub(crate) operation: Operation,
    /// The channel this exchange rides. A VALUE, like `operation`: the engine labels with it and
    /// hands it on, and never compares or matches it (that would be a transport-identity branch,
    /// which `scripts/structure-lint.sh` refuses outside a `proto/` arm, its handler and its codec).
    pub(crate) transport: crate::transport::Transport,
    pub(crate) op_handler: &'static dyn OperationHandler,
}

/// The engine's operation handle. (Kept as `Op` so the engine's signatures read unchanged.)
pub(crate) type Op = OpDispatch;

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
        self.op_handler.egress_accept(egress_protocol, wants_stream)
    }
    /// The (protocol × operation) upstream path: lane override, else the lane's protocol
    /// `RequestHandler` renders it from resolved primitives (never the `Lane`). `None` only if the
    /// protocol has no registered handler — impossible for chat (all six are registered).
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

/// Chat — operation #1. A const handle to the shared chat OperationHandler, for tests and as the
/// resolver's fallback. TEST-BUILD ONLY: `ChatOperation` relocated to the `busbar-llm` plugin at the
/// G6 A4b dissolve (it names the concrete chat IR that moved there), so production core has no chat
/// codec to name; the netted `crate::proto::chat_handle::ChatOperation` supplies it for the core test
/// binary. Prefer [`chat`] on the request path so the RequestHandler actually decides the handler.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)] // exercised by the dialect test crates; unused in the netted-core target
pub(crate) const CHAT: Op = crate::transport::Transport::Http.frame(
    Operation::CHAT,
    &crate::proto::chat_handle::ChatOperation("openai"),
);

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
pub(crate) fn chat(protocol: &str, transport: crate::transport::Transport) -> Op {
    op_for(protocol, Operation::CHAT, transport)
        .expect("a chat-serving protocol is registered (the busbar-llm plugin registers openai)")
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
        .map(|op_handler| transport.frame(operation, op_handler))
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
