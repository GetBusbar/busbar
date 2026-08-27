// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL HANDLER MATRIX — the neutral codec-cell surface a plane crate
//! (`busbar-mcp`, `busbar-llm`, `busbar-a2a`) implements without reaching into `busbar-core`.
//!
//! `RequestHandler → OperationHandler → IR`
//!
//! - [`RequestHandler`] — ONE per protocol. Reads path+body to decide WHICH operation a request
//!   asks for (`resolve_operation`), owns the `(protocol, operation) → path template`
//!   (`upstream_path`), and holds its row of the support matrix (`operation_handler`).
//! - [`OperationHandler`] — ONE per (protocol × operation). A pure codec: wire ↔ IR, both
//!   directions, plus the operation-capability surface the engine reads. It never routes, fails
//!   over, checks auth, bills, or knows another protocol exists.
//!
//! RELOCATED DOWN from `busbar-core` (`handlers`) so the dialect crates implement these traits
//! against the neutral substrate; core re-exports every item from its historical
//! `busbar_core::handlers::…` path so its own call sites (and the netted dual-compile test build)
//! are unchanged. The engine dispatch handle (`OpDispatch`), the registry-resolved `chat`/`op_for`
//! resolvers and `protocol_error` STAY in core — those name the core registry singleton.

use crate::billing::TokenUsage;
use crate::diagnostics::USAGE_TAP_DECODE_FAILED;
use crate::ir::egress_prep::EgressPrep;
use crate::ir::facts::IrFacts;
use crate::ir::handle::IrHandle;
use crate::wire::{EgressCtx, EgressWire, TranslatedResponse};
use busbar_api::operation::Operation;
use serde_json::Value;

/// A same-protocol 2xx response body the usage tap could not decode into token usage, so the request
/// was billed 0 tokens. Labeled by `protocol` (the ingress protocol, a fixed enumeration) and
/// `reason` (`unknown_protocol` / `bad_json` / `decode`). This is the per-request VOLUME signal for the
/// tap-decode fault class: the log site is warn-once-per-(protocol,reason) to avoid per-request spam,
/// so this counter — not the log — is what an operator alerts on. A steady non-zero rate means a live
/// protocol/dialect the tap reader cannot decode, i.e. silent under-billing.
pub const BILLING_TAP_DECODE_FAIL_TOTAL: &str = "busbar_billing_tap_decode_fail_total"; // labels: protocol, reason

/// Process-lifetime warn-once latch for the usage-tap decode fault class, keyed `protocol:reason`. A
/// live protocol/dialect the tap reader cannot decode fails on EVERY 2xx body of that shape, so an
/// unlatched `warn!` spams per request; [`BILLING_TAP_DECODE_FAIL_TOTAL`] carries the per-request
/// volume. This records the fault (increments the counter) and returns `true` only the FIRST time a
/// given `(protocol, reason)` is seen, so the caller warns once and logs `debug!` thereafter.
pub fn usage_tap_decode_fail_should_warn(protocol: &str, reason: &'static str) -> bool {
    metrics::counter!(
        BILLING_TAP_DECODE_FAIL_TOTAL,
        "protocol" => protocol.to_string(),
        "reason" => reason,
    )
    .increment(1);
    static SEEN: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    seen.insert(format!("{protocol}:{reason}"))
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
    /// upstream (`op_for`) and ask it, rather than reaching a chat vtable through a `Lane`. An
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
    fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<TokenUsage> {
        match self.read_response(body) {
            Ok(r) => r.token_usage(),
            Err(e) => {
                // A same-protocol 2xx body the op's own codec cannot decode: record it (like the
                // cross-protocol seam) rather than silently bill 0 tokens with no operator signal.
                // Warn-once-per-(protocol,reason); the BILLING_TAP_DECODE_FAIL_TOTAL counter carries
                // the per-request volume so the log does not spam.
                if usage_tap_decode_fail_should_warn(ingress_protocol, "decode") {
                    ::tracing::warn!(
                        diag = %USAGE_TAP_DECODE_FAILED.banner(),
                        protocol = ingress_protocol,
                        error = ?e,
                        "usage tap: read_response failed to decode a same-protocol 2xx body; \
                         billing 0 tokens for this request"
                    );
                } else {
                    ::tracing::debug!(
                        diag = %USAGE_TAP_DECODE_FAILED.banner(),
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

/// THE SINGLE NEUTRAL TRANSLATE ENTRYPOINT ON THE CODEC CELL (G6 step 4).
///
/// Every request/response hop flows through this trait so core never orchestrates the concrete
/// read→prepare→write pipeline itself: `wire.rs`'s cross-protocol request seam calls
/// [`Self::translate_request`], the engine's non-stream cross-protocol response arm calls
/// [`Self::translate_response`], and the hook / lazy-body read side calls [`Self::read_facts`] /
/// [`Self::read_facts_value`]. The streaming half already routes through the registry
/// `proto::new_stream_translator` factory (G6 step 3).
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
        prep: &EgressPrep,
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
    fn read_facts_value(&self, v: &Value) -> Result<Box<dyn IrFacts + Send + Sync>, IngressReject> {
        Ok(self.read_request_value(v)?.facts())
    }

    /// Byte-codec sibling of [`Self::read_facts_value`], for an opaque/multipart body whose caller
    /// text is reachable only through the byte reader.
    fn read_facts(
        &self,
        wire: &[u8],
        content_type: &str,
    ) -> Result<Box<dyn IrFacts + Send + Sync>, IngressReject> {
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
    /// Stable protocol identity (matches `proto::Protocol::name()`). Called only from `busbar-core`'s
    /// own tests (`contract_tests.rs`, `registry_tests.rs`) — it is the registry-key/impl-identity
    /// binding that `registry_tests.rs` asserts (`request_handler()` is a string-keyed registry;
    /// nothing in the type system otherwise binds an impl to the key it is filed under). A
    /// legitimate test hook whose purpose is being a test hook.
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
