// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSS-DIALECT TRANSLATE PIPELINE (#83a SD-3: dialect machinery). Translating one dialect's
//! request or response into another's — read through the ingress cell, prepare, write through the
//! egress dialect — is this plane's own rule (Law 5), so the pipeline lives with the dialects: the
//! [`TranslateCodec`](crate::translate::TranslateCodec) entrypoint, blanket-implemented for every codec cell, and the values its two
//! directions read from and answer with. The cell traits it is written over are contract shapes
//! (`busbar_contract::codec`); nothing here names the host.

use busbar_contract::billing::Billing;
use busbar_contract::codec::{
    CodecError, EgressWire, IngressReject, OperationHandler, TranslatedResponse,
};
use busbar_contract::ir::egress_prep::EgressPrep;
use busbar_contract::ir::facts::IrFacts;
use serde_json::Value;

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
                // A write that could not be represented is a REFUSAL, on the same terminal the
                // pre-write representability guard above uses: the guard answers before the write
                // for what it can see, and this answers after it for what only the writer can.
                if let EgressWire::Unrepresentable { reason } = wire {
                    return Err(TranslateReqReject::Unrepresentable(reason));
                }
                Ok(TranslatedRequest {
                    wire,
                    dropped_controls,
                })
            }
        }
    }

    /// Read the request facts the hook seam / lazy-body projects from — the ONE read, through this
    /// codec's own reader, projected to the neutral [`IrFacts`]. The value-codec
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
    ///     `record_resp_usage(&ir)` placement) → fill the serving model from `lane_model` IFF the
    ///     upstream body carried none ([`busbar_contract::ir::handle::IrHandle::fill_response_model_if_absent`]) →
    ///     `prepare_for_ingress` →
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
    #[allow(clippy::too_many_arguments)]
    fn translate_response(
        &self,
        input: TranslateRespInput<'_>,
        // Does the caller's INGRESS protocol serve this operation? (Resolved by the engine via
        // `op_for`; replaces the former `ingress_op: Option<&dyn OperationHandler>`.)
        ingress_serves_op: bool,
        ingress_protocol: &str,
        // The resolved lane WIRE model the proxy routed this hop to. Used to fill the response model
        // when the upstream body carried none — see [`busbar_contract::ir::handle::IrHandle::fill_response_model_if_absent`]. Fill
        // happens AFTER read (so we see the upstream's own model first) and BEFORE `prepare_for_ingress`
        // + the ingress write, so a cross-protocol response reports the REAL serving model losslessly.
        lane_model: &str,
        now: u64,
        wants_stream: bool,
        elapsed_ms: Option<u64>,
        // The ORIGINAL ingress request body, when the caller has one parsed (the cross-protocol
        // path always does — see `Hop::body`). Threaded to `IrHandle::apply_request_echo` so a
        // dialect whose response spec requires certain members to MIRROR the request (OpenAI
        // Responses) can answer with the client's actual values instead of the spec's bare
        // defaults. `None` when the caller has no parsed ingress body (the opaque/audio bridge).
        ingress_request_body: Option<&Value>,
    ) -> Result<(Option<Billing>, TranslatedResponse), CodecError> {
        match input {
            TranslateRespInput::Opaque(bytes) => {
                let mut ir = self.read_response(bytes)?;
                let usage = ir.billing();
                ir.fill_response_model_if_absent(lane_model);
                if let Some(body) = ingress_request_body {
                    ir.apply_request_echo(body);
                }
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
                ir.fill_response_model_if_absent(lane_model);
                if let Some(body) = ingress_request_body {
                    ir.apply_request_echo(body);
                }
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
