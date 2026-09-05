//! The plane, implemented.
//!
//! Every method below is an adapter. It works out which dialect it is looking at, hands the bytes to
//! the codec that already knows that dialect, and turns what comes back into the shapes the loop
//! asks for. The interesting reading is in the codec crate; the interesting decisions are in the
//! units. What is here is the wiring, and it is meant to stay boring enough to check by eye.

use busbar_contract::bounded::{ArenaBytes, FactValue, Facts, Ir, Span};
use busbar_contract::dest::{DestinationFacts, EgressBody, Leg, RoutePlan, VerifiedDestination};
use busbar_contract::grammar::{ArrivalLocation, Location};
use busbar_contract::ids::{AdminVerbId, MeterClassId, OpClassId, SchemeAlt, SchemeKey};
use busbar_contract::kinds::{ContentFacts, CredentialLocator, PlaneFacts};
use busbar_contract::plane::{Ingress, Plane, PlaneSessionState, Progress, Response, UnitDraft};
use busbar_contract::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, RefusalReason, ResourceLocator, ScopeFacts,
    Unit, UnitEnd, UsageLocator, UsageLocators,
};
use busbar_contract::wire::{Decode, Encode, EnvelopeField, Frame, FrameCursor, TransportEnvelope};

use busbar_llm::ir::{IrResponse, IrStopReason, IrStreamEvent, StreamDecodeState};

use crate::dialect::{self, Dialect};
use crate::meta;
use crate::{LlmPlane, Upstream};

// ── the error vocabulary the dialect envelopes are shaped around ────────────────────────────────
//
// The BYTES of a refusal are the dialect writer's; only the kind token and the status are chosen
// here, and they are chosen exactly as the existing forward path chooses them. Restating the tokens
// is the one duplication in this crate and it is deliberate: reaching for them through the crate
// that holds them would pull an HTTP stack into a plane.

/// The token an authentication refusal wears.
const KIND_AUTHENTICATION: &str = "authentication_error";
/// The token a permission refusal wears.
const KIND_PERMISSION: &str = "permission_error";
/// The token a rate refusal wears.
const KIND_RATE_LIMIT: &str = "rate_limit_error";
/// The token a malformed-or-unacceptable request wears.
const KIND_INVALID_REQUEST: &str = "invalid_request_error";
/// The token a node-side capacity refusal wears.
const KIND_OVERLOADED: &str = "overloaded_error";
/// The token an oversized request wears.
const KIND_REQUEST_TOO_LARGE: &str = "request_too_large";
/// The token a node-side fault wears.
const KIND_API_ERROR: &str = "api_error";

/// The transport fact the request target is published under.
///
/// A plane cannot see a connection, so the request target reaches it as a transport fact. This is
/// the key the transport writes it under; a transport that writes none leaves this plane unable to
/// name a dialect, and the decode step says so rather than guessing.
const FACT_PATH: &str = "path";

/// The default response ceiling used when a dialect requires one and the client sent none.
///
/// The design fixes the fallback and the order it is reached in: the lane's own default, then the
/// configured default, then this. It is injected only when the request carries NO ceiling — a
/// client-supplied value is never rewritten and never clamped here.
const DEFAULT_MAX_RESPONSE: u32 = 4096;

/// The configuration key the operator's own default response ceiling is read from.
const CONFIG_MAX_RESPONSE: &str = "default_max_tokens";

// ── working out which dialect is in play ────────────────────────────────────────────────────────

/// Which dialect the arriving bytes are, from the request target and the headers the transport
/// published as facts.
///
/// This is the ladder, walked in rung order. It is the same ladder the kernel walks over the
/// declared claims; walking it here as well is what lets the decode step name the dialect it is
/// about to read without a second, differently-ordered answer existing anywhere.
fn ingress_dialect<'u>(ctx: &Ctx<'u>) -> Option<&'static Dialect> {
    let transport = ctx.transport();
    let path = transport.fact(FACT_PATH)?;
    let header = |name: &str| transport.fact(name);
    let name = crate::claims::dialect_for(path, &header)?;
    dialect::dialect(name)
}

/// Which dialect a verified destination speaks, and what to rewrite the model to.
fn upstream_for(plane: &LlmPlane, dest: &VerifiedDestination) -> Option<&'static Upstream> {
    let lane = dest.lane()?;
    plane.upstreams().iter().find(|u| u.lane == lane)
}

/// Parse a body the way the codec parses one.
///
/// The same reader the forward path uses, so a body this plane accepts is a body the codec accepts,
/// and a body it refuses is refused for the codec's reason rather than for a second opinion's.
fn parse(bytes: &[u8]) -> Result<serde_json::Value, Decode> {
    sonic_rs::from_slice(bytes).map_err(|_| Decode::Malformed)
}

/// Serialize a document the way the codec serializes one.
fn serialize(value: &serde_json::Value) -> Result<Vec<u8>, Encode> {
    sonic_rs::to_vec(value).map_err(|_| Encode::Unrepresentable)
}

/// Copy bytes into the per-unit arena.
fn put<'u>(ctx: &Ctx<'u>, bytes: &[u8]) -> Result<ArenaBytes<'u>, Encode> {
    ctx.arena()
        .alloc_bytes(bytes)
        .map_err(|_| Encode::ArenaExhausted)
}

/// Copy a string into the per-unit arena.
fn put_str<'u>(ctx: &Ctx<'u>, s: &str) -> Option<&'u str> {
    ctx.arena().alloc_str(s).ok()
}

/// How the dialect's own stop reason reads as a finish class.
///
/// A cut-short answer and a completed one settle differently, so the mapping is written out rather
/// than defaulted: an upstream that reported an error, and an upstream that ran out of room, are
/// both endings the ledger prices differently from a natural stop.
fn finish_of(stop: Option<IrStopReason>) -> FinishClass {
    match stop {
        Some(IrStopReason::Error) => FinishClass::Error,
        Some(IrStopReason::MaxTokens) | Some(IrStopReason::PauseTurn) => FinishClass::Partial,
        Some(_) => FinishClass::Complete,
        // No reason reported at all is not evidence of completion.
        None => FinishClass::Partial,
    }
}

/// The status and kind token one refusal reason wears on the wire.
///
/// The reason code itself never reaches a client: what reaches a client is this dialect's own
/// rendering of the pair below, written by the dialect's own error writer.
fn refusal_shape(reason: RefusalReason) -> (u16, &'static str) {
    match reason {
        RefusalReason::CredentialRejected
        | RefusalReason::SessionUnbound
        | RefusalReason::SchemeNotDeclared => (401, KIND_AUTHENTICATION),
        RefusalReason::Revoked | RefusalReason::ScopeMissing | RefusalReason::Vetoed => {
            (403, KIND_PERMISSION)
        }
        RefusalReason::BodyTooLarge
        | RefusalReason::CursorBudget
        | RefusalReason::CredentialBudget => (413, KIND_REQUEST_TOO_LARGE),
        RefusalReason::InFlightCap
        | RefusalReason::SessionBudget
        | RefusalReason::OpenSlotBusy
        | RefusalReason::OverBudget
        | RefusalReason::GroupFrozen
        | RefusalReason::OverdraftCeiling => (429, KIND_RATE_LIMIT),
        RefusalReason::NoDestination | RefusalReason::Unpriced => (400, KIND_INVALID_REQUEST),
        RefusalReason::DurabilityUnavailable
        | RefusalReason::StaleSlice
        | RefusalReason::TierMismatch => (503, KIND_OVERLOADED),
    }
}

/// The message a refusal carries.
///
/// Deliberately a small closed set of neutral sentences: a refusal message is read by a client, and
/// a client must not learn from it which internal ceiling it hit.
fn refusal_message(reason: RefusalReason) -> &'static str {
    match refusal_shape(reason).0 {
        401 => "Authentication failed.",
        403 => "Not permitted.",
        413 => "Request too large.",
        429 => "Rate limited.",
        503 => "Temporarily unavailable.",
        _ => "Request rejected.",
    }
}

/// Which operation class a request target names.
///
/// The dialects' own resolvers read the body as well as the target for two of the six; this reads
/// the target only, which is enough for every class the previous release billed and is what the
/// ladder's own rungs already distinguish. A target that names none of the non-chat surfaces is a
/// conversation, which is what every one of the six dialects' primary surface is.
fn op_class_for(path: &str) -> OpClassId {
    if path.ends_with("/v1/embeddings")
        || path.ends_with("/v2/embed")
        || path.contains(":embedContent")
        || path.contains(":batchEmbedContents")
    {
        OpClassId::new("embeddings")
    } else if path.ends_with("/v1/moderations") {
        OpClassId::new("moderation")
    } else if path.ends_with("/v2/rerank") {
        OpClassId::new("rerank")
    } else if path.contains("/v1/images/") || path.contains(":predict") {
        OpClassId::new("image")
    } else if path.contains("/v1/audio/transcriptions") || path.contains("/v1/audio/translations") {
        OpClassId::new("transcription")
    } else if path.contains("/v1/audio/speech") {
        OpClassId::new("speech")
    } else {
        OpClassId::new("chat")
    }
}

/// Whether a frame is one event of a streamed answer rather than a whole body.
fn is_event_frame(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(8)];
    head.starts_with(b"event:") || head.starts_with(b"data:")
}

/// Split one streamed event into its name and its payload.
///
/// The framing is the transport's, so this reads only what the transport left: the two named lines,
/// in either order, with the payload taken verbatim.
fn split_event(bytes: &[u8]) -> (&str, &[u8]) {
    let text = core::str::from_utf8(bytes).unwrap_or_default();
    let mut name = "";
    let mut data: &[u8] = b"";
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            name = rest.trim();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data = rest.trim_start().as_bytes();
        }
    }
    (name, data)
}

/// The per-connection codec state a streamed answer needs.
///
/// One value, held by the kernel, handed in and taken back. Nothing about a stream lives in the
/// plane itself, which is what makes the plane a value rather than an object.
#[derive(Debug, Default)]
pub struct LlmSessionState {
    /// Where the reader had got to in the dialect's own event grammar.
    pub decode: StreamDecodeState,
}

/// The reader's stream state, or a fresh one when the kernel is holding none.
///
/// A transport with no session hands no state, and a dialect whose events are independent of one
/// another reads correctly from a fresh state. A dialect whose events are not independent needs the
/// session transport, and the registry is what requires it.
fn decode_state(st: Option<&mut PlaneSessionState>) -> StreamDecodeState {
    st.and_then(|s| s.get::<LlmSessionState>())
        .map(|s| s.decode.clone())
        .unwrap_or_default()
}

impl Plane for LlmPlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        let Some(frame) = frames.next_frame() else {
            return Ok(Ingress::NeedMore);
        };
        let d = ingress_dialect(ctx).ok_or(Decode::UnsupportedOperation)?;
        let path = ctx.transport().fact(FACT_PATH).unwrap_or_default();
        let bytes = frame.bytes.as_slice();

        // The codec's own reader is what says whether these bytes are this dialect's shape. A
        // second opinion here would be a second dialect.
        let value = parse(bytes)?;
        let protocol =
            busbar_llm::proto_codec::protocol_for(d.name).ok_or(Decode::UnsupportedOperation)?;
        let request = protocol
            .reader()
            .read_request(&value)
            .map_err(|_| Decode::Malformed)?;

        let body = ctx
            .arena()
            .alloc_bytes(bytes)
            .map_err(|_| Decode::Oversize)?;

        let mut facts = Facts::new();
        let _ = facts.set(meta::FACT_DIALECT, FactValue::Str(d.name));
        let _ = facts.set(
            meta::FACT_OPERATION,
            FactValue::Str(op_class_for(path).as_str()),
        );
        if let Some(model) = value.get("model").and_then(serde_json::Value::as_str) {
            if let Some(model) = put_str(ctx, model) {
                let _ = facts.set(meta::FACT_MODEL, FactValue::Str(model));
            }
        }
        let _ = facts.set(
            meta::FACT_STREAM,
            FactValue::Bool(
                value
                    .get("stream")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            ),
        );
        // The response ceiling the client asked for, as evidence. It is a fact, never a decision:
        // what it is clamped to is the admission step's business.
        if let Some(max) = request.max_tokens {
            let _ = facts.set(meta::FACT_MAX_RESPONSE, FactValue::Int(i64::from(max)));
        }

        Ok(Ingress::OneShot(UnitDraft {
            op: op_class_for(path),
            // The span table is empty on purpose: the arena hands out bytes and strings, and there
            // is no way through it to allocate a table of resolved pointers. The kernel's own
            // scanner resolves the locations the admission step names, which is where the design
            // says the authoritative resolution happens anyway.
            body_ir: Ir::new(body.as_slice(), &[]),
            correlates: None,
            correlation_out: None,
            facts,
        }))
    }

    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        let upstream = upstream_for(self, dest).ok_or(Encode::Unrepresentable)?;
        let egress = dialect::dialect(upstream.dialect).ok_or(Encode::Unrepresentable)?;
        let ingress = ingress_dialect(ctx).ok_or(Encode::Unrepresentable)?;

        let egress_protocol =
            busbar_llm::proto_codec::protocol_for(egress.name).ok_or(Encode::Unrepresentable)?;
        let bytes = u.body().body();
        let mut value: serde_json::Value =
            sonic_rs::from_slice(bytes).map_err(|_| Encode::Unrepresentable)?;

        let stream = value
            .get("stream")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let out = if ingress.name == egress.name {
            // Same dialect. The bytes the client sent are the bytes the upstream gets, unless the
            // model has to change — re-serializing an unchanged document would move whitespace and
            // member order for no reason, and a request that is signed over its bytes would stop
            // verifying.
            if egress_protocol
                .writer()
                .rewrite_model_if_needed(&mut value, upstream.model)
            {
                serialize(&value)?
            } else {
                bytes.to_vec()
            }
        } else {
            let ingress_protocol = busbar_llm::proto_codec::protocol_for(ingress.name)
                .ok_or(Encode::Unrepresentable)?;
            let mut request = ingress_protocol
                .reader()
                .read_request(&value)
                .map_err(|_| Encode::Unrepresentable)?;
            // Two normalizations the crossing needs that neither the reader nor the writer does
            // for itself. Both are rules of the crossing, not of either dialect, which is why they
            // sit here rather than in a codec.
            //
            // A dialect that refuses a request with no response ceiling gets one — only when the
            // request carries none. A value the client sent is never rewritten and never clamped.
            if request.max_tokens.is_none() && dialect::requires_max_response(egress.name) {
                request.max_tokens = Some(configured_max_response(ctx));
            }
            // Everything the source dialect modelled and the intermediate representation does not
            // is dropped. Carrying it over would put one vendor's member names into another
            // vendor's request, where at best they are ignored and at worst they are rejected —
            // and a control that survives the crossing by accident is a control nobody chose.
            request.extra.clear();
            let mut written = egress_protocol.writer().write_request(&request);
            egress_protocol
                .writer()
                .rewrite_model_if_needed(&mut written, upstream.model);
            serialize(&written)?
        };

        let mut envelope = TransportEnvelope::default();
        let path = egress_protocol
            .writer()
            .upstream_path_for_stream(upstream.model, stream);
        let _ = envelope.fields.push(EnvelopeField {
            name: "method",
            value: put(ctx, b"POST")?,
        });
        let _ = envelope.fields.push(EnvelopeField {
            name: "path",
            value: put(ctx, path.as_bytes())?,
        });
        let _ = envelope.fields.push(EnvelopeField {
            name: "content-type",
            value: put(ctx, b"application/json")?,
        });

        Ok(EgressBody {
            envelope,
            body: put(ctx, &out)?,
            auth: SchemeKey::new(egress.egress_scheme),
        })
    }

    fn encode_ingress_frame<'u>(
        &self,
        _u: &Unit<'u>,
        _f: &Frame,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        // None of the six dialects carries a client frame that belongs to an already-open request:
        // a request is one body, and everything after it flows the other way. Consuming the frame
        // and sending nothing is the honest answer, not an error.
        Ok(None)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        let Some(frame) = frames.next_frame() else {
            return Ok(Progress::NeedMore);
        };
        let upstream = upstream_for(self, dest).ok_or(Decode::UnsupportedOperation)?;
        let egress = dialect::dialect(upstream.dialect).ok_or(Decode::UnsupportedOperation)?;
        let protocol = busbar_llm::proto_codec::protocol_for(egress.name)
            .ok_or(Decode::UnsupportedOperation)?;
        let bytes = frame.bytes.as_slice();
        let body = ctx
            .arena()
            .alloc_bytes(bytes)
            .map_err(|_| Decode::Oversize)?;

        let mut facts = Facts::new();
        let _ = facts.set(meta::FACT_SOURCE_DIALECT, FactValue::Str(egress.name));

        if is_event_frame(bytes) {
            let (name, data) = split_event(bytes);
            // The dialect's own end-of-stream marker is not a document; it ends the answer.
            if data == b"[DONE]" {
                let _ = facts.set(meta::FACT_FRAME_KIND, FactValue::Str("event"));
                return Ok(Progress::Terminal {
                    for_: None,
                    r: Response {
                        ir: Ir::new(body.as_slice(), &[]),
                        finish: FinishClass::Complete,
                        facts,
                    },
                });
            }
            let value = parse(data)?;
            let mut state = decode_state(st);
            let events = protocol
                .reader()
                .read_response_events(name, &value, &mut state);
            let _ = facts.set(meta::FACT_FRAME_KIND, FactValue::Str("event"));
            let terminal = events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageStop));
            let finish = events
                .iter()
                .find_map(|e| match e {
                    IrStreamEvent::MessageDelta { stop_reason, .. } => {
                        Some(finish_of(*stop_reason))
                    }
                    IrStreamEvent::Error(_) => Some(FinishClass::Error),
                    _ => None,
                })
                .unwrap_or(FinishClass::Partial);
            let r = Response {
                ir: Ir::new(body.as_slice(), &[]),
                finish,
                facts,
            };
            return Ok(if terminal {
                Progress::Terminal { for_: None, r }
            } else {
                Progress::Frame { for_: None, r }
            });
        }

        let value = parse(bytes)?;
        let response = protocol
            .reader()
            .read_response(&value)
            .map_err(|_| Decode::Malformed)?;
        let _ = facts.set(meta::FACT_FRAME_KIND, FactValue::Str("body"));
        response_facts(ctx, &response, &mut facts);
        Ok(Progress::Terminal {
            for_: None,
            r: Response {
                ir: Ir::new(body.as_slice(), &[]),
                finish: finish_of(response.stop_reason),
                facts,
            },
        })
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let ingress = ingress_dialect(ctx).ok_or(Encode::Unrepresentable)?;
        let source = match r.facts.get(meta::FACT_SOURCE_DIALECT) {
            Some(FactValue::Str(name)) => name,
            _ => ingress.name,
        };
        let source_protocol =
            busbar_llm::proto_codec::protocol_for(source).ok_or(Encode::Unrepresentable)?;
        let ingress_protocol =
            busbar_llm::proto_codec::protocol_for(ingress.name).ok_or(Encode::Unrepresentable)?;
        let bytes = r.ir.body();

        let is_event = matches!(
            r.facts.get(meta::FACT_FRAME_KIND),
            Some(FactValue::Str("event"))
        );
        if is_event {
            let (name, data) = split_event(bytes);
            if data == b"[DONE]" {
                return put(ctx, bytes);
            }
            let value: serde_json::Value =
                sonic_rs::from_slice(data).map_err(|_| Encode::Unrepresentable)?;
            let mut state = decode_state(st);
            let mut out = Vec::new();
            for event in source_protocol
                .reader()
                .read_response_events(name, &value, &mut state)
            {
                for (kind, payload) in ingress_protocol.writer().write_response_events(&event) {
                    out.extend_from_slice(b"event: ");
                    out.extend_from_slice(kind.as_bytes());
                    out.extend_from_slice(b"\ndata: ");
                    out.extend_from_slice(&serialize(&payload)?);
                    out.extend_from_slice(b"\n\n");
                }
            }
            return put(ctx, &out);
        }

        let value: serde_json::Value =
            sonic_rs::from_slice(bytes).map_err(|_| Encode::Unrepresentable)?;
        if source == ingress.name {
            // Same dialect: the upstream's own bytes are already what the client reads.
            return put(ctx, bytes);
        }
        let response = source_protocol
            .reader()
            .read_response(&value)
            .map_err(|_| Encode::Unrepresentable)?;
        let mut written = ingress_protocol.writer().write_response(&response);
        ingress_protocol
            .writer()
            .inject_response_metrics(&mut written, None);
        put(ctx, &serialize(&written)?)
    }

    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let ingress = ingress_dialect(ctx).ok_or(Encode::Unrepresentable)?;
        let protocol =
            busbar_llm::proto_codec::protocol_for(ingress.name).ok_or(Encode::Unrepresentable)?;
        let (status, kind) = refusal_shape(refusal.reason);
        let envelope = protocol
            .writer()
            .write_error(status, kind, refusal_message(refusal.reason));
        put(ctx, &serialize(&envelope)?)
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        // A completed request has already had its whole answer written; there is no separate
        // ending to send. A failure mid-answer is the one case with an ending to write, and the
        // dialect's own error frame is what a client of that dialect knows how to read.
        let UnitEnd::Failed { .. } = end else {
            return Ok(None);
        };
        let ingress = ingress_dialect(ctx).ok_or(Encode::Unrepresentable)?;
        let protocol =
            busbar_llm::proto_codec::protocol_for(ingress.name).ok_or(Encode::Unrepresentable)?;
        let envelope = protocol.writer().write_error(
            500,
            KIND_API_ERROR,
            "The request could not be completed.",
        );
        Ok(Some(put(ctx, &serialize(&envelope)?)?))
    }

    fn authenticate<'u>(&self, _u: &Unit<'u>, ctx: &Ctx<'u>) -> CredentialLocator {
        CredentialLocator {
            narrowing: ingress_dialect(ctx).map(|d| SchemeAlt::new(d.scheme_alt)),
            // Every one of the six dialects presents its credential on the request itself. None of
            // them authenticates once and rides a session.
            from_session: false,
        }
    }

    fn verify<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        match self.first_upstream() {
            Some(u) => DestinationFacts::Upstream {
                transport: crate::claims::TRANSPORT,
                host: u.host,
                lane: u.lane,
            },
            // Nothing is configured, so there is nowhere to go. Naming a kernel verb that does not
            // exist is refused at the verify step, which is the right ending: the alternative would
            // be inventing a host.
            None => DestinationFacts::KernelVerb {
                verb: "unconfigured",
            },
        }
    }

    fn approve<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        let mut facts = ScopeFacts::default();
        let _ = facts.resources.push(ResourceLocator {
            kind: "operation",
            name: u.op().as_str(),
        });
        facts
    }

    fn admit<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> AdmitFacts {
        let Some(d) = ingress_dialect(ctx) else {
            return AdmitFacts::default();
        };
        let body = u.body().body();
        // Which bytes are the priced input: the conversation the client sent, not the controls
        // around it. A dialect whose container the scanner does not reach prices the whole body,
        // which is the conservative reading.
        let input_span = crate::spans::resolve(body, &[d.input_pointer])
            .first()
            .map(|(_, s)| *s)
            .unwrap_or(Span {
                start: 0,
                end: body.len(),
            });
        AdmitFacts {
            lane_locator: Some(Location::Arrival(ArrivalLocation::FirstFrameJsonPointer(
                d.model_pointer,
            ))),
            max_response_ptr: Some(Location::Arrival(ArrivalLocation::FirstFrameJsonPointer(
                d.max_response_pointer,
            ))),
            input_span: Some(input_span),
        }
    }

    fn route<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> RoutePlan {
        let mut plan = RoutePlan::default();
        let _ = plan.legs.push(Leg {
            destination: self.verify(u, ctx),
        });
        plan
    }

    fn meter<'u>(&self, _u: &Unit<'u>, r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        let mut locators = UsageLocators::default();
        let Some(source) = (match r.facts.get(meta::FACT_SOURCE_DIALECT) {
            Some(FactValue::Str(name)) => dialect::dialect(name),
            _ => None,
        }) else {
            return locators;
        };
        let Some(protocol) = busbar_llm::proto_codec::protocol_for(source.name) else {
            return locators;
        };
        let Ok(value) = sonic_rs::from_slice::<serde_json::Value>(r.ir.body()) else {
            return locators;
        };
        let Ok(response) = protocol.reader().read_response(&value) else {
            return locators;
        };
        // The quantities come back already normalized: a dialect that reports its cached count
        // INSIDE its input total has had it subtracted by its own reader, and a dialect whose cache
        // counts are already separate is left alone. So the four lines below partition the input
        // once, whichever dialect answered — and the plane does no arithmetic to make that true.
        let usage = &response.usage;
        let mut line = |class: &'static str, ptr: Option<&'static str>, quantity: Option<u64>| {
            if let Some(quantity) = quantity {
                let _ = locators.lines.push(UsageLocator {
                    class: MeterClassId::new(class),
                    location: ptr
                        .map(|p| Location::Arrival(ArrivalLocation::FirstFrameJsonPointer(p))),
                    quantity: Some(quantity),
                    lane: None,
                });
            }
        };
        line(
            "tokens_in",
            Some(source.tokens_in_pointer),
            Some(usage.input_tokens),
        );
        line(
            "tokens_out",
            Some(source.tokens_out_pointer),
            Some(usage.output_tokens),
        );
        line(
            "cache_read",
            source.cache_read_pointer,
            usage.cache_read_input_tokens,
        );
        line(
            "cache_write",
            source.cache_write_pointer,
            usage.cache_creation_input_tokens,
        );
        locators
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        AuditFacts {
            // The class the draft declared is the class that priced the unit, so it is the class
            // the audit step reports. Reporting a different one here would be a dispute, and a
            // dispute over a class this plane never re-derives would be a fabricated one.
            op_class: u.op(),
            finish: match out {
                UnitEnd::Completed => FinishClass::Complete,
                UnitEnd::Refused(_) | UnitEnd::Failed { .. } => FinishClass::Error,
                UnitEnd::Aborted(_) | UnitEnd::Stalled => FinishClass::Partial,
            },
        }
    }

    fn plane_facts<'u>(&self, verb: AdminVerbId, ctx: &Ctx<'u>) -> Result<PlaneFacts<'u>, Decode> {
        let mut facts = Facts::new();
        if verb == meta::VERB_DIALECTS {
            for d in dialect::DIALECTS {
                let _ = facts.set(d.name, FactValue::Str(d.name));
            }
            return Ok(PlaneFacts { facts });
        }
        if verb == meta::VERB_LADDER {
            for entry in crate::claims::LADDER {
                if let Some(key) = put_str(ctx, &format!("rung.{}", entry.rung)) {
                    let _ = facts.set(key, FactValue::Str(entry.dialect));
                }
            }
            return Ok(PlaneFacts { facts });
        }
        Err(Decode::UnsupportedOperation)
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        r: &Response<'u>,
        ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        let mut facts = Facts::new();
        let source = match r.facts.get(meta::FACT_SOURCE_DIALECT) {
            Some(FactValue::Str(name)) => name,
            _ => return ContentFacts { facts },
        };
        let Some(protocol) = busbar_llm::proto_codec::protocol_for(source) else {
            return ContentFacts { facts };
        };
        let Ok(value) = sonic_rs::from_slice::<serde_json::Value>(r.ir.body()) else {
            return ContentFacts { facts };
        };
        let Ok(response) = protocol.reader().read_response(&value) else {
            return ContentFacts { facts };
        };
        response_facts(ctx, &response, &mut facts);
        ContentFacts { facts }
    }
}

/// The operator's configured default response ceiling, or the design's own fallback.
fn configured_max_response(ctx: &Ctx<'_>) -> u32 {
    ctx.config()
        .get_int(CONFIG_MAX_RESPONSE)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(DEFAULT_MAX_RESPONSE)
}

/// What an answer was, for the record and the export path.
///
/// What is here is what the export sinks already receive: which model answered, how it stopped, how
/// many tool calls it asked for, and the upstream's own identifier for it. Not the content.
fn response_facts<'u>(ctx: &Ctx<'u>, response: &IrResponse, facts: &mut Facts<'u>) {
    if let Some(model) = response.model.as_deref().and_then(|m| put_str(ctx, m)) {
        let _ = facts.set(meta::FACT_RESPONSE_MODEL, FactValue::Str(model));
    }
    if let Some(id) = response.id.as_deref().and_then(|i| put_str(ctx, i)) {
        let _ = facts.set(meta::FACT_RESPONSE_ID, FactValue::Str(id));
    }
    if let Some(stop) = response.stop_reason {
        let _ = facts.set(meta::FACT_FINISH_REASON, FactValue::Str(stop_name(stop)));
    }
    let tool_calls = response
        .content
        .iter()
        .filter(|b| matches!(b, busbar_llm::ir::IrBlock::ToolUse { .. }))
        .count();
    let _ = facts.set(
        meta::FACT_TOOL_CALLS,
        FactValue::Int(i64::try_from(tool_calls).unwrap_or(i64::MAX)),
    );
}

/// The name a stop reason is recorded under.
///
/// A closed set of this plane's own words, never the upstream's token: an upstream token echoed
/// into a record is a foreign value in a field the record's readers believe is closed.
fn stop_name(stop: IrStopReason) -> &'static str {
    match stop {
        IrStopReason::EndTurn => "end_turn",
        IrStopReason::StopSequence => "stop_sequence",
        IrStopReason::MaxTokens => "max_tokens",
        IrStopReason::ToolUse => "tool_use",
        IrStopReason::Safety => "safety",
        IrStopReason::Refusal => "refusal",
        IrStopReason::PauseTurn => "pause_turn",
        IrStopReason::Error => "error",
        IrStopReason::Other => "other",
    }
}
