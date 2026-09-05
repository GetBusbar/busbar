//! The `Plane`/`SessionPlane` implementation.
//!
//! Every method here is a thin adapter over `busbar_voice::ir`'s shared duplex codec
//! ([`OpenAiRealtimeCodec`], [`GeminiLiveCodec`]), this crate's own Twilio reader/writer
//! ([`crate::twilio`]) and its own µ-law transform ([`crate::ulaw`]). None of the three inputs the
//! design brief names is skipped: a turn is the unit (opened on the first audio frame of a session,
//! closed on the upstream's `response.done` usage report or an upstream error); a provider tool call
//! decodes to `Progress::OneShot`; the interrupt fact and the pacing fact are both written where the
//! crate doc comment on [`crate::meta`] says they are.
//!
//! # Assumptions and simplifications, stated once
//!
//! - **HTTP/WS path arrives as a transport fact.** The same assumption `busbar-plane-admin` states
//!   for the same reason: nothing in `busbar-contract` pins the `http`/`ws` transports' fact key
//!   names, so `FACT_PATH` is this crate's own guess (`"path"`), used to resolve which one-shot
//!   operation or which duplex dialect a session's Unit 0 is.
//! - **Only the first decoded IR event per wire frame is acted on.** Both `read_up`/`read_down`
//!   return `Vec<..Event>` (one wire message can map to 0..n IR events); this plane surfaces the
//!   first and drops the rest. A wire frame that genuinely carries more than one IR event (not
//!   observed in the reference dialects' own reader, which emit at most one per frame today) would
//!   lose the extras. Flagged rather than silently accepted.
//! - **The uplink audio format is assumed PCM16 for the `audio_seconds_in` estimate on the two WS
//!   dialects.** `DecodeState` only tracks the NEGOTIATED OUTPUT format (for the downlink barge-in
//!   truncate math); there is no equivalent uplink format tracked anywhere in this plane's closure,
//!   so the ms-estimate this plane derives for its own `audio_ms_in` counter assumes the Realtime
//!   default. Twilio's own uplink is unambiguous (G.711 µ-law, priced from the raw payload before this
//!   plane's `encode_ingress_frame` transforms it), so this assumption is scoped to the two WS
//!   dialects only.
//! - **A provider tool call's `CallArgs`/`CallClose` frames relay under the still-open duplex turn**,
//!   not under the `tool_call` `OneShot` unit `CallOpen` mints. Modelling a tool call as its own
//!   fully-correlated open unit across a streamed argument delta would need a second correlation
//!   table this plane does not build in this pass; `CallOpen` mints the `OneShot` (so a tool call is
//!   visible, priced and audited as its own unit at its `tool_call` operation class) and increments
//!   [`crate::session::TurnCounters::tool_calls`], and the delta/close frames that follow are folded
//!   into the turn's own frame stream. Stated as a finding, not hidden.
//! - **`encode_response` is a passthrough of bytes `decode_response` already rendered**, mirroring
//!   `busbar-plane-admin`'s pattern. `decode_response` reads the open turn's own client dialect off
//!   `Ctx::session()`'s declared `dialect` session fact (the one fact this plane's `SESSION_FACTS`
//!   declares) and renders the client-shaped bytes immediately. The downlink half of
//!   [`crate::session::Pending`] is gone with the reason it existed: a step after decode can now
//!   read what decode determined off the unit's own draft facts.
//! - **Verify's upstream pick for a fresh session is a documented default, not a policy.** A session
//!   whose own arriving dialect is one of the two duplex-upstream dialects dials the SAME dialect's
//!   configured upstream when one exists; otherwise (Twilio, or no matching upstream configured) it
//!   dials this plane's FIRST configured upstream. Picking among several qualifying upstreams is the
//!   trust unit's and the ranking hooks' business in every other plane in this workspace; this default
//!   exists only so a unit test has something deterministic to assert against.
//! - **A provider tool call's destination is `Client(AwaitReply)`.** The design names two permitted
//!   shapes (`Client(AwaitReply)` or `NestedPlane(mcp)`); wiring the second requires the `mcp` plane's
//!   own operation classes, which are outside this crate's dependency graph. `Client(AwaitReply)` is
//!   implemented; a future pass that wants server-side tool EXECUTION (rather than delivering the call
//!   to whatever session member answers it) is the one that should add the `NestedPlane` path.

use busbar_contract::bounded::{ArenaBytes, FactValue, Facts, Ir};
use busbar_contract::dest::{
    ClientMode, DestinationFacts, EgressBody, RoutePlan, VerifiedDestination,
};
use busbar_contract::ids::{
    AdminVerbId, CorrelationRef, CorrelationValue, MeterClassId, OpClassId, SchemeKey,
};
use busbar_contract::kinds::{ContentFacts, CredentialLocator, PlaneFacts};
use busbar_contract::plane::{
    Ingress, Plane, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, ResourceLocator, ScopeFacts, Unit, UnitEnd,
    UsageLocator, UsageLocators,
};
use busbar_contract::wire::{Decode, DiscardCode, Encode, Frame, FrameCursor, TransportEnvelope};

use busbar_voice::ir::control::IrDuplexControl;
use busbar_voice::ir::event::{IrClientEvent, IrServerEvent};
use busbar_voice::ir::media::{AudioFormat, IrAudioFrame, UpDown};
use busbar_voice::ir::tool::IrDuplexTool;
use busbar_voice::ir::{
    DuplexReader, DuplexWriter, GeminiLiveCodec, OpenAiRealtimeCodec, WireEvent,
};

use crate::claims::{self, Dialect};
use crate::meta;
use crate::session::{Pending, VoiceSessionState};
use crate::{twilio, ulaw, VoicePlane};

/// The transport fact key this plane assumes `http`/`ws` carry the request path under.
///
/// See the module doc comment's first assumption.
const FACT_PATH: &str = "path";

/// The fact key a tool call's provider-origin `OneShot` correlates on.
const FACT_TOOL_CORRELATION: &str = "call_id";

/// Both duplex dialects' reader, boxed so the same call site works for either without a generic
/// parameter leaking into every method signature. Cheap: both codecs are zero-sized.
fn reader_for(dialect: Dialect) -> Box<dyn DuplexReader> {
    match dialect {
        Dialect::GeminiLive => Box::new(GeminiLiveCodec),
        _ => Box::new(OpenAiRealtimeCodec),
    }
}

/// See [`reader_for`].
fn writer_for(dialect: Dialect) -> Box<dyn DuplexWriter> {
    match dialect {
        Dialect::GeminiLive => Box::new(GeminiLiveCodec),
        _ => Box::new(OpenAiRealtimeCodec),
    }
}

impl VoicePlane {
    /// The upstream a fresh session's Unit 0 dials, given the dialect it arrived on. See the module
    /// doc comment's "verify's upstream pick" note.
    fn default_upstream(&self, arriving: Dialect) -> Option<&'static crate::Upstream> {
        if arriving.is_duplex_upstream() {
            if let Some(u) = self.upstream_for_dialect(arriving) {
                return Some(u);
            }
        }
        self.upstreams().first()
    }
}

impl Plane for VoicePlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        // Dispatch on the SESSION's own bound dialect, not the literal transport key: a claim's
        // selector (`claims::dialect_for`) is what names the dialect, and more than one dialect can
        // share a transport key in principle (the two WS dialects already do). A one-shot HTTP
        // operation carries no session state at all, which is how the two shapes are told apart here.
        match st {
            None => decode_one_shot(frames, ctx),
            Some(halfbox) => {
                let state = halfbox
                    .get_mut::<VoiceSessionState>()
                    .ok_or(Decode::MissingDeclaredFact)?;
                let dialect = state.dialect.ok_or(Decode::MissingDeclaredFact)?;
                match dialect {
                    Dialect::TwilioMediaStreams => decode_twilio_frame(frames, state, ctx),
                    Dialect::OpenaiRealtime | Dialect::GeminiLive => {
                        decode_ws_frame(frames, state, dialect, ctx)
                    }
                    Dialect::OneShotTranscribe | Dialect::OneShotTts => {
                        Err(Decode::UnsupportedOperation)
                    }
                }
            }
        }
    }

    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        // Unit 0 of a session: the first frame IS the egress body (the session-shapes section of
        // the architecture doc — "Unit 0's EgressBody is the first upstream frame"). Every later frame of the same turn travels through
        // `encode_ingress_frame` instead. `u.body()` already carries this plane's own rendering of
        // the client's first event (built in `decode_ingress`/`decode_one_shot`), so egress here is
        // the pass-through of those bytes into the arena the destination's own encoder expects.
        let _ = dest;
        let body = ctx
            .arena()
            .alloc_bytes(u.body().body())
            .map_err(|_| Encode::ArenaExhausted)?;
        Ok(EgressBody {
            envelope: TransportEnvelope::default(),
            body,
            auth: SchemeKey::new(claims::SCHEME),
        })
    }

    fn encode_ingress_frame<'u>(
        &self,
        _u: &Unit<'u>,
        f: &Frame,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        let state = st
            .ok_or(Encode::Poisoned)?
            .get_mut::<VoiceSessionState>()
            .ok_or(Encode::Poisoned)?;
        let client_dialect = state.dialect.ok_or(Encode::Poisoned)?;
        let upstream_dialect = upstream_dialect_for(self, dest);

        let client_event = match client_dialect {
            Dialect::TwilioMediaStreams => {
                // The documented seam: the µ-law -> PCM16 transform happens HERE, never at decode.
                let event =
                    twilio::decode(f.bytes.as_slice()).map_err(|_| Encode::Unrepresentable)?;
                match event {
                    twilio::TwilioEvent::Media { payload, .. } => {
                        let pcm = ulaw::decode_frame(&payload);
                        IrClientEvent::AudioFrame(IrAudioFrame {
                            dir: UpDown::Up,
                            seq: state.codec.next_up_seq(),
                            media: bytes::Bytes::from(pcm),
                        })
                    }
                    // Lifecycle events (`connected`/`start`/`mark`/`stop`) carry no audio and are
                    // fully handled at decode; nothing is relayed onward for them.
                    _ => return Ok(None),
                }
            }
            _ => match state.pending.take() {
                Some(Pending::Ingress(ev)) => ev,
                // `NeedMore`/non-audio control answered fully at decode: nothing further to relay.
                _ => return Ok(None),
            },
        };

        let writer = writer_for(upstream_dialect);
        let out = writer.write_up(client_event);
        ctx.arena()
            .alloc_bytes(&out.0)
            .map(Some)
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        let state = st
            .ok_or(Decode::MissingDeclaredFact)?
            .get_mut::<VoiceSessionState>()
            .ok_or(Decode::MissingDeclaredFact)?;
        let upstream_dialect = upstream_dialect_for(self, dest);
        let client_dialect = client_dialect_from_session(ctx).unwrap_or(upstream_dialect);

        let frame = frames.next_frame().ok_or(Decode::Malformed)?;
        let wire = WireEvent(bytes::Bytes::copy_from_slice(frame.bytes.as_slice()));
        let reader = reader_for(upstream_dialect);
        let events = reader.read_down(wire, &mut state.codec);
        let Some(event) = events.into_iter().next() else {
            return Ok(Progress::Discard {
                reason: DiscardCode::Unsupported,
            });
        };

        progress_from_server_event(event, state, client_dialect, ctx)
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        // See the module doc comment's `encode_response` note: `decode_response` already rendered
        // client-dialect bytes into `r.ir`; this is the passthrough.
        ctx.arena()
            .alloc_bytes(r.ir.body())
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let event = IrServerEvent::Error {
            code: format!("{:?}", refusal.reason),
            message: "the session was refused".to_string(),
        };
        // A refusal is rendered in the OpenAI Realtime shape unconditionally: `st` is deliberately
        // `&PlaneSessionState` (immutable — a refusal never advances codec state, per the trait's own
        // doc comment), so this plane cannot read back which dialect a not-yet-open session even
        // claimed. `error` is one of the few wire shapes both duplex dialects converge on closely
        // enough that a client library for either can surface it; a fully dialect-correct refusal
        // would need the immutable half of the state to still carry the negotiated dialect, which it
        // does today (`VoiceSessionState::dialect`) but this method has no path to it before Unit 0
        // completes. Flagged rather than guessed past.
        let bytes = OpenAiRealtimeCodec.write_down(event).0;
        ctx.arena()
            .alloc_bytes(&bytes)
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        // A turn's own ending is always rendered as a `Progress::Terminal` `Response` through
        // `encode_response` (the upstream's `response.done`/error IS the ending); there is no further
        // trailer this dialect writes at the unit's own close.
        Ok(None)
    }

    fn authenticate<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> CredentialLocator {
        // Twilio, OpenAI Realtime and Gemini Live all authenticate once at session open and cache
        // the result for the session's life (`claims::Dialect::authenticates_from_session`); the two
        // one-shot HTTP operations present a credential on the one request they are. The dialect is
        // the draft's own fact, sealed onto the unit by the kernel, so this step reads what decode
        // determined rather than a session fact that a one-shot unit does not have at all.
        CredentialLocator {
            narrowing: None,
            from_session: draft_dialect(u).is_some_and(Dialect::authenticates_from_session),
        }
    }

    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> DestinationFacts {
        if u.op().as_str() == "tool_call" {
            return DestinationFacts::Client {
                selector: "*",
                mode: ClientMode::AwaitReply {
                    correlation: CorrelationRef {
                        fact_key: FACT_TOOL_CORRELATION,
                        value: CorrelationValue::Num(0),
                    },
                    deadline_secs: 30,
                },
            };
        }
        let session_upstream_count = ctx.session().map(|s| s.upstream_count()).unwrap_or(0);
        if session_upstream_count > 0 {
            return DestinationFacts::SessionUpstream {
                upstream: busbar_contract::ids::UpstreamIdx(0),
                stream: None,
                lane: self
                    .upstreams()
                    .first()
                    .map(|up| up.lane)
                    .unwrap_or(busbar_contract::ids::LaneId::new("voice")),
            };
        }
        // The dialect the decode step named, off the unit's own sealed draft facts.
        let arriving = draft_dialect(u).unwrap_or(Dialect::OpenaiRealtime);
        match self.default_upstream(arriving) {
            Some(up) => DestinationFacts::Upstream {
                transport: claims::WS_TRANSPORT,
                address: busbar_contract::UpstreamAddress::socket(up.host),
                lane: up.lane,
            },
            None => DestinationFacts::Upstream {
                transport: claims::WS_TRANSPORT,
                address: busbar_contract::UpstreamAddress::socket(""),
                lane: busbar_contract::ids::LaneId::new("voice"),
            },
        }
    }

    fn approve<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        let mut resources = busbar_contract::bounded::BoundedVec::new();
        let _ = resources.push(ResourceLocator {
            kind: "voice_operation",
            name: u.op().as_str(),
        });
        ScopeFacts { resources }
    }

    fn admit<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        // No client-located lane name and no client response ceiling on a duplex session: the lane
        // is this plane's own configuration (`Upstream::lane`), and the response is unbounded audio,
        // not a single JSON body the kernel would clamp.
        AdmitFacts::default()
    }

    fn route<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> RoutePlan {
        // `verify` already named the one destination this unit reaches; there is no second leg.
        RoutePlan::default()
    }

    fn meter<'u>(&self, _u: &Unit<'u>, r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        let mut lines = busbar_contract::bounded::BoundedVec::new();
        let classes = [
            (meta::FACT_AUDIO_TOKENS_IN, "audio_tokens_in"),
            (meta::FACT_AUDIO_TOKENS_OUT, "audio_tokens_out"),
            (meta::FACT_TEXT_TOKENS, "text_tokens"),
            (meta::FACT_CACHED_TOKENS, "cached_tokens"),
        ];
        for (fact_key, class) in classes {
            if let Some(FactValue::Int(v)) = r.facts.get(fact_key) {
                let _ = lines.push(UsageLocator {
                    class: MeterClassId::new(class),
                    location: None,
                    quantity: u64::try_from(v).ok(),
                    lane: None,
                });
            }
        }
        if let Some(FactValue::Int(ms)) = r.facts.get(meta::FACT_AUDIO_MS_IN) {
            let _ = lines.push(UsageLocator {
                class: MeterClassId::new("audio_seconds_in"),
                location: None,
                quantity: u64::try_from(ms).ok(),
                lane: None,
            });
        }
        if let Some(FactValue::Int(calls)) = r.facts.get(meta::FACT_TOOL_CALLS) {
            let _ = lines.push(UsageLocator {
                class: MeterClassId::new("tool_calls"),
                location: None,
                quantity: u64::try_from(calls).ok(),
                lane: None,
            });
        }
        UsageLocators { lines }
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        AuditFacts {
            op_class: u.op(),
            finish: match out {
                UnitEnd::Completed => FinishClass::TurnComplete,
                UnitEnd::Refused(_) | UnitEnd::Failed { .. } => FinishClass::Error,
                UnitEnd::Aborted(_) | UnitEnd::Stalled => FinishClass::Partial,
            },
        }
    }

    fn plane_facts<'u>(
        &self,
        verb: AdminVerbId,
        _subject: Option<&'u str>,
        ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        if verb != meta::VERB_DIALECTS {
            return Err(Decode::UnsupportedOperation);
        }
        let mut facts = Facts::new();
        let count = ctx
            .arena()
            .alloc_str(&claims::DIALECT_CLAIMS.len().to_string())
            .map_err(|_| Decode::Oversize)?;
        facts
            .set("dialect_count", FactValue::Str(count))
            .map_err(|_| Decode::Oversize)?;
        Ok(PlaneFacts { facts })
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        let mut facts = Facts::new();
        for key in <VoicePlane as busbar_contract::plane::PlaneMeta>::CONTENT_FACTS {
            if let Some(v) = r.facts.get(key) {
                let _ = facts.set(key, v);
            }
        }
        ContentFacts { facts }
    }
}

impl SessionPlane for VoicePlane {
    fn open_session<'u>(&self, ctx: &Ctx<'u>) -> PlaneSessionState {
        let dialect = ctx
            .transport()
            .fact(FACT_PATH)
            .and_then(claims::dialect_for)
            .unwrap_or(Dialect::OpenaiRealtime);
        PlaneSessionState::new(VoiceSessionState::for_dialect(dialect))
    }

    fn open_upstream<'u>(&self, dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        let dialect = upstream_dialect_for(self, dest);
        PlaneSessionState::new(VoiceSessionState::for_dialect(dialect))
    }
}

/// Which dialect the upstream a verified destination names speaks, by matching its host against
/// this plane's configured upstream list. Falls back to OpenAI Realtime (the more common of the two
/// and this plane's documented default elsewhere) when the destination is a `SessionUpstream` this
/// function cannot resolve a host for, or names no configured upstream at all.
fn upstream_dialect_for(plane: &VoicePlane, dest: &VerifiedDestination) -> Dialect {
    match dest.facts() {
        DestinationFacts::Upstream { address, .. } => plane
            .upstreams()
            .iter()
            .find(|u| Some(u.host) == address.authority())
            .map(|u| u.dialect)
            .unwrap_or(Dialect::OpenaiRealtime),
        _ => plane
            .upstreams()
            .first()
            .map(|u| u.dialect)
            .unwrap_or(Dialect::OpenaiRealtime),
    }
}

/// The dialect the decode step named, read back off the unit's sealed draft facts.
///
/// The one place this plane's later steps ask what dialect a unit is: decode is the step that read
/// the bytes and matched the claim, and what it determined travels on the unit. A one-shot unit has
/// no session at all, so a session fact could not have answered for it.
fn draft_dialect(u: &Unit<'_>) -> Option<Dialect> {
    match u.draft_facts().get(meta::FACT_DIALECT) {
        Some(FactValue::Str(name)) => dialect_from_name(name),
        _ => None,
    }
}

/// The client's own dialect, read back off the session fact this plane declared (`SESSION_FACTS`).
fn client_dialect_from_session<'u>(ctx: &Ctx<'u>) -> Option<Dialect> {
    ctx.session()
        .and_then(|s| s.session_fact(meta::FACT_DIALECT))
        .and_then(dialect_from_name)
}

/// The inverse of [`Dialect::name`].
fn dialect_from_name(name: &str) -> Option<Dialect> {
    match name {
        "openai-realtime" => Some(Dialect::OpenaiRealtime),
        "gemini-live" => Some(Dialect::GeminiLive),
        "twilio-media-streams" => Some(Dialect::TwilioMediaStreams),
        "transcribe" => Some(Dialect::OneShotTranscribe),
        "tts" => Some(Dialect::OneShotTts),
        _ => None,
    }
}

/// Decode a one-shot (`http`) transcribe/tts request: no session, a single `OneShot` unit.
fn decode_one_shot<'u>(frames: &mut FrameCursor<'u>, ctx: &Ctx<'u>) -> Result<Ingress<'u>, Decode> {
    let path = ctx
        .transport()
        .fact(FACT_PATH)
        .ok_or(Decode::MissingDeclaredFact)?;
    let dialect = claims::dialect_for(path).ok_or(Decode::UnsupportedOperation)?;
    let op = match dialect {
        Dialect::OneShotTranscribe => OpClassId::new("transcribe"),
        Dialect::OneShotTts => OpClassId::new("tts"),
        _ => return Err(Decode::UnsupportedOperation),
    };
    let frame = frames.next_frame();
    let body: &'u [u8] = frame.map(|f| f.bytes.as_slice()).unwrap_or(&[]);
    let mut facts = Facts::new();
    facts
        .set(meta::FACT_DIALECT, FactValue::Str(dialect.name()))
        .map_err(|_| Decode::Oversize)?;
    Ok(Ingress::OneShot(UnitDraft {
        op,
        body_ir: Ir::new(body, &[]),
        correlates: None,
        correlation_out: None,
        facts,
    }))
}

/// Decode one frame of a duplex session bound to one of the two WS dialects (OpenAI Realtime or
/// Gemini Live).
fn decode_ws_frame<'u>(
    frames: &mut FrameCursor<'u>,
    state: &mut VoiceSessionState,
    dialect: Dialect,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    let frame = frames.next_frame().ok_or(Decode::Malformed)?;
    let wire = WireEvent(bytes::Bytes::copy_from_slice(frame.bytes.as_slice()));
    let reader = reader_for(dialect);
    let events = reader.read_up(wire, &mut state.codec);
    let Some(event) = events.into_iter().next() else {
        return Ok(Ingress::NeedMore);
    };
    // Stashed so `encode_ingress_frame` never calls the stateful reader a second time for the same
    // wire frame (see `crate::session::Pending`'s doc comment).
    state.pending = Some(Pending::Ingress(event.clone()));
    ingress_from_client_event(event, state, dialect, ctx)
}

/// Decode one frame of a `twilio-media`-carried session.
fn decode_twilio_frame<'u>(
    frames: &mut FrameCursor<'u>,
    state: &mut VoiceSessionState,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    let frame = frames.next_frame().ok_or(Decode::Malformed)?;
    let event = twilio::decode(frame.bytes.as_slice()).map_err(|_| Decode::Malformed)?;
    match event {
        // Lifecycle events with no audio and nothing left to bind: consumed, no unit, no state
        // change beyond what `Start` below records.
        twilio::TwilioEvent::Connected => Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported,
        }),
        twilio::TwilioEvent::Start { stream_sid, .. } => {
            state.twilio_stream_sid = Some(stream_sid);
            state.dialect = Some(Dialect::TwilioMediaStreams);
            Ok(Ingress::Discard {
                reason: DiscardCode::Unsupported,
            })
        }
        twilio::TwilioEvent::Media {
            stream_sid,
            payload,
        } => {
            // The forgery/replay guard the architecture note for this dialect names: a `media`
            // frame naming a `streamSid` other than the one `start` bound is discarded, not
            // refused — it costs nothing and ends no unit, exactly what a discard is for.
            if state.twilio_stream_sid.as_deref() != Some(stream_sid.as_str()) {
                return Ok(Ingress::Discard {
                    reason: DiscardCode::ForgedSource,
                });
            }
            let ms = AudioFormat::G711Ulaw.bytes_to_ms(payload.len() as u64);
            state.turn.audio_ms_in = state.turn.audio_ms_in.saturating_add(ms);
            let arena_bytes = ctx
                .arena()
                .alloc_bytes(&payload)
                .map_err(|_| Decode::Oversize)?;
            Ok(open_or_relay(
                state,
                Dialect::TwilioMediaStreams,
                arena_bytes,
                None,
            ))
        }
        twilio::TwilioEvent::Mark { .. } => Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported,
        }),
        twilio::TwilioEvent::Stop => {
            let for_ = state.turn_correlation;
            let _ = state.close_turn();
            Ok(Ingress::Close {
                for_,
                facts: Facts::new(),
            })
        }
    }
}

/// Turn one decoded client→server IR event into an `Ingress` answer, for the two WS dialects.
///
/// Any client event — audio, control or a tool result — opens the turn if none is open yet: a
/// session's very first frame is not always audio (`session.update` routinely arrives first), and
/// there is no reason to wait for audio specifically before a unit exists to hold the session's
/// facts and price its hold.
fn ingress_from_client_event<'u>(
    event: IrClientEvent,
    state: &mut VoiceSessionState,
    dialect: Dialect,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    let (relay, interrupt_ms) = match &event {
        IrClientEvent::AudioFrame(f) => {
            // See the module doc comment: the uplink format is assumed PCM16 for this estimate.
            let ms = AudioFormat::Pcm16.bytes_to_ms(f.media.len() as u64);
            state.turn.audio_ms_in = state.turn.audio_ms_in.saturating_add(ms);
            let bytes = ctx
                .arena()
                .alloc_bytes(&f.media)
                .map_err(|_| Decode::Oversize)?;
            (bytes, None)
        }
        IrClientEvent::Control(IrDuplexControl::ItemTruncate {
            audio_played_ms, ..
        }) => (ArenaBytes::new(&[]), Some(*audio_played_ms)),
        IrClientEvent::Control(_) | IrClientEvent::Tool(_) => (ArenaBytes::new(&[]), None),
    };
    Ok(open_or_relay(state, dialect, relay, interrupt_ms))
}

/// Open a fresh turn (this is its first frame) or relay onto the one already open, attaching the
/// interrupt fact where the caller says the event carried one, either way.
fn open_or_relay<'u>(
    state: &mut VoiceSessionState,
    dialect: Dialect,
    relay: ArenaBytes<'u>,
    interrupt_ms: Option<u64>,
) -> Ingress<'u> {
    let mut facts = Facts::new();
    if let Some(ms) = interrupt_ms {
        let _ = facts.set(
            meta::FACT_INTERRUPT_AUDIO_PLAYED_MS,
            FactValue::Int(i64::try_from(ms).unwrap_or(i64::MAX)),
        );
    }
    if !state.turn_open {
        let correlation = state.open_turn();
        let _ = facts.set(meta::FACT_DIALECT, FactValue::Str(dialect.name()));
        let ir = Ir::new(relay.as_slice(), &[]);
        Ingress::Open(UnitDraft {
            op: OpClassId::new("duplex_turn"),
            body_ir: ir,
            correlates: None,
            correlation_out: Some(correlation),
            facts,
        })
    } else {
        Ingress::Frame {
            for_: state.turn_correlation,
            relay,
            facts,
        }
    }
}

/// Turn one decoded server→client IR event into a `Progress` answer, rendering the client-shaped
/// bytes immediately (see the module doc comment's `encode_response` note).
fn progress_from_server_event<'u>(
    event: IrServerEvent,
    state: &mut VoiceSessionState,
    client_dialect: Dialect,
    ctx: &Ctx<'u>,
) -> Result<Progress<'u>, Decode> {
    let for_ = state.turn_correlation;
    match event {
        IrServerEvent::SessionCreated { .. } | IrServerEvent::RateLimits => Ok(Progress::Discard {
            reason: DiscardCode::Unsupported,
        }),
        IrServerEvent::Tool(IrDuplexTool::CallOpen { call_id, name, .. }) => {
            state.turn.tool_calls = state.turn.tool_calls.saturating_add(1);
            let mut facts = Facts::new();
            let name_arena = ctx.arena().alloc_str(&name).map_err(|_| Decode::Oversize)?;
            let call_id_arena = ctx
                .arena()
                .alloc_str(&call_id)
                .map_err(|_| Decode::Oversize)?;
            facts
                .set(meta::FACT_TOOL_NAME, FactValue::Str(name_arena))
                .map_err(|_| Decode::Oversize)?;
            facts
                .set(meta::FACT_CALL_ID, FactValue::Str(call_id_arena))
                .map_err(|_| Decode::Oversize)?;
            Ok(Progress::OneShot(UnitDraft {
                op: OpClassId::new("tool_call"),
                body_ir: Ir::new(&[], &[]),
                correlates: None,
                // The call identifier travels as itself. It is a string on the wire and it is a
                // string here, allocated in the unit's own arena — a fold into sixty four bits
                // would be one collision away from answering a tool call with another's reply.
                correlation_out: Some(CorrelationRef {
                    fact_key: FACT_TOOL_CORRELATION,
                    value: CorrelationValue::Str(call_id_arena),
                }),
                facts,
            }))
        }
        IrServerEvent::Tool(_) => Ok(Progress::Frame {
            for_,
            r: Response {
                ir: Ir::new(&[], &[]),
                finish: FinishClass::Partial,
                facts: Facts::new(),
            },
        }),
        IrServerEvent::SpeechStarted { .. } => {
            let ms = state.codec.flush_playback();
            let mut facts = Facts::new();
            facts
                .set(
                    meta::FACT_INTERRUPT_AUDIO_PLAYED_MS,
                    FactValue::Int(i64::try_from(ms).unwrap_or(i64::MAX)),
                )
                .map_err(|_| Decode::Oversize)?;
            Ok(Progress::Frame {
                for_,
                r: Response {
                    ir: Ir::new(&[], &[]),
                    finish: FinishClass::Partial,
                    facts,
                },
            })
        }
        IrServerEvent::SpeechStopped { .. } | IrServerEvent::AudioDone { .. } => {
            Ok(Progress::Frame {
                for_,
                r: Response {
                    ir: Ir::new(&[], &[]),
                    finish: FinishClass::Partial,
                    facts: Facts::new(),
                },
            })
        }
        IrServerEvent::AudioFrame(f) => {
            let writer = writer_for(client_dialect);
            let media_len = f.media.len() as u64;
            let rendered = match client_dialect {
                Dialect::TwilioMediaStreams => {
                    let mulaw = ulaw::encode_frame(&f.media);
                    let sid = state.twilio_stream_sid.clone().unwrap_or_default();
                    twilio::encode_media(&sid, &mulaw)
                }
                _ => writer.write_down(IrServerEvent::AudioFrame(f)).0.to_vec(),
            };
            let bytes = ctx
                .arena()
                .alloc_bytes(&rendered)
                .map_err(|_| Decode::Oversize)?;
            let mut facts = Facts::new();
            facts
                .set(
                    meta::EGRESS_PACING_FACT_KEY,
                    FactValue::Int(i64::try_from(state.codec.played_ms()).unwrap_or(i64::MAX)),
                )
                .map_err(|_| Decode::Oversize)?;
            let _ = media_len;
            Ok(Progress::Frame {
                for_,
                r: Response {
                    ir: Ir::new(bytes.as_slice(), &[]),
                    finish: FinishClass::Partial,
                    facts,
                },
            })
        }
        IrServerEvent::Usage(usage) => {
            let counters = state.close_turn();
            let mut facts = Facts::new();
            let ints: [(&str, i64); 6] = [
                (
                    meta::FACT_AUDIO_TOKENS_IN,
                    i64::try_from(usage.audio_in).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_AUDIO_TOKENS_OUT,
                    i64::try_from(usage.audio_out).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_TEXT_TOKENS,
                    i64::try_from(usage.text_in.saturating_add(usage.text_out)).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_CACHED_TOKENS,
                    i64::try_from(usage.cached).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_AUDIO_MS_IN,
                    i64::try_from(counters.audio_ms_in).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_TOOL_CALLS,
                    i64::try_from(counters.tool_calls).unwrap_or(i64::MAX),
                ),
            ];
            for (k, v) in ints {
                facts
                    .set(k, FactValue::Int(v))
                    .map_err(|_| Decode::Oversize)?;
            }
            Ok(Progress::Terminal {
                for_,
                r: Response {
                    ir: Ir::new(&[], &[]),
                    finish: FinishClass::TurnComplete,
                    facts,
                },
            })
        }
        IrServerEvent::Error { code, message } => {
            let _ = state.close_turn();
            let mut facts = Facts::new();
            let code_arena = ctx.arena().alloc_str(&code).map_err(|_| Decode::Oversize)?;
            let message_arena = ctx
                .arena()
                .alloc_str(&message)
                .map_err(|_| Decode::Oversize)?;
            facts
                .set(meta::FACT_ERROR_CODE, FactValue::Str(code_arena))
                .map_err(|_| Decode::Oversize)?;
            facts
                .set(meta::FACT_ERROR_MESSAGE, FactValue::Str(message_arena))
                .map_err(|_| Decode::Oversize)?;
            Ok(Progress::Terminal {
                for_,
                r: Response {
                    ir: Ir::new(&[], &[]),
                    finish: FinishClass::Error,
                    facts,
                },
            })
        }
    }
}
