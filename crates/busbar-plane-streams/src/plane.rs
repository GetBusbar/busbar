//! The `Plane`/`SessionPlane` implementation.
//!
//! Every method here is a thin adapter over `busbar_voice_codec::ir`'s shared duplex codec
//! ([`OpenAiRealtimeCodec`], which is also the SHARED duplex IR every dialect that declares no
//! reader of its own rides), this crate's own Twilio reader/writer
//! ([`crate::twilio`]) and its own µ-law transform ([`crate::ulaw`]). None of the three inputs the
//! design brief names is skipped: a turn is the unit (opened on the first audio frame of a session,
//! closed on the upstream's `response.done` usage report or an upstream error); a provider tool call
//! decodes to `Progress::OneShot`; the interrupt fact and the pacing fact are both written where the
//! crate doc comment on [`crate::meta`] says they are.
//!
//! # Assumptions and simplifications, stated once
//!
//! Three of the entries below are no longer this module's own reading. They were raised as findings,
//! carried to the architecture's inventory row for this plane, and **ratified there** — so what
//! follows restates a decision rather than declaring one, and a change to any of the three is a
//! change to that row first and to this file second. They are: only the first decoded IR event per
//! wire frame is acted on; uplink audio is assumed PCM16 for the `audio_seconds_in` estimate on the
//! two WS dialects; and model-emitted text in a duplex turn prices under `text_tokens_out`, an
//! output class, never the input one.
//!
//! - **HTTP/WS path arrives as a transport fact**, under the kernel's own reserved key
//!   (`busbar_contract::transport::facts::PATH`), used to resolve which one-shot operation or which
//!   duplex dialect a session's Unit 0 is. This used to be a guess, and both transports now declare
//!   the key they publish it under.
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
    Ingress, Plane, PlaneSessionState, Progress, Response, SessionParams, SessionPlane, UnitDraft,
};
use busbar_contract::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, ResourceLocator, ScopeFacts, Unit, UnitEnd,
    UsageLocator, UsageLocators,
};
use busbar_contract::wire::{Decode, DiscardCode, Encode, Frame, FrameCursor, TransportEnvelope};

use busbar_voice_codec::ir::config;
use busbar_voice_codec::ir::control::IrDuplexControl;
use busbar_voice_codec::ir::event::{IrClientEvent, IrServerEvent};
use busbar_voice_codec::ir::media::AudioFormat;
use busbar_voice_codec::ir::tool::IrDuplexTool;
use busbar_voice_codec::ir::{
    DecodeState, DuplexReader, DuplexWriter, OpenAiRealtimeCodec, WireRef,
};

use crate::claims;
use crate::dialect::{self, Dialect};
use crate::meta;
use crate::session::{Pending, VoiceSessionState};
use crate::VoicePlane;

/// The transport fact key the request path is published under.
///
/// The kernel's own reserved key, named rather than assumed. It used to be this crate's guess, and
/// the module header said so; the header's first assumption is retired with it.
const FACT_PATH: &str = busbar_contract::transport::facts::PATH;

/// The fact key a tool call's provider-origin `OneShot` correlates on.
///
/// Public because it is half of a correlation and the other half is entered somewhere else: the leg
/// this plane plans names this key, and whatever holds the waiting table has to name the same one
/// for a reply to match. Two spellings of one key is exactly the drift that makes a wait unmatchable
/// while both sides look right on their own.
pub const FACT_TOOL_CORRELATION: &str = meta::FACT_CALL_ID;

/// How long a tool call's reply leg waits, in seconds.
///
/// Declared here, beside the leg that names it, so the table that has to end an unanswered call at
/// this deadline reads the plane's own figure rather than restating it.
pub const TOOL_REPLY_DEADLINE_SECS: u32 = 30;

/// A DIALECT'S READER, TAKEN OFF ITS OWN ROW — boxed so the same call site works for any dialect
/// without a generic parameter leaking into every method signature. Cheap: every codec is
/// zero-sized.
///
/// This used to be `if dialect.name == <one vendor> { that codec } else { the other }`, which is
/// instance dispatch with a string comparison in front of it, in the crate the dialect kind's
/// direction rule makes the NEUTRAL party. A row that declares no reader of its own
/// ([`Dialect::reader`] is `None`) is declaring that its frames ARE the shared duplex IR, and the
/// shared IR is what it gets — named here as the IR it is, which is the one thing this crate is
/// entitled to know about frames.
/// `None` for the dialect itself — a session whose dialect this node could not name — gets the
/// shared IR for the same reason a row that declared `None` does: the shared IR is the one frame
/// vocabulary this crate is entitled to know, and it is the honest answer when no plugin claimed
/// the frames.
pub(crate) fn reader_for(dialect: Option<&Dialect>) -> Box<dyn DuplexReader> {
    match dialect.and_then(|d| d.reader) {
        Some(f) => f(),
        None => Box::new(OpenAiRealtimeCodec),
    }
}

/// See [`reader_for`].
pub(crate) fn writer_for(dialect: Option<&Dialect>) -> Box<dyn DuplexWriter> {
    match dialect.and_then(|d| d.writer) {
        Some(f) => f(),
        None => Box::new(OpenAiRealtimeCodec),
    }
}

impl VoicePlane {
    /// The upstream a fresh session's Unit 0 dials, given the dialect it arrived on. See the module
    /// doc comment's "verify's upstream pick" note.
    fn default_upstream(&self, arriving: &Dialect) -> Option<&'static crate::Upstream> {
        if arriving.duplex_upstream {
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
                // ONE LOOKUP, NO BRANCH ON A NAME. A dialect that brings its own envelope reads its
                // own frames; one that does not rides the shared duplex codec. A claim that is not
                // a streaming dialect at all has no row and no envelope, and there is nothing here
                // for it to be read as.
                match dialect.envelope {
                    Some(envelope) => (envelope.decode_ingress)(frames, state, ctx),
                    None => decode_ws_frame(frames, state, dialect, ctx),
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
        // The client's own dialect off the session fact first, exactly as `decode_response` asks
        // it: this seam is scoped to the DESTINATION, so the half it is handed is not guaranteed
        // to be the one the client's arriving frames bound a dialect on.
        let client_dialect = client_dialect_from_session(ctx)
            .or(state.dialect)
            .ok_or(Encode::Poisoned)?;
        let upstream_dialect = upstream_dialect_for(self, dest);

        let client_event = match client_dialect.envelope {
            // A dialect with its own envelope relays its own frame, and takes its own uplink meter
            // while the payload is still in its own format.
            Some(envelope) => match (envelope.relay_ingress)(f.bytes.as_slice(), state)? {
                Some(event) => event,
                None => return Ok(None),
            },
            None => match state.pending.take() {
                Some(Pending::Ingress(ev)) => ev,
                // Nothing stashed. Either decode answered the frame fully (a control event with
                // nothing to relay) or the stash was left on another half of the session, which is
                // not a reason to drop a caller's audio on the floor: the frame is re-read here.
                // The reader is the one the stash existed to avoid calling twice, so it is called
                // once either way.
                None => {
                    let reader = reader_for(Some(client_dialect));
                    let events = reader.read_up_ref(WireRef(f.bytes.as_slice()), &mut state.codec);
                    match events.into_iter().next() {
                        Some(ev) => ev,
                        None => return Ok(None),
                    }
                }
            },
        };

        // The uplink meter is taken HERE, at the seam that relays the frame to the provider, and
        // not at decode: decode runs against the client half of the session and this step and the
        // response step run against the destination's, so a figure counted at decode was read back
        // from a half it was never written to and every second the caller spoke metered at zero.
        // Counting where the audio actually leaves also means audio this node never relayed is
        // audio nobody is charged for.
        // A dialect that declares `meters_own_uplink` counted its own carrier payload above,
        // before the transform; counting again here would double every second it admitted.
        if !client_dialect.meters_own_uplink {
            if let IrClientEvent::AudioFrame(f) = &client_event {
                // See the module doc comment: the uplink format is assumed PCM16 for this estimate.
                let ms = AudioFormat::Pcm16.bytes_to_ms(f.media.len() as u64);
                state.turn.audio_ms_in = state.turn.audio_ms_in.saturating_add(ms);
            }
        }

        let writer = writer_for(upstream_dialect);
        // The upstream dialect may have NO verb for this concept (the cross-dialect drop rows): then
        // nothing is relayed — the same answer a lifecycle frame handled fully at decode gives.
        let Some(out) = writer.write_up(client_event, &mut state.codec) else {
            return Ok(None);
        };
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
        // A one-shot operation has no session, by construction: `decode_one_shot` admitted it
        // without one and there is none to hand back here. Requiring one turned every transcribe
        // and every text-to-speech answer into a decode refusal, so the unit that WAS admitted
        // never saw its own answer and never metered anything at all.
        let Some(halfbox) = st else {
            return decode_one_shot_response(frames, ctx);
        };
        let state = halfbox
            .get_mut::<VoiceSessionState>()
            .ok_or(Decode::MissingDeclaredFact)?;
        let upstream_dialect = upstream_dialect_for(self, dest);
        let client_dialect = client_dialect_from_session(ctx).or(upstream_dialect);

        let frame = frames.next_frame().ok_or(Decode::Malformed)?;
        // The reader is handed the frame WHERE IT IS. It parses the bytes and keeps none of them, so
        // buying them a second home first bought nothing — and a duplex session reads fifty frames a
        // second in each direction for the length of a call.
        let reader = reader_for(upstream_dialect);
        let events = reader.read_down_ref(WireRef(frame.bytes.as_slice()), &mut state.codec);
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
        let (code, message) = refusal_render(refusal.reason);
        let event = IrServerEvent::Error {
            code: code.to_string(),
            message: message.to_string(),
        };
        // A refusal is rendered in the OpenAI Realtime shape unconditionally: `st` is deliberately
        // `&PlaneSessionState` (immutable — a refusal never advances codec state, per the trait's own
        // doc comment), so this plane cannot read back which dialect a not-yet-open session even
        // claimed. `error` is one of the few wire shapes both duplex dialects converge on closely
        // enough that a client library for either can surface it; a fully dialect-correct refusal
        // would need the immutable half of the state to still carry the negotiated dialect, which it
        // does today (`VoiceSessionState::dialect`) but this method has no path to it before Unit 0
        // completes. Flagged rather than guessed past.
        // The write seam threads the session's decode state (it holds what framing cannot answer
        // per-event); a refusal reaches none of the session's state here, and needs none — it is one
        // self-contained frame with nothing accumulated behind it, so it is framed against a fresh one.
        let bytes = OpenAiRealtimeCodec
            .write_down(event, &mut DecodeState::default())
            .ok_or(Encode::Unrepresentable)?
            .0;
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
        // Every streaming dialect authenticates once at session open and caches the result for the
        // session's life (`dialect::Dialect::authenticates_from_session`, a row field); the two
        // one-shot HTTP operations present a credential on the one request they are. The dialect is
        // the draft's own fact, sealed onto the unit by the kernel, so this step reads what decode
        // determined rather than a session fact that a one-shot unit does not have at all.
        CredentialLocator {
            narrowing: None,
            from_session: draft_dialect(u).is_some_and(|d| d.authenticates_from_session),
        }
    }

    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> DestinationFacts {
        if u.op().as_str() == "tool_call" {
            // The leg names the key; the value is the call identifier `decode_response` already
            // minted on this unit's `correlation_out`, in the unit's own arena, as itself. This
            // plane no longer folds that identifier into a number to get it past a `'static`
            // bound — two calls open at once is the ordinary shape of a turn that asks for two
            // tools, and it is the pair a fold is least entitled to confuse.
            return DestinationFacts::Client {
                selector: "*",
                mode: ClientMode::AwaitReply {
                    correlation_key: FACT_TOOL_CORRELATION,
                    deadline_secs: TOOL_REPLY_DEADLINE_SECS,
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
        // The dialect the decode step named, off the unit's own sealed draft facts, else the first
        // row this node has — a POSITION in the table, which is the order the composition root
        // registered in. It used to be one vendor's row by name, which made a neutral crate's
        // fallback an instance.
        let arriving = draft_dialect(u).or_else(dialect::first);
        match arriving.and_then(|a| self.default_upstream(a)) {
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

    fn meter<'u>(&self, u: &Unit<'u>, r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        let mut lines = busbar_contract::bounded::BoundedVec::new();
        let classes = [
            (meta::FACT_AUDIO_TOKENS_IN, "audio_tokens_in"),
            (meta::FACT_AUDIO_TOKENS_OUT, "audio_tokens_out"),
            (meta::FACT_TEXT_TOKENS_IN, "text_tokens_in"),
            (meta::FACT_TEXT_TOKENS_OUT, "text_tokens_out"),
            (meta::FACT_CACHED_TOKENS, "cached_tokens"),
        ];
        // A duplex turn's figures all come off the upstream's usage report, which is the answer. A
        // one-shot request's input figure comes off the request, which decode read and put on the
        // unit. The answer is asked first either way: a figure the destination confirmed beats one
        // this node estimated, and the unit's own is only reached where the answer reported none.
        let reported = |key: &str| match r.facts.get(key) {
            Some(value) => Some(value),
            None => u.draft_facts().get(key),
        };
        for (fact_key, class) in classes {
            if let Some(FactValue::Int(v)) = reported(fact_key) {
                let _ = lines.push(UsageLocator {
                    class: MeterClassId::new(class),
                    location: None,
                    quantity: u64::try_from(v).ok(),
                    lane: None,
                });
            }
        }
        // The two halves of one duration, ADDED rather than one preferred over the other: the frame
        // that opened the turn stated its own milliseconds on the draft (it never reaches the relay
        // seam), and every frame after it is counted at that seam and reported on the answer. This
        // is not a figure the destination confirmed, so the "answer wins" rule above does not
        // govern it — taking the answer alone dropped the opening frame's audio every turn.
        let opening = match u.draft_facts().get(meta::FACT_AUDIO_MS_IN) {
            Some(FactValue::Int(ms)) => Some(ms),
            _ => None,
        };
        let relayed = match r.facts.get(meta::FACT_AUDIO_MS_IN) {
            Some(FactValue::Int(ms)) => Some(ms),
            _ => None,
        };
        if opening.is_some() || relayed.is_some() {
            let ms = opening.unwrap_or(0).saturating_add(relayed.unwrap_or(0));
            // The counter is milliseconds; the class is seconds. The conversion is the meter
            // boundary's, stated once in `meta` — a millisecond figure carried through under a
            // seconds-denominated class settles at a thousand times the duration it describes.
            let _ = lines.push(UsageLocator {
                class: MeterClassId::new("audio_seconds_in"),
                location: None,
                quantity: u64::try_from(ms).ok().map(meta::audio_seconds_in),
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
            // One mapping, written once in the contract and read by every plane. Every unit this
            // plane audits is a turn of a live session, so a completed one is `TurnComplete`.
            finish: busbar_contract::unit::finish_class_of(out, FinishClass::TurnComplete),
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
            .alloc_str(&dialect::count().to_string())
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
            .and_then(dialect::dialect)
            .or_else(dialect::first);
        PlaneSessionState::new(VoiceSessionState::for_maybe_dialect(dialect))
    }

    fn open_upstream<'u>(&self, dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        let dialect = upstream_dialect_for(self, dest);
        PlaneSessionState::new(VoiceSessionState::for_maybe_dialect(dialect))
    }

    /// THE PROJECTION: what an operator's gate or tap sees when this plane's session is opened.
    ///
    /// The posture is the same one the 1.5.x front door locks and for the same two reasons: a
    /// carrier leg is µ-law end to end, so it opens on [`busbar_voice_codec::ir::config::g711_config`]
    /// and nothing may resample it; every other dialect opens on the deployment's own declared
    /// defaults, read off this call's configuration view under [`SESSION_DEFAULTS_KEY`] and falling
    /// back to the section default when a deployment declares none.
    ///
    /// Rendered ONCE per connection and then held. The bytes are what a configured gate matches on,
    /// so re-rendering them on a second call — after a tap has committed a rewrite — would hand the
    /// second hop a payload the first hop never saw.
    fn session_params<'p, 'u>(
        &self,
        st: &'p mut PlaneSessionState,
        ctx: &Ctx<'u>,
    ) -> Option<SessionParams<'p>> {
        let state = st.get_mut::<VoiceSessionState>()?;
        if state.params.is_empty() {
            // The posture is the dialect's own declaration, read off its row: a dialect that locks
            // one opens on it and nothing may resample it; every other dialect opens on the
            // deployment's declared defaults.
            let locked = match state.dialect.and_then(|d| d.locked_session_config) {
                Some(locked) => locked(),
                None => declared_defaults(ctx),
            };
            state.params = serde_json::to_vec(&locked).ok()?;
        }
        Some(SessionParams {
            container: HOOK_CONTAINER,
            operation: SESSION_OPEN_METHOD,
            declared: &state.params,
        })
    }

    /// ADOPT what a rewrite committed, in place of the posture the projection rendered.
    ///
    /// The bytes are taken VERBATIM and only after they read back as this plane's own session
    /// shape: a payload that does not is not a rewrite of these parameters, and adopting it would
    /// replace a locked posture with something no dialect can open on.
    fn adopt_session_params(&self, st: &mut PlaneSessionState, declared: &[u8]) {
        let Some(state) = st.get_mut::<VoiceSessionState>() else {
            return;
        };
        if serde_json::from_slice::<config::SessionConfig>(declared).is_ok() {
            state.params = declared.to_vec();
        }
    }

    /// THE FRAME A SERVED SESSION OWES BEFORE ANY FRAME ARRIVES, when its dialect declares one.
    ///
    /// WHICH event is the DIALECT's declaration ([`dialect::Dialect::opening_event`]) and nothing
    /// here decides it; WHAT is announced is the posture this session RESOLVED to, which is the same
    /// bytes the projector rendered and holds; and the ENVELOPE is the codec's, reached through the
    /// writer the same row declares. This module therefore contains no vendor's JSON and no vendor's
    /// event name — which is the whole of why the declaration is on the row.
    ///
    /// It reads `state.params` rather than re-rendering the posture, and that ordering is the point:
    /// the projector has already run, an operator's tap has already committed whatever it committed,
    /// and `adopt_session_params` has already taken it. A second render here would announce the
    /// posture the session was ASKED to open on while running under the one it resolved to.
    ///
    /// EMPTY on every other answer, and each is a declared one: a dialect that owes no opening event
    /// (a carrier that speaks second, a dialled leg that relays its upstream's), a session whose
    /// posture was never rendered, and a posture that does not read back as a session shape.
    fn opening_frames(&self, st: &mut PlaneSessionState) -> Vec<Vec<u8>> {
        let Some(state) = st.get_mut::<VoiceSessionState>() else {
            return Vec::new();
        };
        let Some(declared) = state.dialect.and_then(|d| d.opening_event) else {
            return Vec::new();
        };
        let Ok(session) = serde_json::from_slice::<serde_json::Value>(&state.params) else {
            return Vec::new();
        };
        let event = match declared {
            dialect::OpeningEvent::SessionCreated => IrServerEvent::SessionCreated { session },
        };
        writer_for(state.dialect)
            .write_down(event, &mut state.codec)
            .map(|frame| vec![frame.0.to_vec()])
            .unwrap_or_default()
    }
}

/// The container a deployment files this plane's session hooks under.
///
/// The deployment's own word for the section, which is what a configured gate is filed against;
/// spelled here because the projector is now the one place that answers what a hook sees.
const HOOK_CONTAINER: &str = "streams";

/// The method name a session-open hook sees.
///
/// The hook wire's name for the open, NOT [`meta::OP_SESSION_OPEN`]: the operation class prices a
/// unit and this string is matched by a deployment's configured gate. They are different vocabularies
/// and a gate written against one would not match the other.
const SESSION_OPEN_METHOD: &str = "session.open";

/// The configuration key a deployment's declared session defaults are carried under, as the dialect's
/// own `session` object in the notation the wire is written in.
const SESSION_DEFAULTS_KEY: &str = "session_defaults";

/// The declared session defaults for this call: the deployment's, or the section default.
///
/// A value that does not read back as a session shape is NOT half-adopted — the section default
/// stands — because a partially-applied posture is one no operator wrote down.
fn declared_defaults<'u>(ctx: &Ctx<'u>) -> config::SessionConfig {
    ctx.config()
        .get_str(SESSION_DEFAULTS_KEY)
        .and_then(|raw| serde_json::from_str::<config::SessionConfig>(raw).ok())
        .unwrap_or_else(config::default_session)
}

/// What a refused session is told, in the closed vocabulary a client is allowed to see.
///
/// The internal reason is a kernel enum with names for the money, the buckets and the store
/// (`OverdraftCeiling`, `StaleSlice`, `DurabilityUnavailable`). Formatting it onto the wire told
/// every caller which internal ceiling it met and pinned this node's private vocabulary as the
/// dialect's `error.code` — a name no client library has a case for and no dialect documents. What
/// goes out instead is the same small opaque set every other plane in this workspace renders (see
/// `busbar-plane-admin`'s own table): the caller learns the CLASS of refusal and nothing about why
/// this node reached it.
fn refusal_render(reason: busbar_contract::unit::RefusalReason) -> (&'static str, &'static str) {
    use busbar_contract::unit::RefusalReason as R;
    match reason {
        R::BodyTooLarge | R::DecodeFailed | R::SchemeNotDeclared | R::SecretPlaceholder => {
            ("invalid_request", "the request could not be read")
        }
        R::CredentialRejected | R::SessionUnbound | R::CredentialBudget => {
            ("unauthorized", "the session did not carry usable authority")
        }
        R::ScopeMissing | R::Vetoed | R::Revoked | R::PoolNotPermitted => (
            "forbidden",
            "the caller may not open a session for this operation",
        ),
        R::RateLimited | R::InFlightCap | R::OpenSlotBusy | R::SessionBudget => {
            ("rate_limited", "too many sessions at once")
        }
        R::NoDestination | R::DestinationUnreachable | R::BreakerOpen | R::Drain => (
            "unavailable",
            "no provider is reachable for this session right now",
        ),
        // Everything else is this node saying no for a reason that is this node's own — the money,
        // the buckets, the journal. A caller is told it failed here and nothing more.
        _ => ("internal", "the session could not be opened at this time"),
    }
}

/// Which dialect the upstream a verified destination names speaks, by matching its host against
/// this plane's configured upstream list.
///
/// Falls back to the FIRST ROW OF THE TABLE — a position, which is the declaration order the
/// composition root registered in — when the destination is a `SessionUpstream` this function cannot
/// resolve a host for, or names no configured upstream at all, and to `None` on a node with no
/// dialect registered at all. It used to fall back to one particular vendor's row, by name, with a
/// doc comment calling that vendor "the more common of the two": a neutral crate ranking instances,
/// which is the fusion the dialect kind exists to forbid, written down as if it were a fact about
/// wires.
fn upstream_dialect_for(
    plane: &VoicePlane,
    dest: &VerifiedDestination,
) -> Option<&'static Dialect> {
    match dest.facts() {
        DestinationFacts::Upstream { address, .. } => plane
            .upstreams()
            .iter()
            .find(|u| Some(u.host) == address.authority())
            .map(|u| u.dialect)
            .or_else(dialect::first),
        _ => plane
            .upstreams()
            .first()
            .map(|u| u.dialect)
            .or_else(dialect::first),
    }
}

/// The dialect the decode step named, read back off the unit's sealed draft facts.
///
/// The one place this plane's later steps ask what dialect a unit is: decode is the step that read
/// the bytes and matched the claim, and what it determined travels on the unit. A one-shot unit has
/// no session at all, so a session fact could not have answered for it.
fn draft_dialect(u: &Unit<'_>) -> Option<&'static Dialect> {
    match u.draft_facts().get(meta::FACT_DIALECT) {
        Some(FactValue::Str(name)) => dialect::dialect(name),
        _ => None,
    }
}

/// The client's own dialect, read back off the session fact this plane declared (`SESSION_FACTS`).
fn client_dialect_from_session<'u>(ctx: &Ctx<'u>) -> Option<&'static Dialect> {
    ctx.session()
        .and_then(|s| s.session_fact(meta::FACT_DIALECT))
        .and_then(dialect::dialect)
}

/// Every body pointer this plane declares: none.
///
/// This plane's frames are decoded by the codec rather than located by pointer — a duplex event
/// carries its own shape, and the quantities are counted as audio moves rather than pointed at in
/// a document. The span table is still built by the one scanner from this declaration, so
/// "declares nothing" is something the loop can read instead of a table nobody filled in.
const BODY_PTRS: &[&str] = &[];

/// The span view of a body, built from the pointers this plane declares.
fn view<'u>(body: &'u [u8], ctx: &Ctx<'u>) -> Result<Ir<'u>, Decode> {
    let spans = busbar_contract::spans::resolve(body, BODY_PTRS, ctx.arena())
        .map_err(|_| Decode::Oversize)?;
    Ok(Ir::new(body, spans))
}

/// Decode a one-shot (`http`) transcribe/tts request: no session, a single `OneShot` unit.
fn decode_one_shot<'u>(frames: &mut FrameCursor<'u>, ctx: &Ctx<'u>) -> Result<Ingress<'u>, Decode> {
    let path = ctx
        .transport()
        .fact(FACT_PATH)
        .ok_or(Decode::MissingDeclaredFact)?;
    let dialect = claims::dialect_for(path).ok_or(Decode::UnsupportedOperation)?;
    // The two one-shot names are strings and have no dialect row: they are HTTP operations, not
    // streaming dialects (see `claims`'s own header).
    let op = match dialect {
        claims::TRANSCRIBE => OpClassId::new(claims::TRANSCRIBE),
        claims::TTS => OpClassId::new(claims::TTS),
        _ => return Err(Decode::UnsupportedOperation),
    };
    let frame = frames.next_frame();
    let body: &'u [u8] = frame.map(|f| f.bytes.as_slice()).unwrap_or(&[]);
    let mut facts = Facts::new();
    facts
        .set(meta::FACT_DIALECT, FactValue::Str(dialect))
        .map_err(|_| Decode::Oversize)?;
    // What a text-to-speech request is priced on is the text it asks to be spoken, and that text is
    // in the request rather than in the answer. Decode is the step that reads the request's bytes,
    // so the figure is taken here and travels on the unit; the metering step reads it back off the
    // draft rather than opening the body a second time.
    if dialect == claims::TTS {
        if let Some(text) = crate::oneshot::tts_input_text(body) {
            facts
                .set(
                    meta::FACT_TEXT_TOKENS_IN,
                    FactValue::Int(
                        i64::try_from(meta::text_tokens_of(text.len())).unwrap_or(i64::MAX),
                    ),
                )
                .map_err(|_| Decode::Oversize)?;
        }
    }
    Ok(Ingress::OneShot(Box::new(UnitDraft {
        op,
        body_ir: view(body, ctx)?,
        correlates: None,
        correlation_out: None,
        facts,
    })))
}

/// Decode the answer to a one-shot transcribe or text-to-speech request.
///
/// There is no session and no codec state: the operation is one request and one answer, and the
/// answer ends the unit. What the answer states is what is stamped — a transcription's own text,
/// under the class the emitted text prices at. A speech answer is audio bytes whose duration this
/// plane cannot read without knowing the format the upstream chose, so it states nothing about
/// them: the request's own text estimate, taken at decode, is what that unit is priced on.
fn decode_one_shot_response<'u>(
    frames: &mut FrameCursor<'u>,
    ctx: &Ctx<'u>,
) -> Result<Progress<'u>, Decode> {
    let path = ctx
        .transport()
        .fact(FACT_PATH)
        .ok_or(Decode::MissingDeclaredFact)?;
    let dialect = claims::dialect_for(path).ok_or(Decode::UnsupportedOperation)?;
    if !matches!(dialect, claims::TRANSCRIBE | claims::TTS) {
        return Err(Decode::UnsupportedOperation);
    }
    let frame = frames.next_frame();
    let body: &'u [u8] = frame.map(|f| f.bytes.as_slice()).unwrap_or(&[]);
    let mut facts = Facts::new();
    if dialect == claims::TRANSCRIBE {
        if let Some(text) = transcript_text(body) {
            facts
                .set(
                    meta::FACT_TEXT_TOKENS_OUT,
                    FactValue::Int(
                        i64::try_from(meta::text_tokens_of(text.len())).unwrap_or(i64::MAX),
                    ),
                )
                .map_err(|_| Decode::Oversize)?;
        }
    }
    Ok(Progress::Terminal {
        for_: None,
        r: Box::new(Response {
            ir: view(body, ctx)?,
            finish: FinishClass::TurnComplete,
            facts,
        }),
    })
}

/// The text a one-shot transcription answered with, in the provisional wire shape this plane
/// documents (`{"text": "..."}`). `None` for anything else, which states nothing rather than
/// guessing a figure.
fn transcript_text(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("text")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Decode one frame of a duplex session bound to one of the two WS dialects (OpenAI Realtime or
/// Gemini Live).
fn decode_ws_frame<'u>(
    frames: &mut FrameCursor<'u>,
    state: &mut VoiceSessionState,
    dialect: &'static Dialect,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    let frame = frames.next_frame().ok_or(Decode::Malformed)?;
    // A frame the cursor carved but that carries no bytes yet is the one genuinely partial shape at
    // this layer (mcp's own decode makes the same distinction on an empty body): wait for the rest.
    if frame.bytes.is_empty() {
        return Ok(Ingress::NeedMore);
    }
    // A frame WITH bytes that is not readable text is a refusal, not a partial read: nothing more
    // ever arrives to complete an already-complete WS frame that failed to decode as UTF-8.
    std::str::from_utf8(frame.bytes.as_slice()).map_err(|_| Decode::Malformed)?;
    // Borrowed, not copied: see `decode_response`'s own note on the downlink side of this.
    let reader = reader_for(Some(dialect));
    let events = reader.read_up_ref(WireRef(frame.bytes.as_slice()), &mut state.codec);
    let Some(event) = events.into_iter().next() else {
        // A JSON document this dialect does not recognise is answered exactly the way
        // `decode_response` answers an unrecognised server event and mcp answers an unrecognised
        // notice: dropped, never left pending forever.
        return Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported,
        });
    };
    // Stashed so `encode_ingress_frame` never calls the stateful reader a second time for the same
    // wire frame (see `crate::session::Pending`'s doc comment).
    state.pending = Some(Pending::Ingress(event.clone()));
    ingress_from_client_event(event, state, dialect, ctx)
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
    dialect: &'static Dialect,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    // A tool RESULT is not a frame of the conversation; it is the answer to a call the upstream
    // opened, and it belongs to that call's own unit. Relayed onto the open turn — which is what
    // every client tool event did — it arrived under the turn's hold naming the turn's correlation,
    // so the one unit actually waiting for it could not be told it had been answered, and the reply
    // and the wait passed each other on the same session.
    if let IrClientEvent::Tool(IrDuplexTool::CallResult { call_id, .. }) = &event {
        let id = ctx
            .arena()
            .alloc_str(call_id)
            .map_err(|_| Decode::Oversize)?;
        let mut facts = Facts::new();
        facts
            .set(meta::FACT_CALL_ID, FactValue::Str(id))
            .map_err(|_| Decode::Oversize)?;
        return Ok(Ingress::Frame {
            // The identifier as itself, under the key the leg named. Whole value, because the pair
            // this has to tell apart is two calls open on one session at one moment.
            for_: Some(CorrelationRef {
                fact_key: FACT_TOOL_CORRELATION,
                value: CorrelationValue::Str(id),
            }),
            relay: ArenaBytes::new(&[]),
            facts: Box::new(facts),
        });
    }
    let (relay, interrupt_ms, audio_ms) = match &event {
        IrClientEvent::AudioFrame(f) => {
            // See the module doc comment: the uplink format is assumed PCM16 for this estimate.
            // The figure is not accumulated here — see `encode_ingress_frame`, which counts what
            // is actually relayed on the half the response step later reads it back from.
            let ms = AudioFormat::Pcm16.bytes_to_ms(f.media.len() as u64);
            let bytes = ctx
                .arena()
                .alloc_bytes(&f.media)
                .map_err(|_| Decode::Oversize)?;
            (bytes, None, Some(ms))
        }
        IrClientEvent::Control(IrDuplexControl::ItemTruncate {
            audio_played_ms, ..
        }) => (ArenaBytes::new(&[]), Some(*audio_played_ms), None),
        IrClientEvent::Control(_) | IrClientEvent::Tool(_) => (ArenaBytes::new(&[]), None, None),
    };
    // A REQUEST THIS SESSION HAS NO LEG TO ANSWER, marked for the unit that must refuse it. WHICH
    // events are requests is the DIALECT's declaration and this crate reads it rather than deciding
    // it; whether this session can answer one is the session's own view of how many upstreams it
    // has. Both are read here, once, where the frame is read — and a request on a session that HAS
    // a leg is not marked at all, because that one is relayed and the provider answers it.
    let awaits_terminal = dialect
        .request_terminal
        .is_some_and(|t| (t.is_request)(&event))
        && ctx.session().is_none_or(|s| s.upstream_count() == 0);
    open_or_relay(
        state,
        dialect,
        relay,
        interrupt_ms,
        audio_ms,
        awaits_terminal,
        ctx,
    )
}

/// Open a fresh turn (this is its first frame) or relay onto the one already open, attaching the
/// interrupt fact where the caller says the event carried one, either way.
///
/// A frame that CARRIES an interrupt always opens. The scheduler reads the interrupt off an OPEN —
/// that is the only shape whose dispatch reaches the compare-and-set that supersedes the unit in
/// flight — so a barge-in delivered as one more frame of the very turn it interrupts named the
/// superseded unit to nobody: the interrupted turn kept the direction's slot and kept pricing while
/// the caller was already talking over it, and the turn that took over could never open.
pub fn open_or_relay<'u>(
    state: &mut VoiceSessionState,
    dialect: &Dialect,
    relay: ArenaBytes<'u>,
    interrupt_ms: Option<u64>,
    audio_ms: Option<u64>,
    awaits_terminal: bool,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    let mut facts = Facts::new();
    if let Some(ms) = interrupt_ms {
        let _ = facts.set(
            meta::FACT_INTERRUPT_AUDIO_PLAYED_MS,
            FactValue::Int(i64::try_from(ms).unwrap_or(i64::MAX)),
        );
        // The interrupted turn ends here; the frame that interrupted it opens the next one, and
        // carries the fact that says which one it took over from.
        let _ = state.close_turn();
    }
    if !state.turn_open {
        // The opening frame becomes the unit's own egress body rather than travelling through the
        // relay seam, so what it carries of the caller's audio is stated on the draft. Every later
        // frame of the turn is counted where it relays.
        if let Some(ms) = audio_ms {
            let _ = facts.set(
                meta::FACT_AUDIO_MS_IN,
                FactValue::Int(i64::try_from(ms).unwrap_or(i64::MAX)),
            );
        }
        let correlation = state.open_turn();
        let _ = facts.set(meta::FACT_DIALECT, FactValue::Str(dialect.name));
        if awaits_terminal {
            let _ = facts.set(meta::FACT_AWAITS_TERMINAL, FactValue::Bool(true));
        }
        let ir = view(relay.as_slice(), ctx)?;
        Ok(Ingress::Open(Box::new(UnitDraft {
            op: OpClassId::new("duplex_turn"),
            body_ir: ir,
            correlates: None,
            correlation_out: Some(correlation),
            facts,
        })))
    } else {
        Ok(Ingress::Frame {
            for_: state.turn_correlation,
            relay,
            facts: Box::new(facts),
        })
    }
}

/// Turn one decoded server→client IR event into a `Progress` answer, rendering the client-shaped
/// bytes immediately (see the module doc comment's `encode_response` note).
fn progress_from_server_event<'u>(
    event: IrServerEvent,
    state: &mut VoiceSessionState,
    client_dialect: Option<&Dialect>,
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
            Ok(Progress::OneShot(Box::new(UnitDraft {
                op: OpClassId::new("tool_call"),
                body_ir: Ir::empty(),
                correlates: None,
                // The call identifier travels as itself. It is a string on the wire and it is a
                // string here, allocated in the unit's own arena — a fold into sixty four bits
                // would be one collision away from answering a tool call with another's reply.
                correlation_out: Some(CorrelationRef {
                    fact_key: FACT_TOOL_CORRELATION,
                    value: CorrelationValue::Str(call_id_arena),
                }),
                facts,
            })))
        }
        IrServerEvent::Tool(_) => Ok(Progress::Frame {
            for_,
            r: Box::new(Response {
                ir: Ir::empty(),
                finish: FinishClass::Partial,
                facts: Facts::new(),
            }),
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
                r: Box::new(Response {
                    ir: Ir::empty(),
                    finish: FinishClass::Partial,
                    facts,
                }),
            })
        }
        IrServerEvent::SpeechStopped { .. } | IrServerEvent::AudioDone { .. } => {
            Ok(Progress::Frame {
                for_,
                r: Box::new(Response {
                    ir: Ir::empty(),
                    finish: FinishClass::Partial,
                    facts: Facts::new(),
                }),
            })
        }
        IrServerEvent::AudioFrame(f) => {
            let writer = writer_for(client_dialect);
            let media_len = f.media.len() as u64;
            // One buffer, filled and then copied into the arena. The identifier is BORROWED from the
            // binding the `start` event made: it is the same string on every frame of the call, and
            // a call sends fifty frames a second, so cloning it per frame is fifty copies a second
            // of a string that never changes.
            //
            // Each arm reaches the arena on its own rather than through one shared owning type: the
            // carrier's renderer refills a buffer the SESSION holds, and handing its bytes through a
            // per-frame owner put back exactly the allocation per frame the renderer exists to
            // remove — the renderer's committed zero was true of the renderer and false of its only
            // caller.
            let bytes = match client_dialect.and_then(|d| d.envelope) {
                Some(envelope) => {
                    (envelope.render_downlink_audio)(state, &f.media);
                    ctx.arena()
                        .alloc_bytes(&state.render_buf)
                        .map_err(|_| Decode::Oversize)?
                }
                None => {
                    let rendered = writer
                        .write_down(IrServerEvent::AudioFrame(f), &mut state.codec)
                        .ok_or(Decode::Malformed)?
                        .0;
                    ctx.arena()
                        .alloc_bytes(&rendered)
                        .map_err(|_| Decode::Oversize)?
                }
            };
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
                r: Box::new(Response {
                    ir: view(bytes.as_slice(), ctx)?,
                    finish: FinishClass::Partial,
                    facts,
                }),
            })
        }
        IrServerEvent::Usage(usage) => {
            let counters = state.close_turn();
            let mut facts = Facts::new();
            let ints: [(&str, i64); 7] = [
                (
                    meta::FACT_AUDIO_TOKENS_IN,
                    i64::try_from(usage.audio_in).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_AUDIO_TOKENS_OUT,
                    i64::try_from(usage.audio_out).unwrap_or(i64::MAX),
                ),
                // The two halves travel separately. Summing them was what forced the whole figure
                // through a single input-direction class; the upstream reports them apart and this
                // plane keeps them apart, so the emitted half prices as output.
                (
                    meta::FACT_TEXT_TOKENS_IN,
                    i64::try_from(usage.text_in).unwrap_or(i64::MAX),
                ),
                (
                    meta::FACT_TEXT_TOKENS_OUT,
                    i64::try_from(usage.text_out).unwrap_or(i64::MAX),
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
                r: Box::new(Response {
                    ir: Ir::empty(),
                    finish: FinishClass::TurnComplete,
                    facts,
                }),
            })
        }
        IrServerEvent::Error { code, message } => {
            // A turn that ends in an upstream error consumed the same uplink audio and ran the same
            // tool calls as one that ends in a usage report. The kernel-side counters are the only
            // record of either, and closing the turn is what takes them: dropping them here would
            // meter the failed turn at zero and hand back for free every second the caller spoke.
            let counters = state.close_turn();
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
            facts
                .set(
                    meta::FACT_AUDIO_MS_IN,
                    FactValue::Int(i64::try_from(counters.audio_ms_in).unwrap_or(i64::MAX)),
                )
                .map_err(|_| Decode::Oversize)?;
            facts
                .set(
                    meta::FACT_TOOL_CALLS,
                    FactValue::Int(i64::try_from(counters.tool_calls).unwrap_or(i64::MAX)),
                )
                .map_err(|_| Decode::Oversize)?;
            Ok(Progress::Terminal {
                for_,
                r: Box::new(Response {
                    ir: Ir::empty(),
                    finish: FinishClass::Error,
                    facts,
                }),
            })
        }
    }
}
