// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READER / WRITER PAIR — the bidirectional analog of the LLM plane's
//! `ProtocolReader`/`ProtocolWriter`. Design `plane4-duplex-session.md`.
//!
//! The single design delta vs the LLM `ProtocolReader` is that Plane 4 needs a client→server event
//! vocabulary, so the plane defines TWO DIRECTIONS over one wire schema (the MCP "one reader, one
//! writer, both directions" discipline).
//!
//! The dialect is OpenAI Realtime GA: every wire event is a JSON object tagged on a `type` field. The
//! reader parses `WireEvent` bytes to a `serde_json::Value` and hand-maps by `type` (the LLM-plane
//! convention — serde-derive is reserved for the [`crate::ir::config::SessionConfig`] object); the
//! writer builds the JSON back. One wire event maps to 0..n IR events; a malformed / unrecognized
//! frame yields an EMPTY vec (the streaming-decode discipline — degrade, don't error), except a
//! dialect `error` event, which surfaces as [`IrServerEvent::Error`].
//!
//! STATE THREADING: unlike the LLM reader (whose request path is stateless whole-JSON), BOTH
//! directions here thread [`DecodeState`] — uplink needs the monotonic frame `seq` and `CallRef`
//! minting just as downlink does. The WRITERS thread the same state, for the one thing framing cannot
//! answer from a single event: a dialect that delivers a tool call ATOMICALLY has nothing to frame
//! from a streamed argument FRAGMENT, so the fragments accumulate on the session and the call is
//! framed whole at its close. Everything else a writer needs is still carried in the IR (each tool
//! variant carries its raw `call_id`, so re-framing a `function_call_output` invents nothing).

use crate::ir::config::SessionConfig;
use crate::ir::control::IrDuplexControl;
use crate::ir::event::{IrClientEvent, IrServerEvent};
use crate::ir::media::{AudioFormat, IrAudioFrame, IrAudioRef, UpDown};
use crate::ir::tool::{CallRef, IrDuplexTool};
use crate::ir::usage::IrDuplexUsage;
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};

/// The dialect wire `type` tokens — named once here so the reader's dispatch and the writer's framing
/// never drift. These are the plane's OWN vocabulary (it owns 100% of its protocol nouns, `plane4-duplex-session.md`).
mod wire {
    // client → server
    pub const SESSION_UPDATE: &str = "session.update";
    pub const INPUT_AUDIO_APPEND: &str = "input_audio_buffer.append";
    pub const INPUT_AUDIO_COMMIT: &str = "input_audio_buffer.commit";
    pub const INPUT_AUDIO_CLEAR: &str = "input_audio_buffer.clear";
    pub const ITEM_CREATE: &str = "conversation.item.create";
    pub const ITEM_TRUNCATE: &str = "conversation.item.truncate";
    pub const ITEM_DELETE: &str = "conversation.item.delete";
    pub const RESPONSE_CREATE: &str = "response.create";
    pub const RESPONSE_CANCEL: &str = "response.cancel";
    // server → client
    pub const SESSION_CREATED: &str = "session.created";
    pub const SPEECH_STARTED: &str = "input_audio_buffer.speech_started";
    pub const SPEECH_STOPPED: &str = "input_audio_buffer.speech_stopped";
    pub const OUTPUT_AUDIO_DELTA: &str = "response.output_audio.delta";
    pub const OUTPUT_AUDIO_DELTA_LEGACY: &str = "response.audio.delta";
    pub const OUTPUT_AUDIO_DONE: &str = "response.output_audio.done";
    pub const OUTPUT_AUDIO_DONE_LEGACY: &str = "response.audio.done";
    pub const OUTPUT_ITEM_ADDED: &str = "response.output_item.added";
    pub const FN_ARGS_DELTA: &str = "response.function_call_arguments.delta";
    pub const FN_ARGS_DONE: &str = "response.function_call_arguments.done";
    pub const RESPONSE_DONE: &str = "response.done";
    pub const RATE_LIMITS_UPDATED: &str = "rate_limits.updated";
    pub const ERROR: &str = "error";
    // shared item nouns
    pub const ITEM_FN_CALL_OUTPUT: &str = "function_call_output";
    pub const ITEM_FN_CALL: &str = "function_call";
}

/// ONE WIRE EVENT — the opaque, dialect-shaped message a reader parses / a writer produces: the JSON
/// bytes of one OpenAI Realtime event. Kept deliberately opaque so the reader/writer own all framing
/// knowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEvent(pub bytes::Bytes);

/// THE SAME WIRE EVENT, BORROWED — the bytes of one dialect event where they already are.
///
/// A reader never keeps its input: it parses the bytes and hands back IR events that own everything
/// they carry. So a caller who already holds the bytes — a transport holding the frame it just read
/// off a socket — has no reason to buy them a second home first. A duplex session reads fifty
/// frames a second in each direction, and each of those copies was one whole frame.
///
/// [`WireEvent`] remains what a WRITER produces, because a writer's output is bytes that did not
/// exist until it made them and must outlive the call that made them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireRef<'a>(pub &'a [u8]);

impl<'a> From<&'a WireEvent> for WireRef<'a> {
    fn from(evt: &'a WireEvent) -> Self {
        Self(&evt.0)
    }
}

/// PER-SESSION DECODE STATE threaded through the reader — the analog of the LLM reader's
/// `StreamDecodeState`. Holds what is per-session, not per-frame: monotonic frame sequencing, the
/// `CallRef ↔ call_id` correlation table (`plane4-duplex-session.md`), the negotiated output format, and the barge-in
/// playback-position bookkeeping (`plane4-duplex-session.md` — the plane tracks bytes played because the upstream emits
/// audio faster than realtime).
/// THE CEILING ON THE `call_id → CallRef` TABLE, stated here rather than left implicit.
///
/// The table is a correlation convenience — open, args, close and result for ONE call meeting under
/// one handle — not a ledger, and nothing removes from it within a session (a `conversation.item.delete`
/// deletes an ITEM, which is not the call). A client that mints distinct `call_id`s therefore grows
/// it for as long as the call lasts. 1024 is far past any real turn's concurrent tool calls, so the
/// eviction below is unreachable in ordinary use; past it the OLDEST entry goes and a re-sighting of
/// an evicted id correlates as a NEW call, which is the honest answer once the older correlation is
/// no longer held.
pub const MAX_TRACKED_CALL_IDS: usize = 1024;

/// THE CEILING ON THE DROPPED-FIELD DIAGNOSTIC LIST. The list is a diagnostic tap, not a ledger: a
/// peer that patches the session with unmodelled fields every frame must not be able to grow it
/// without limit. Past the ceiling the OLDEST note goes — the most recent drops are the ones an
/// operator is looking at.
pub const MAX_TRACKED_DROPPED_FIELDS: usize = 64;

/// THE CEILING ON ONE CALL'S ACCUMULATED ARGUMENT TEXT. A dialect that delivers a tool call ATOMICALLY
/// cannot frame it until the streamed arguments are whole, so the fragments are held — and a peer that
/// streams fragments forever must not be able to hold memory forever. Past the ceiling the buffer is
/// ABANDONED and the call frames nothing, which is the same answer arguments that never parse get: an
/// argument list nobody can read is not an argument list, and dispatching the call without it is the
/// one outcome a tool call cannot afford. 256 KiB is far past any real argument object.
pub const MAX_TOOL_ARG_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub struct DecodeState {
    up_seq: u64,
    down_seq: u64,
    next_call_ref: u64,
    call_ids: HashMap<String, CallRef>,
    /// Insertion order of `call_ids`, oldest first — what makes "evict the oldest" answerable
    /// without asking the map, which has no order.
    call_id_order: VecDeque<String>,
    /// The tool NAME the model announced for a `call_id` — the slot Gemini's `functionResponse`
    /// requires and OpenAI's `function_call_output` does not carry, remembered from the originating
    /// call so a cross-dialect result can still name its tool.
    call_names: HashMap<String, String>,
    /// Wire fields the decode could not model and therefore DROPPED, newest last. This crate links no
    /// logging surface, so the plane's "warn" is realized as a recorded, readable drop rather than a
    /// silent one.
    dropped_fields: VecDeque<String>,
    /// STREAMED TOOL-ARGUMENT FRAGMENTS held per call, for the WRITE seam. A dialect that delivers a
    /// tool call atomically has nothing to frame until the arguments are whole; the shared IR streams
    /// them, so the writer accumulates here and frames the call ONCE at its close. `None` for the
    /// entry means the accumulation was abandoned (over the ceiling) — the call frames nothing.
    call_args: HashMap<CallRef, Option<String>>,
    /// Downlink audio bytes RELAYED for the CURRENT item — reset when the item ends (its audio is
    /// done, a new audio-bearing item begins) and on a barge-in flush.
    played_bytes: u64,
    /// The latest clock reading the runtime has fed for the current item (ms of playback elapsed),
    /// `None` while nobody feeds one. This crate owns no time source; it bounds, never invents.
    played_clock_ms: Option<u64>,
    /// Negotiated OUTPUT format the truncate math measures against.
    output_fmt: AudioFormat,
}

impl Default for DecodeState {
    fn default() -> Self {
        DecodeState {
            up_seq: 0,
            down_seq: 0,
            next_call_ref: 0,
            call_ids: HashMap::new(),
            call_id_order: VecDeque::new(),
            call_names: HashMap::new(),
            dropped_fields: VecDeque::new(),
            call_args: HashMap::new(),
            played_bytes: 0,
            played_clock_ms: None,
            output_fmt: AudioFormat::Pcm16,
        }
    }
}

impl DecodeState {
    /// The next uplink frame sequence number (monotonic per session).
    pub fn next_up_seq(&mut self) -> u64 {
        let s = self.up_seq;
        self.up_seq += 1;
        s
    }

    /// The next downlink frame sequence number (monotonic per session).
    pub fn next_down_seq(&mut self) -> u64 {
        let s = self.down_seq;
        self.down_seq += 1;
        s
    }

    /// The [`CallRef`] for a wire `call_id`, minting a fresh monotonic handle the first time the id is
    /// seen and returning the SAME handle on every later sighting (open → args → close → result all
    /// correlate to one ref). Bounded by [`MAX_TRACKED_CALL_IDS`]: past the ceiling the oldest id is
    /// evicted, so a session cannot be made to grow this table without limit by minting call ids.
    pub fn ref_for_call_id(&mut self, call_id: &str) -> CallRef {
        if let Some(r) = self.call_ids.get(call_id) {
            return *r;
        }
        let r = CallRef(self.next_call_ref);
        self.next_call_ref += 1;
        self.call_ids.insert(call_id.to_string(), r);
        self.call_id_order.push_back(call_id.to_string());
        while self.call_id_order.len() > MAX_TRACKED_CALL_IDS {
            if let Some(oldest) = self.call_id_order.pop_front() {
                self.call_ids.remove(&oldest);
                self.call_names.remove(&oldest);
            }
        }
        r
    }

    /// REMEMBER the tool name the model announced for a `call_id`. OpenAI's `function_call_output`
    /// carries no name; Gemini's `functionResponse` REQUIRES one, so the name is kept from the
    /// originating call and handed back on the result. An empty name records nothing.
    pub fn remember_call_name(&mut self, call_id: &str, name: &str) {
        if name.is_empty() || call_id.is_empty() {
            return;
        }
        self.call_names
            .insert(call_id.to_string(), name.to_string());
    }

    /// The tool name remembered for a `call_id` (empty when the call was never announced on this
    /// session — a result for an id we never saw open cannot invent a name).
    #[must_use]
    pub fn call_name(&self, call_id: &str) -> &str {
        self.call_names.get(call_id).map_or("", String::as_str)
    }

    /// ACCUMULATE one streamed argument fragment for a call, on the WRITE seam. The shared IR streams
    /// a tool call's arguments (the OpenAI dialect's own shape); a dialect that delivers the call
    /// ATOMICALLY has nothing to frame from a fragment, so the pieces are held here until the call
    /// closes. Past [`MAX_TOOL_ARG_BYTES`] the accumulation is abandoned and stays abandoned.
    ///
    /// A fragment that is ITSELF a whole JSON OBJECT is not a fragment of anything: it is the dialect
    /// handing the arguments over complete (an atomic call's `args`, or the complete `arguments` a
    /// streamed call states when it closes), so it REPLACES what was held rather than being appended
    /// to it. Appending would splice the same arguments onto their own prefix and leave nothing
    /// readable — the call would be lost precisely when the dialect had just said it plainly.
    pub fn push_call_args(&mut self, call: CallRef, fragment: &[u8]) {
        let whole = serde_json::from_slice::<Value>(fragment)
            .ok()
            .filter(Value::is_object);
        let held = self
            .call_args
            .entry(call)
            .or_insert_with(|| Some(String::new()));
        if let Some(v) = whole {
            *held = Some(v.to_string());
            return;
        }
        let Some(buf) = held else {
            return; // already abandoned — a later fragment cannot make the whole readable.
        };
        if buf.len().saturating_add(fragment.len()) > MAX_TOOL_ARG_BYTES {
            *held = None;
            return;
        }
        buf.push_str(&String::from_utf8_lossy(fragment));
    }

    /// TAKE a call's accumulated arguments, parsed as ONE whole JSON value, and forget them.
    ///
    /// `None` when nothing was accumulated, when the accumulation was abandoned, or when the whole
    /// does not parse — each of which means the same thing to a caller framing an atomic tool call:
    /// there are no arguments to state. A caller must NOT substitute an empty or null argument list
    /// for this answer; a call dispatched without the arguments the model asked for is a different
    /// call.
    pub fn take_call_args(&mut self, call: CallRef) -> Option<Value> {
        let buf = self.call_args.remove(&call)??;
        if buf.is_empty() {
            return None;
        }
        serde_json::from_str::<Value>(&buf).ok()
    }

    /// RECORD a wire field the decode could not model and dropped — the plane's "warn" made readable.
    /// Bounded by [`MAX_TRACKED_DROPPED_FIELDS`].
    pub fn record_dropped_field(&mut self, field: &str) {
        self.dropped_fields.push_back(field.to_string());
        while self.dropped_fields.len() > MAX_TRACKED_DROPPED_FIELDS {
            self.dropped_fields.pop_front();
        }
    }

    /// The wire fields dropped as unmodelled so far this session, newest last.
    #[must_use]
    pub fn dropped_fields(&self) -> Vec<&str> {
        self.dropped_fields.iter().map(String::as_str).collect()
    }

    /// The negotiated output format (defaults to `pcm16` until a `session.update` sets it).
    #[must_use]
    pub fn output_format(&self) -> AudioFormat {
        self.output_fmt
    }

    /// Adopt the negotiated output audio format (from a `session.update` / `session.created`).
    pub fn set_output_format(&mut self, fmt: AudioFormat) {
        self.output_fmt = fmt;
    }

    /// Account `n` bytes of downlink audio as RELAYED for the current item.
    ///
    /// WHAT THIS COUNTS, PLAINLY: bytes that went out, not audio that came back. The upstream emits a
    /// turn's audio far faster than it plays, so immediately after a burst this counter already holds
    /// the whole turn while the user has heard a fraction of it. It is therefore an UPPER BOUND on the
    /// audio heard — the right shape for a truncate point (never cut BEFORE what was heard), and not a
    /// measurement of playback. [`Self::record_played_at`] is the seam a real clock narrows it through.
    pub fn record_played(&mut self, n: u64) {
        self.record_played_at(n, None);
    }

    /// The same accounting WITH A CLOCK: `at_ms` is how long this item's audio has actually been
    /// playing when these bytes were relayed.
    ///
    /// This is the seam the runtime feeds a clock through — it owns the wall clock, this crate owns no
    /// time source and invents none. While `None` is passed the position is the bytes relayed, exactly
    /// as before; once a reading arrives the position cannot exceed the time there has been to hear it
    /// in, which is the difference between "audio handed over" and "audio heard".
    pub fn record_played_at(&mut self, n: u64, at_ms: Option<u64>) {
        self.played_bytes += n;
        if let Some(ms) = at_ms {
            self.played_clock_ms = Some(self.played_clock_ms.map_or(ms, |prev| prev.max(ms)));
        }
    }

    /// The audio the user can have heard so far, in ms — the barge-in truncate point.
    ///
    /// The bytes relayed for this item, converted at the negotiated format's rate, and bounded by the
    /// clock when the runtime has fed one (no clock: the bytes stand alone, an upper bound).
    #[must_use]
    pub fn played_ms(&self) -> u64 {
        let by_bytes = crate::ir::media::truncate_point_ms(self.played_bytes, self.output_fmt);
        match self.played_clock_ms {
            Some(elapsed) => by_bytes.min(elapsed),
            None => by_bytes,
        }
    }

    /// FLUSH the queued/played downlink audio on `speech_started` (barge-in): returns the just-heard
    /// duration (ms) — the value an [`IrDuplexControl::ItemTruncate`] carries — and zeroes the
    /// playback counter for the next item. This is the DATA move; the runtime that cancels the
    /// in-flight response and emits the truncate is the next layer.
    pub fn flush_playback(&mut self) -> u64 {
        let ms = self.played_ms();
        self.played_bytes = 0;
        self.played_clock_ms = None;
        ms
    }

    /// THE ITEM BOUNDARY — the played-out position belongs to ONE item, so it starts over when that
    /// item's audio ends (or the next audio-bearing item begins). Without this the barge-in truncate
    /// point would be the running total since the session opened, and turn two would be truncated at
    /// turn one plus turn two.
    pub fn reset_playback(&mut self) {
        self.played_bytes = 0;
        self.played_clock_ms = None;
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────────────────────────

fn parse(wire: WireRef<'_>) -> Option<Value> {
    serde_json::from_slice::<Value>(wire.0).ok()
}

fn wire_of(v: &Value) -> WireEvent {
    // serde_json::to_vec on an owned Value cannot fail.
    WireEvent(Bytes::from(serde_json::to_vec(v).unwrap_or_default()))
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or_default()
}

/// Read the item correlation this dialect states on a downlink audio event. Each field is carried only
/// when the wire actually said it — an absent field stays absent rather than becoming an empty string
/// or a zero index, which name a different (real) item.
fn audio_ref_of(v: &Value) -> IrAudioRef {
    let text = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let index = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    IrAudioRef {
        response_id: text("response_id"),
        item_id: text("item_id"),
        output_index: index("output_index"),
        content_index: index("content_index"),
    }
}

/// base64-decode a wire audio string to opaque media bytes (the identity IR is the decoded bytes).
///
/// `None` on a payload that is not base64, and every read path must DROP that frame rather than
/// substitute an empty one. The callee returns `Option` deliberately — it refuses even a lone
/// trailing sextet "rather than silently drop it, honoring the fail-loud contract" — and an empty
/// frame relayed and metered in place of a refusal is indistinguishable from a caller who said
/// nothing, which is the one confusion a voice plane cannot afford. The Twilio grammar in this same
/// crate already answers this way (`BadPayload`, never an empty payload).
fn decode_audio(b64: &str) -> Option<Bytes> {
    busbar_substrate_values::media::base64_decode(b64)
}

/// base64-encode opaque media bytes back to a wire audio string.
fn encode_audio(media: &Bytes) -> String {
    busbar_substrate_values::media::base64_encode(media)
}

/// DECODE A `session` OBJECT LENIENTLY — the drop-and-warn discipline the cross-dialect map states
/// for values this plane does not model (`voice-cross-dialect-map.json`: an unmodelled telephony
/// codec, an eagerness with no twin, a noise-reduction knob are each recorded as a DROPPED FIELD, not
/// a refused session).
///
/// The whole-object parse is tried first (the ordinary path, no allocation beyond serde's). Only when
/// it fails is the patch salvaged FIELD BY FIELD: a key that cannot stand alone is the key the plane
/// cannot model, so that key alone is dropped — noted in [`DecodeState::dropped_fields`] — and the
/// rest of the client's patch survives. Defaulting the whole object instead would silently replace the
/// client's instructions, tools, voice and turn detection with an EMPTY session, which is the one
/// answer a session patch must never give.
///
/// Unknown KEYS are not drops: `SessionConfig` ignores them by design (a partial GA patch names only
/// what it changes), so they never reach this path.
fn session_config_lenient(session: &Value, st: &mut DecodeState) -> SessionConfig {
    use serde::Deserialize as _;
    if let Ok(cfg) = SessionConfig::deserialize(session) {
        return cfg;
    }
    let Some(obj) = session.as_object() else {
        // Not an object at all — there is no field to salvage.
        st.record_dropped_field("session");
        return SessionConfig::default();
    };
    let mut kept = serde_json::Map::new();
    for (k, val) in obj {
        let probe = Value::Object(std::iter::once((k.clone(), val.clone())).collect());
        if SessionConfig::deserialize(&probe).is_ok() {
            kept.insert(k.clone(), val.clone());
        } else {
            st.record_dropped_field(k);
        }
    }
    let kept = Value::Object(kept);
    SessionConfig::deserialize(&kept).unwrap_or_else(|_| {
        // Every field stood alone yet the set does not parse — nothing left to salvage honestly.
        st.record_dropped_field("session");
        SessionConfig::default()
    })
}

// ── reader ──────────────────────────────────────────────────────────────────────────────────────

/// WIRE → IR. Reads a dialect's wire events into the plane's neutral IR, in both directions.
///
/// One wire event maps to 0..n IR events (the `read_response_events` shape). Both directions thread
/// per-session [`DecodeState`] (seq, `CallRef`, playback position).
/// A reader is written against BORROWED bytes and reached either way. The pair taking an owned
/// [`WireEvent`] is what a caller who has one already uses; the pair taking a [`WireRef`] is what a
/// caller who is holding the bytes uses, and it is the one the framing on a live session takes,
/// because a copy per frame is fifty copies a second per direction for the length of a call.
pub trait DuplexReader {
    /// Client→server events (the net-new vocabulary): audio uplink, config, tool results.
    fn read_up_ref(&self, wire: WireRef<'_>, st: &mut DecodeState) -> Vec<IrClientEvent>;

    /// Server→client events, threading per-session decode state (barge-in position, `CallRef` map).
    fn read_down_ref(&self, wire: WireRef<'_>, st: &mut DecodeState) -> Vec<IrServerEvent>;

    /// The uplink read, over bytes the caller owns.
    fn read_up(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrClientEvent> {
        self.read_up_ref(WireRef::from(&evt), st)
    }

    /// The downlink read, over bytes the caller owns.
    fn read_down(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrServerEvent> {
        self.read_down_ref(WireRef::from(&evt), st)
    }
}

/// IR → WIRE. Re-frames the plane's neutral IR back onto a dialect's wire, in both directions.
///
/// The writers thread the SAME per-session [`DecodeState`] the readers do, for the one thing framing
/// cannot answer per-event: a dialect that delivers a tool call ATOMICALLY cannot frame a streamed
/// argument FRAGMENT, and the negotiated audio format is a session fact, not a frame field. Everything
/// else needed to frame is still carried in the IR (tool `call_id`, audio `media`), so the writers
/// remain re-entrant and shareable — the state is the session's, not the codec's.
pub trait DuplexWriter {
    /// Re-frame a client→server event onto the UPSTREAM dialect's wire, or `None` when the dialect has
    /// NO VERB for the concept.
    ///
    /// The uplink is where the cross-dialect map's drop rows live (an OpenAI `response.cancel` or
    /// `input_audio_buffer.clear` has no Gemini twin), and a dropped concept must produce NOTHING: a
    /// stand-in frame carrying none of the semantics is indistinguishable, upstream, from the concept
    /// having survived. `None` IS the warn — this crate links no logging surface, so the caller that
    /// sees the drop is the one positioned to report it.
    fn write_up(&self, ev: IrClientEvent, st: &mut DecodeState) -> Option<WireEvent>;

    /// Re-frame a server→client event onto the CLIENT dialect's wire, or `None` when this event is not
    /// a frame on its own — a streamed tool-argument fragment held for the atomic call it belongs to,
    /// or a call whose arguments never became readable. The downlink answers `None` for the same
    /// reason the uplink does: a frame that carries none of the concept reads, downstream, as the
    /// concept having survived.
    fn write_down(&self, ev: IrServerEvent, st: &mut DecodeState) -> Option<WireEvent>;
}

/// THE OpenAI Realtime GA DIALECT CODEC — the plane's sole dialect today (`codec: None`, one wire
/// format, `plane4-duplex-session.md`). A unit struct: all per-session state lives in [`DecodeState`], so the codec itself
/// is stateless and shareable.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiRealtimeCodec;

impl DuplexReader for OpenAiRealtimeCodec {
    fn read_up_ref(&self, wire: WireRef<'_>, st: &mut DecodeState) -> Vec<IrClientEvent> {
        let Some(v) = parse(wire) else {
            return Vec::new();
        };
        let ty = str_at(&v, "type");
        match ty {
            wire::SESSION_UPDATE => {
                let cfg = v
                    .get("session")
                    .map(|s| session_config_lenient(s, st))
                    .unwrap_or_default();
                if let Some(fmt) = cfg.output_audio_format {
                    st.set_output_format(fmt);
                }
                vec![IrClientEvent::Control(IrDuplexControl::SessionConfigure {
                    config: cfg,
                })]
            }
            wire::INPUT_AUDIO_APPEND => {
                let Some(media) = decode_audio(str_at(&v, "audio")) else {
                    return Vec::new();
                };
                vec![IrClientEvent::AudioFrame(IrAudioFrame {
                    dir: UpDown::Up,
                    seq: st.next_up_seq(),
                    media,
                    // The uplink append names no item — the item does not exist until the server
                    // makes one.
                    origin: IrAudioRef::default(),
                })]
            }
            wire::INPUT_AUDIO_COMMIT => {
                vec![IrClientEvent::Control(IrDuplexControl::InputAudioCommit)]
            }
            wire::INPUT_AUDIO_CLEAR => {
                vec![IrClientEvent::Control(IrDuplexControl::InputAudioClear)]
            }
            wire::ITEM_CREATE => {
                let item = v.get("item").cloned().unwrap_or(Value::Null);
                if str_at(&item, "type") == wire::ITEM_FN_CALL_OUTPUT {
                    let call_id = str_at(&item, "call_id");
                    let call_ref = st.ref_for_call_id(call_id);
                    let output = Bytes::from(str_at(&item, "output").to_owned().into_bytes());
                    // The dialect's own result item carries no tool name; the one the model announced
                    // is remembered per call id, for the dialects that require it.
                    let name = st.call_name(call_id).to_string();
                    vec![IrClientEvent::Tool(IrDuplexTool::CallResult {
                        call_ref,
                        call_id: call_id.to_string(),
                        name,
                        output,
                    })]
                } else {
                    vec![IrClientEvent::Control(IrDuplexControl::ItemCreate { item })]
                }
            }
            wire::ITEM_TRUNCATE => {
                vec![IrClientEvent::Control(IrDuplexControl::ItemTruncate {
                    item_ref: str_at(&v, "item_id").to_string(),
                    // A wire value that does not fit takes the field's documented default (`0`),
                    // the same answer an ABSENT `content_index` gets. Narrowing with `as` would
                    // instead hand back a different, perfectly valid index into different content.
                    content_index: u32::try_from(u64_at(&v, "content_index")).unwrap_or(0),
                    audio_played_ms: u64_at(&v, "audio_end_ms"),
                })]
            }
            wire::ITEM_DELETE => {
                vec![IrClientEvent::Control(IrDuplexControl::ItemDelete {
                    item_ref: str_at(&v, "item_id").to_string(),
                })]
            }
            wire::RESPONSE_CREATE => {
                let response = v.get("response").cloned();
                vec![IrClientEvent::Control(IrDuplexControl::ResponseCreate {
                    response,
                })]
            }
            wire::RESPONSE_CANCEL => {
                vec![IrClientEvent::Control(IrDuplexControl::ResponseCancel)]
            }
            _ => Vec::new(),
        }
    }

    fn read_down_ref(&self, wire: WireRef<'_>, st: &mut DecodeState) -> Vec<IrServerEvent> {
        let Some(v) = parse(wire) else {
            return Vec::new();
        };
        let ty = str_at(&v, "type");
        match ty {
            wire::SESSION_CREATED => {
                let session = v.get("session").cloned().unwrap_or(Value::Null);
                if let Some(fmt) = session
                    .get("output_audio_format")
                    .and_then(Value::as_str)
                    .and_then(AudioFormat::from_wire)
                {
                    st.set_output_format(fmt);
                }
                vec![IrServerEvent::SessionCreated { session }]
            }
            wire::SPEECH_STARTED => vec![IrServerEvent::SpeechStarted {
                audio_start_ms: u64_at(&v, "audio_start_ms"),
                item_id: str_at(&v, "item_id").to_string(),
            }],
            wire::SPEECH_STOPPED => vec![IrServerEvent::SpeechStopped {
                audio_end_ms: u64_at(&v, "audio_end_ms"),
                item_id: str_at(&v, "item_id").to_string(),
            }],
            wire::OUTPUT_AUDIO_DELTA | wire::OUTPUT_AUDIO_DELTA_LEGACY => {
                let Some(media) = decode_audio(str_at(&v, "delta")) else {
                    return Vec::new();
                };
                st.record_played(media.len() as u64);
                vec![IrServerEvent::AudioFrame(IrAudioFrame {
                    dir: UpDown::Down,
                    seq: st.next_down_seq(),
                    media,
                    origin: audio_ref_of(&v),
                })]
            }
            wire::OUTPUT_AUDIO_DONE | wire::OUTPUT_AUDIO_DONE_LEGACY => {
                // THE ITEM BOUNDARY: this item's audio is complete, so the played-out position starts
                // over. Carrying it forward would truncate the NEXT turn at the running session total.
                st.reset_playback();
                vec![IrServerEvent::AudioDone {
                    item_id: str_at(&v, "item_id").to_string(),
                }]
            }
            wire::OUTPUT_ITEM_ADDED => {
                let item = v.get("item").cloned().unwrap_or(Value::Null);
                if str_at(&item, "type") == wire::ITEM_FN_CALL {
                    let call_id = str_at(&item, "call_id");
                    let call_ref = st.ref_for_call_id(call_id);
                    let name = str_at(&item, "name").to_string();
                    // Remember the name for the RESULT leg: OpenAI's `function_call_output` carries
                    // none, and a Gemini `functionResponse` requires one.
                    st.remember_call_name(call_id, &name);
                    // A tool-call item is NOT the playing audio item's boundary — it can be added
                    // while that item is still playing — so the playback position stands.
                    vec![IrServerEvent::Tool(IrDuplexTool::CallOpen {
                        call_ref,
                        call_id: call_id.to_string(),
                        name,
                    })]
                } else {
                    // A new AUDIO-BEARING output item begins: its playback starts at zero, even if the
                    // previous item's `…audio.done` never arrived.
                    st.reset_playback();
                    Vec::new()
                }
            }
            wire::FN_ARGS_DELTA => {
                let call_id = str_at(&v, "call_id");
                let call_ref = st.ref_for_call_id(call_id);
                let json_delta = Bytes::from(str_at(&v, "delta").to_owned().into_bytes());
                vec![IrServerEvent::Tool(IrDuplexTool::CallArgs {
                    call_ref,
                    call_id: call_id.to_string(),
                    json_delta,
                })]
            }
            wire::FN_ARGS_DONE => {
                let call_id = str_at(&v, "call_id");
                let call_ref = st.ref_for_call_id(call_id);
                let mut out = Vec::new();
                // THE COMPLETE ARGUMENTS THE CLOSE STATES. This dialect repeats the whole argument
                // string on the done event; a dialect that delivers the call atomically needs exactly
                // that, and a peer whose deltas were never seen (a session joined mid-call) has
                // nothing else. Dropping it dispatched the call with no arguments at all.
                let arguments = str_at(&v, "arguments");
                if !arguments.is_empty() {
                    out.push(IrServerEvent::Tool(IrDuplexTool::CallArgs {
                        call_ref,
                        call_id: call_id.to_string(),
                        json_delta: Bytes::from(arguments.to_owned().into_bytes()),
                    }));
                }
                out.push(IrServerEvent::Tool(IrDuplexTool::CallClose {
                    call_ref,
                    call_id: call_id.to_string(),
                }));
                out
            }
            wire::RESPONSE_DONE => {
                let usage = v
                    .get("response")
                    .and_then(|r| r.get("usage"))
                    .map(extract_usage)
                    .unwrap_or_default();
                vec![IrServerEvent::Usage(usage)]
            }
            wire::RATE_LIMITS_UPDATED => vec![IrServerEvent::RateLimits],
            wire::ERROR => {
                let err = v.get("error").cloned().unwrap_or(Value::Null);
                vec![IrServerEvent::Error {
                    code: str_at(&err, "code").to_string(),
                    message: str_at(&err, "message").to_string(),
                }]
            }
            _ => Vec::new(),
        }
    }
}

/// Extract the split token classes from a `response.done.usage` object (`plane4-duplex-session.md` — audio vs text are
/// SEPARATE classes; extraction-only, never client-translated).
fn extract_usage(u: &Value) -> IrDuplexUsage {
    let ind = u.get("input_token_details");
    let outd = u.get("output_token_details");
    let field = |o: Option<&Value>, k: &str| {
        o.and_then(|x| x.get(k))
            .and_then(Value::as_u64)
            .unwrap_or_default()
    };
    IrDuplexUsage {
        audio_in: field(ind, "audio_tokens"),
        audio_out: field(outd, "audio_tokens"),
        text_in: field(ind, "text_tokens"),
        text_out: field(outd, "text_tokens"),
        cached: field(ind, "cached_tokens"),
    }
}

// ── writer ──────────────────────────────────────────────────────────────────────────────────────

impl DuplexWriter for OpenAiRealtimeCodec {
    /// The OpenAI Realtime dialect is the one every shared-IR concept was named from, so it frames
    /// EVERY client event — this writer never drops. It is also the dialect the shared IR's STREAMED
    /// tool call was named from, so it never accumulates: each fragment is already a frame here.
    fn write_up(&self, ev: IrClientEvent, _st: &mut DecodeState) -> Option<WireEvent> {
        let v = match ev {
            IrClientEvent::AudioFrame(f) => json!({
                "type": wire::INPUT_AUDIO_APPEND,
                "audio": encode_audio(&f.media),
            }),
            IrClientEvent::Control(c) => match c {
                IrDuplexControl::SessionConfigure { config } => json!({
                    "type": wire::SESSION_UPDATE,
                    "session": config,
                }),
                IrDuplexControl::ResponseCreate { response } => {
                    let mut o = json!({ "type": wire::RESPONSE_CREATE });
                    if let Some(r) = response {
                        o["response"] = r;
                    }
                    o
                }
                IrDuplexControl::ResponseCancel => json!({ "type": wire::RESPONSE_CANCEL }),
                IrDuplexControl::InputAudioCommit => json!({ "type": wire::INPUT_AUDIO_COMMIT }),
                IrDuplexControl::InputAudioClear => json!({ "type": wire::INPUT_AUDIO_CLEAR }),
                IrDuplexControl::ItemCreate { item } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": item,
                }),
                IrDuplexControl::ItemDelete { item_ref } => json!({
                    "type": wire::ITEM_DELETE,
                    "item_id": item_ref,
                }),
                IrDuplexControl::ItemTruncate {
                    item_ref,
                    content_index,
                    audio_played_ms,
                } => json!({
                    "type": wire::ITEM_TRUNCATE,
                    "item_id": item_ref,
                    "content_index": content_index,
                    "audio_end_ms": audio_played_ms,
                }),
            },
            IrClientEvent::Tool(t) => match t {
                IrDuplexTool::CallResult {
                    call_id, output, ..
                } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": {
                        "type": wire::ITEM_FN_CALL_OUTPUT,
                        "call_id": call_id,
                        "output": String::from_utf8_lossy(&output),
                    },
                }),
                // The other tool variants are server→client; a client-side writer never authors them,
                // but frame them symmetrically rather than panic.
                IrDuplexTool::CallOpen { call_id, name, .. } => json!({
                    "type": wire::OUTPUT_ITEM_ADDED,
                    "item": { "type": wire::ITEM_FN_CALL, "call_id": call_id, "name": name },
                }),
                IrDuplexTool::CallArgs {
                    call_id,
                    json_delta,
                    ..
                } => json!({
                    "type": wire::FN_ARGS_DELTA,
                    "call_id": call_id,
                    "delta": String::from_utf8_lossy(&json_delta),
                }),
                IrDuplexTool::CallClose { call_id, .. } => json!({
                    "type": wire::FN_ARGS_DONE,
                    "call_id": call_id,
                }),
            },
        };
        Some(wire_of(&v))
    }

    /// Every server event is a frame in this dialect — the streamed shapes ARE its own — so this
    /// writer never answers `None`.
    fn write_down(&self, ev: IrServerEvent, _st: &mut DecodeState) -> Option<WireEvent> {
        let v = match ev {
            IrServerEvent::SessionCreated { session } => json!({
                "type": wire::SESSION_CREATED,
                "session": session,
            }),
            IrServerEvent::Tool(t) => match t {
                IrDuplexTool::CallOpen { call_id, name, .. } => json!({
                    "type": wire::OUTPUT_ITEM_ADDED,
                    "item": { "type": wire::ITEM_FN_CALL, "call_id": call_id, "name": name },
                }),
                IrDuplexTool::CallArgs {
                    call_id,
                    json_delta,
                    ..
                } => json!({
                    "type": wire::FN_ARGS_DELTA,
                    "call_id": call_id,
                    "delta": String::from_utf8_lossy(&json_delta),
                }),
                IrDuplexTool::CallClose { call_id, .. } => json!({
                    "type": wire::FN_ARGS_DONE,
                    "call_id": call_id,
                }),
                IrDuplexTool::CallResult {
                    call_id, output, ..
                } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": {
                        "type": wire::ITEM_FN_CALL_OUTPUT,
                        "call_id": call_id,
                        "output": String::from_utf8_lossy(&output),
                    },
                }),
            },
            IrServerEvent::SpeechStarted {
                audio_start_ms,
                item_id,
            } => json!({
                "type": wire::SPEECH_STARTED,
                "audio_start_ms": audio_start_ms,
                "item_id": item_id,
            }),
            IrServerEvent::SpeechStopped {
                audio_end_ms,
                item_id,
            } => json!({
                "type": wire::SPEECH_STOPPED,
                "audio_end_ms": audio_end_ms,
                "item_id": item_id,
            }),
            IrServerEvent::AudioFrame(f) => {
                // The item correlation the source dialect named rides back out — the client relays
                // through this writer even same-dialect, and a client that cannot name the item it is
                // hearing cannot truncate it when the user interrupts. What no source named is not
                // invented here.
                let mut o = json!({
                    "type": wire::OUTPUT_AUDIO_DELTA,
                    "delta": encode_audio(&f.media),
                });
                if let Some(id) = &f.origin.response_id {
                    o["response_id"] = json!(id);
                }
                if let Some(id) = &f.origin.item_id {
                    o["item_id"] = json!(id);
                }
                if let Some(i) = f.origin.output_index {
                    o["output_index"] = json!(i);
                }
                if let Some(i) = f.origin.content_index {
                    o["content_index"] = json!(i);
                }
                o
            }
            IrServerEvent::AudioDone { item_id } => json!({
                "type": wire::OUTPUT_AUDIO_DONE,
                "item_id": item_id,
            }),
            IrServerEvent::Usage(u) => json!({
                "type": wire::RESPONSE_DONE,
                "response": { "usage": usage_to_wire(&u) },
            }),
            IrServerEvent::RateLimits => json!({
                "type": wire::RATE_LIMITS_UPDATED,
                "rate_limits": [],
            }),
            IrServerEvent::Error { code, message } => json!({
                "type": wire::ERROR,
                "error": { "code": code, "message": message },
            }),
        };
        Some(wire_of(&v))
    }
}

/// Re-frame the extracted token classes back onto a `usage` object (the inverse of [`extract_usage`]).
///
/// The sums SATURATE, matching `IrDuplexUsage::to_billing_usage`'s stated discipline ("a runaway
/// turn pins the count, never wraps small"): these counts came off an upstream `usage` object, and
/// a wrapped total is a small, believable number that is false.
fn usage_to_wire(u: &IrDuplexUsage) -> Value {
    json!({
        "total_tokens": u.audio_in
            .saturating_add(u.audio_out)
            .saturating_add(u.text_in)
            .saturating_add(u.text_out),
        "input_token_details": {
            "audio_tokens": u.audio_in,
            "text_tokens": u.text_in,
            "cached_tokens": u.cached,
        },
        "output_token_details": {
            "audio_tokens": u.audio_out,
            "text_tokens": u.text_out,
        },
    })
}

/// THE SECOND DIALECT — Gemini Live (`BidiGenerateContent`). Its codec maps the Gemini wire to/from
/// the SAME shared IR this file's [`OpenAiRealtimeCodec`] targets; earning the superset IR is exactly
/// what a second dialect does (`plane4-duplex-session.md`). See [`gemini::GeminiLiveCodec`].
pub mod gemini;

#[cfg(test)]
mod tests;
