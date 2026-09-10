// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READER / WRITER CONTRACT — the bidirectional analog of the LLM plane's
//! `ProtocolReader`/`ProtocolWriter`. Design `plane4-duplex-session.md`.
//!
//! The single design delta vs the LLM `ProtocolReader` is that Plane 4 needs a client→server event
//! vocabulary, so the plane defines TWO DIRECTIONS over one wire schema (the MCP "one reader, one
//! writer, both directions" discipline).
//!
//! This module holds what EVERY dialect's reader/writer shares and no dialect's own vocabulary: the
//! two traits, the opaque wire frame, the per-session [`DecodeState`], and the JSON/base64 helpers
//! a hand-mapping reader is written over. A dialect parses its frame to a `serde_json::Value` and
//! hand-maps it (serde-derive is reserved for the [`crate::ir::config::SessionConfig`] object);
//! one wire event maps to 0..n IR events; a malformed / unrecognized frame yields an EMPTY vec (the
//! streaming-decode discipline — degrade, don't error), except a dialect's own error event, which
//! surfaces as [`IrServerEvent::Error`]. The readers themselves live with their dialects.
//!
//! STATE THREADING: unlike the LLM reader (whose request path is stateless whole-JSON), BOTH
//! directions here thread [`DecodeState`] — uplink needs the monotonic frame `seq` and `CallRef`
//! minting just as downlink does. The WRITERS thread the same state, for the one thing framing cannot
//! answer from a single event: a dialect that delivers a tool call ATOMICALLY has nothing to frame
//! from a streamed argument FRAGMENT, so the fragments accumulate on the session and the call is
//! framed whole at its close. Everything else a writer needs is still carried in the IR (each tool
//! variant carries its raw `call_id`, so re-framing a `function_call_output` invents nothing).

use crate::ir::config::SessionConfig;
use crate::ir::event::{IrClientEvent, IrServerEvent};
use crate::ir::media::MediaFormat;
use crate::ir::tool::CallRef;
use bytes::Bytes;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};

/// ONE WIRE EVENT — the opaque, dialect-shaped message a reader parses / a writer produces: the JSON
/// bytes of one dialect wire event. Kept deliberately opaque so the reader/writer own all framing
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
/// one handle — not a ledger, and nothing removes from it within a session (an item removal
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
    /// requires and another dialect's result item does not carry, remembered from the originating
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
    /// The order [`DecodeState::call_args`] took its entries in, oldest first, so that table is
    /// bounded by the same ceiling its sibling `call_ids` is.
    ///
    /// It needs its own order rather than borrowing `call_id_order`, because the two tables are
    /// keyed differently and are emptied at different moments: an id leaves `call_ids` when it is
    /// evicted, an accumulation leaves `call_args` when the call closes, and a call whose close
    /// never arrives leaves it never. Without this, an upstream that opens calls and never closes
    /// them grows one held accumulation per call for the life of the session, and an id evicted
    /// from `call_ids` and then sighted again mints a fresh handle — orphaning the entry the old
    /// handle keyed, which nothing can ever reach to remove.
    call_args_order: VecDeque<CallRef>,
    /// Downlink audio bytes RELAYED for the CURRENT item — reset when the item ends (its audio is
    /// done, a new audio-bearing item begins) and on a barge-in flush.
    played_bytes: u64,
    /// The latest clock reading the runtime has fed for the current item (ms of playback elapsed),
    /// `None` while nobody feeds one. This crate owns no time source; it bounds, never invents.
    played_clock_ms: Option<u64>,
    /// Negotiated OUTPUT format the truncate math measures against.
    output_fmt: MediaFormat,
    /// Negotiated INPUT format — what the bytes the CLIENT sends are in.
    ///
    /// It is a separate field from `output_fmt` because the two directions of a session are
    /// negotiated separately and need not agree: a dialect may take one format up and synthesize
    /// another down. A writer that framed the uplink from `output_fmt` would label the client's own
    /// audio with the model's synthesis format, which is a description of bytes nobody sent.
    input_fmt: MediaFormat,
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
            call_args_order: VecDeque::new(),
            played_bytes: 0,
            played_clock_ms: None,
            output_fmt: MediaFormat::Pcm16,
            input_fmt: MediaFormat::Pcm16,
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

    /// REMEMBER the tool name the model announced for a `call_id`. A dialect whose result item
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
    /// a tool call's arguments (one dialect's own shape); a dialect that delivers the call
    /// ATOMICALLY has nothing to frame from a fragment, so the pieces are held here until the call
    /// closes. Past [`MAX_TOOL_ARG_BYTES`] the accumulation is abandoned and stays abandoned.
    ///
    /// The NUMBER of accumulations is bounded by [`MAX_TRACKED_CALL_IDS`] too, because the size of
    /// each one alone is no bound on the table: only a call that CLOSES gives its entry back, and
    /// an upstream is under no obligation to close one. Past the ceiling the oldest accumulation is
    /// given up, exactly as the oldest call id is.
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
        if !self.call_args.contains_key(&call) {
            self.call_args_order.push_back(call);
            while self.call_args_order.len() > MAX_TRACKED_CALL_IDS {
                if let Some(oldest) = self.call_args_order.pop_front() {
                    self.call_args.remove(&oldest);
                }
            }
        }
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
        // Out of the order too, not only out of the table: a closed call that stayed in the order
        // would spend one of the ceiling's places and evict a LIVE accumulation in its stead, which
        // is the one loss this ceiling must not cause.
        self.call_args_order.retain(|held| *held != call);
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

    /// The negotiated output format (defaults to `pcm16` until a session patch sets it).
    #[must_use]
    pub fn output_format(&self) -> MediaFormat {
        self.output_fmt
    }

    /// Adopt the negotiated output media format (from a session patch, or the open the server echoed).
    pub fn set_output_format(&mut self, fmt: MediaFormat) {
        self.output_fmt = fmt;
    }

    /// The negotiated INPUT format — what the client's uplink bytes are in. Defaults to `pcm16`
    /// until a session config states otherwise, which is what an unstated input format means on
    /// every dialect this plane speaks.
    #[must_use]
    pub fn input_format(&self) -> MediaFormat {
        self.input_fmt
    }

    /// Adopt the negotiated input audio format (from a session config that states one).
    pub fn set_input_format(&mut self, fmt: MediaFormat) {
        self.input_fmt = fmt;
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

    /// FLUSH the queued/played downlink media when client activity starts (barge-in): returns the just-heard
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

/// Parse one wire frame as JSON, or `None` for bytes that are not a JSON document.
pub fn parse(wire: WireRef<'_>) -> Option<Value> {
    serde_json::from_slice::<Value>(wire.0).ok()
}

/// Serialize one JSON document as the wire frame a writer hands back.
pub fn wire_of(v: &Value) -> WireEvent {
    // serde_json::to_vec on an owned Value cannot fail.
    WireEvent(Bytes::from(serde_json::to_vec(v).unwrap_or_default()))
}

/// The string at `key`, or the empty string when absent or not a string.
pub fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// base64-decode a wire audio string to opaque media bytes (the identity IR is the decoded bytes).
///
/// `None` on a payload that is not base64, and every read path must DROP that frame rather than
/// substitute an empty one. The callee returns `Option` deliberately — it refuses even a lone
/// trailing sextet "rather than silently drop it, honoring the fail-loud contract" — and an empty
/// frame relayed and metered in place of a refusal is indistinguishable from a caller who said
/// nothing, which is the one confusion a voice plane cannot afford. The Twilio grammar in this same
/// crate already answers this way (`BadPayload`, never an empty payload).
pub fn decode_media(b64: &str) -> Option<Bytes> {
    busbar_substrate_values::media::base64_decode(b64)
}

/// base64-encode opaque media bytes back to a wire audio string.
pub fn encode_media(media: &Bytes) -> String {
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
/// Unknown KEYS are not drops: `SessionConfig` ignores them by design (a partial patch names only
/// what it changes), so they never reach this path.
pub fn session_config_lenient(session: &Value, st: &mut DecodeState) -> SessionConfig {
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
    /// The uplink is where the cross-dialect map's drop rows live (one dialect's turn-cancel or
    /// uplink-clear has no twin in another), and a dropped concept must produce NOTHING: a
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

/// A DIALECT that still lives beside the IR — Gemini Live (`BidiGenerateContent`). Its codec maps that
/// wire to/from the SAME shared IR every dialect targets; earning the superset IR is exactly what a
/// second dialect does (`plane4-duplex-session.md`). See [`gemini::GeminiLiveCodec`]. Its own line
/// moves it out beside the reader that already went, into the plane's dialect module.
pub mod gemini;

#[cfg(test)]
mod tests;
