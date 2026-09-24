//! The plane's per-connection codec state — the one place cross-frame state may live.
//!
//! `busbar_contract::plane::PlaneSessionState` is a type-erased `Box<dyn Any + Send>` the kernel
//! holds one half of per connection: one for the client, one more per upstream a session dials. This
//! module is the concrete type this plane wraps in it.

use busbar_contract::ids::{CorrelationRef, CorrelationValue, MeterClassId};
use busbar_voice_codec::ir::{AudioFormat, DecodeState, IrClientEvent, IrDuplexUsage};

use crate::claims::Dialect;
use crate::meta;

/// One pending, already-decoded IR event, stashed across the two-call boundary a step pair leaves
/// open.
///
/// `decode_ingress`/`encode_ingress_frame` are two separate calls the kernel makes about the SAME
/// inbound frame — the first says what it means, the second says what to send onward. The codecs'
/// `read_up` method is stateful (it advances the per-session frame sequence), so calling it a second
/// time to re-derive what the first call already decoded would double-count that state. Stashing the
/// already-decoded event here and consuming it once is what keeps the codec state's counters correct
/// across the split.
///
/// There is ONE arm, and there was only ever one reason for a second: the downlink split needed a
/// stash because a later step could not see what decode had determined. It can now — a unit carries
/// its draft's facts — and `encode_response` renders the bytes `decode_response` already produced,
/// so the egress arm existed for a problem that is no longer the shape of the surface.
#[derive(Debug, Clone)]
pub enum Pending {
    /// A client→server event decoded at `decode_ingress`, consumed at `encode_ingress_frame`.
    Ingress(IrClientEvent),
}

/// The plane's own bookkeeping for the current, still-open turn.
///
/// Taken (and so reset to zero) every time a turn is ANSWERED — a usage report, an upstream error or
/// a carrier `stop`, each of which states them on its own facts — and CARRIED, not reset, when a
/// barge-in supersedes the open turn, because a superseded turn is never answered and nothing else
/// would ever state what it served. These are the quantities [`busbar_voice_codec::ir::usage::IrDuplexUsage`] does not carry and this plane must
/// derive itself: `audio_seconds_in` from the byte counts of ingress audio frames, `tool_calls` from
/// counting `IrDuplexTool::CallOpen` events as they are decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnCounters {
    /// Milliseconds of ingress audio admitted since the turn opened.
    pub audio_ms_in: u64,
    /// Tool calls the upstream opened since the turn opened.
    pub tool_calls: u64,
}

impl TurnCounters {
    /// Count `bytes` of admitted uplink audio, read under `format`.
    pub fn admit_audio(&mut self, format: AudioFormat, bytes: usize) {
        let ms = format.bytes_to_ms(bytes as u64);
        self.audio_ms_in = self.audio_ms_in.saturating_add(ms);
    }

    /// Count one tool call the upstream opened.
    pub fn open_tool_call(&mut self) {
        self.tool_calls = self.tool_calls.saturating_add(1);
    }

    /// Whether nothing has been counted since the turn opened.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A CLOSED TURN'S RAW COUNTS PER DECLARED CLASS — the lines this plane's `meter` emits for a turn
/// whose answer reported `usage` (`None` for an ending that reported none: an upstream error, a
/// carrier stop, a session torn down mid-turn) and whose own bookkeeping is `counters`. Each class is
/// the declared symbol, milliseconds are converted to the seconds `audio_seconds_in` is declared in
/// through [`meta::audio_seconds_in`], and a zero count is omitted (a zero and an absent line settle
/// alike). Counts only: no rate is read and no figure results.
///
/// This is the plane's one reading of a turn for a host that drives the session itself rather than
/// through the unit loop; `tests::codec` holds it to `meter` over the same turn.
#[must_use]
pub fn class_counts(
    usage: Option<&IrDuplexUsage>,
    counters: TurnCounters,
) -> Vec<(MeterClassId, u64)> {
    let reported = usage.copied().unwrap_or_default();
    [
        (meta::CLASS_AUDIO_TOKENS_IN, reported.audio_in),
        (meta::CLASS_AUDIO_TOKENS_OUT, reported.audio_out),
        (meta::CLASS_TEXT_TOKENS_IN, reported.text_in),
        (meta::CLASS_TEXT_TOKENS_OUT, reported.text_out),
        (meta::CLASS_CACHED_TOKENS, reported.cached),
        (
            meta::CLASS_AUDIO_SECONDS_IN,
            meta::audio_seconds_in(counters.audio_ms_in),
        ),
        (meta::CLASS_TOOL_CALLS, counters.tool_calls),
    ]
    .into_iter()
    .filter(|(_, n)| *n != 0)
    .collect()
}

/// The codec state one connection half of a voice session holds.
///
/// One value per [`busbar_contract::plane::PlaneSessionState`] half: the client half opened by
/// this plane's `SessionPlane::open_session`, one more per upstream opened by its
/// `open_upstream` (see `crate::plane`). Everything here is exactly what a plane may hold across
/// frames and nothing else — no connection, no clock, no credential.
#[derive(Debug, Default)]
pub struct VoiceSessionState {
    /// The dialect this half of the connection speaks. `None` only in the sliver of time before the
    /// first frame has named one; every method that needs it treats an absent dialect as a decode
    /// failure rather than guessing.
    pub dialect: Option<Dialect>,
    /// The shared duplex codec's per-session state (frame sequencing, the `CallRef` correlation
    /// table, the negotiated output format, and the barge-in playback-position bookkeeping). Reused
    /// for both codec-backed dialects (`OpenAI Realtime`, `Gemini Live`): the shared IR is what
    /// makes one state shape valid for either.
    pub codec: DecodeState,
    /// Whether the current turn is open (a unit has been opened and not yet closed).
    pub turn_open: bool,
    /// The correlation the currently open turn answers frames under, once one has been minted.
    pub turn_correlation: Option<CorrelationRef<'static>>,
    /// The next turn identity to mint. Monotonic per session; a duplex session opens and closes many
    /// turns in sequence, and each needs a correlation value distinct from the last so a stray late
    /// frame from a just-closed turn cannot be mistaken for one belonging to the next.
    pub next_turn_id: u64,
    /// This turn's own derived counters (see [`TurnCounters`]).
    pub turn: TurnCounters,
    /// Twilio's `streamSid` for this connection, bound at the `start` event and checked against
    /// every later `media` frame — the forgery/replay guard the architecture note for this dialect
    /// names.
    pub twilio_stream_sid: Option<String>,
    /// The one already-decoded event a two-call step pair is carrying across (see [`Pending`]).
    pub pending: Option<Pending>,
    /// The buffer one downlink audio frame is rendered into, held across frames.
    ///
    /// The renderer this crate carries for the carrier dialect clears and refills a buffer the
    /// caller owns, and its committed cost is stated for a buffer that has already carried a frame
    /// — which is the only shape that costs nothing. A call sends fifty downlink frames a second,
    /// so a fresh vector per frame is fifty allocations a second the renderer was written to
    /// remove. This is where the one buffer lives.
    pub render_buf: Vec<u8>,
}

impl VoiceSessionState {
    /// A fresh state already bound to a known dialect — what a session's client half opens with,
    /// once the claim that matched the connection is known.
    #[must_use]
    pub fn for_dialect(dialect: Dialect) -> Self {
        Self {
            dialect: Some(dialect),
            ..Self::default()
        }
    }

    /// The fact key a turn's correlation is minted under. Declared once here so the mint site and
    /// every read site agree.
    pub const TURN_FACT_KEY: &'static str = "turn_id";

    /// Open a fresh turn, minting the correlation later frames must carry to relay onto it.
    pub fn open_turn(&mut self) -> CorrelationRef<'static> {
        let id = self.next_turn_id;
        self.next_turn_id += 1;
        let correlation = CorrelationRef {
            fact_key: Self::TURN_FACT_KEY,
            value: CorrelationValue::Num(id),
        };
        self.turn_open = true;
        self.turn_correlation = Some(correlation);
        correlation
    }

    /// Close the current turn, snapshotting and resetting its counters.
    ///
    /// Returns the counters as they stood at close, which is what feeds the response facts the
    /// `meter` step reads back out (`crate::plane`'s `decode_response`/`meter`).
    pub fn close_turn(&mut self) -> TurnCounters {
        self.turn_open = false;
        self.turn_correlation = None;
        core::mem::take(&mut self.turn)
    }
}
