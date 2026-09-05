//! The plane's per-connection codec state — the one place cross-frame state may live.
//!
//! `busbar_contract::plane::PlaneSessionState` is a type-erased `Box<dyn Any + Send>` the kernel
//! holds one half of per connection: one for the client, one more per upstream a session dials. This
//! module is the concrete type this plane wraps in it.

use busbar_contract::ids::{CorrelationRef, CorrelationValue};
use busbar_voice::ir::{DecodeState, IrClientEvent};

use crate::claims::Dialect;

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
/// Reset to zero every time a turn closes (see `crate::plane`'s `decode_response`), because these
/// are the quantities [`busbar_voice::ir::usage::IrDuplexUsage`] does not carry and this plane must
/// derive itself: `audio_seconds_in` from the byte counts of ingress audio frames, `tool_calls` from
/// counting `IrDuplexTool::CallOpen` events as they are decoded.
#[derive(Debug, Clone, Copy, Default)]
pub struct TurnCounters {
    /// Milliseconds of ingress audio admitted since the turn opened.
    pub audio_ms_in: u64,
    /// Tool calls the upstream opened since the turn opened.
    pub tool_calls: u64,
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
