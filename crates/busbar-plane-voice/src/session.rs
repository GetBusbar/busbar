//! The plane's per-connection codec state — the one place cross-frame state may live.
//!
//! `busbar_contract::plane::PlaneSessionState` is a type-erased `Box<dyn Any + Send>` the kernel
//! holds one half of per connection: one for the client, one more per upstream a session dials. This
//! module is the concrete type this plane wraps in it.

use busbar_contract::ids::{CorrelationRef, CorrelationValue};
use busbar_voice_codec::ir::DecodeState;

use crate::claims::Dialect;

/// The plane's own bookkeeping for the current, still-open turn.
///
/// Reset to zero every time a turn closes (see `crate::plane`'s `decode_response`), because these
/// are the quantities [`busbar_voice_codec::ir::usage::IrDuplexUsage`] does not carry and this plane must
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
    /// The turn the frames arriving at this half's relay seam belong to, as the unit that carries
    /// them names it.
    ///
    /// Only ever set on a DESTINATION half. A turn's identity is minted where the client's frames
    /// arrive ([`Self::open_turn`], on the client half) and the counters that turn is billed on are
    /// accumulated where they are relayed (on this one), so without this the two halves knew
    /// different halves of the same turn and neither could name it whole.
    pub relayed_turn: Option<u64>,
    /// An INTERRUPTED turn's facts, held until the upstream's own report for its response arrives.
    ///
    /// A barge-in leaves two turns alive at once: the one the caller cut off, whose response the
    /// upstream is still winding down, and the one that took over. The cut turn's seconds and tool
    /// calls are already spent and are still owed; they wait here, under the turn they belong to,
    /// rather than being zeroed at the cut (nothing downstream can recover a metered quantity a
    /// plane dropped) or left to be reported as if they were the new turn's.
    pub superseded_turn: Option<(u64, TurnCounters)>,
    /// The turn the response now streaming down belongs to, bound at its first frame.
    ///
    /// Read at the response's own terminal. Reading the turn that is open INSTEAD meant an
    /// interrupted response's `response.done` ended the turn that replaced it — and every later turn
    /// boundary in the session was displaced by one.
    pub response_turn: Option<u64>,
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

    /// The turn identity a correlation carries, where it carries one of this plane's own.
    #[must_use]
    pub fn turn_id_of(correlation: CorrelationRef<'_>) -> Option<u64> {
        match correlation.value {
            CorrelationValue::Num(id) if correlation.fact_key == Self::TURN_FACT_KEY => Some(id),
            _ => None,
        }
    }

    /// The correlation a turn identity names, rebuilt from the identity alone.
    #[must_use]
    pub fn turn_correlation_of(id: u64) -> CorrelationRef<'static> {
        CorrelationRef {
            fact_key: Self::TURN_FACT_KEY,
            value: CorrelationValue::Num(id),
        }
    }

    /// Bind the turn the frames now reaching this half's relay seam belong to.
    ///
    /// When the identity CHANGES, the turn that was relaying here has ended — cut off by a barge-in,
    /// in the one case that changes it mid-response. Its counters are moved aside under its own
    /// identity ([`Self::superseded_turn`]) rather than continuing to accumulate under the turn that
    /// replaced it, which is how one caller's twenty seconds ended up on the next caller's turn.
    pub fn bind_relayed_turn(&mut self, id: u64) {
        if self.relayed_turn == Some(id) {
            return;
        }
        if let Some(previous) = self.relayed_turn {
            let counters = core::mem::take(&mut self.turn);
            self.set_aside(previous, counters);
        }
        self.relayed_turn = Some(id);
    }

    /// Hold one turn's facts until its own report arrives.
    ///
    /// ONE slot, because a cut response is wound down by the upstream promptly and a second cut
    /// before the first report is not a sequence a duplex dialect produces. Where it happened
    /// anyway, the older turn's facts are FOLDED into the record rather than dropped: mis-attributed
    /// between two adjacent turns of the same session is recoverable from the audit trail, and a
    /// quantity a plane silently dropped is recoverable from nowhere.
    fn set_aside(&mut self, id: u64, counters: TurnCounters) {
        match self.superseded_turn.as_mut() {
            Some((held, held_counters)) => {
                held_counters.audio_ms_in = held_counters
                    .audio_ms_in
                    .saturating_add(counters.audio_ms_in);
                held_counters.tool_calls =
                    held_counters.tool_calls.saturating_add(counters.tool_calls);
                *held = id;
            }
            None => self.superseded_turn = Some((id, counters)),
        }
    }

    /// End the turn a barge-in cut off, setting its facts aside under its own identity.
    ///
    /// The turn that took over opens immediately after; the cut one's report arrives later, when
    /// the upstream finishes winding down the response the caller talked over. Between the two,
    /// this is where the cut turn's seconds and tool calls live. Zeroing them at the cut — which is
    /// what a bare `close_turn` does, since it is a `take` — handed those seconds back for free.
    pub fn supersede_turn(&mut self) {
        let cut = self.turn_correlation.and_then(Self::turn_id_of);
        let counters = self.close_turn();
        if let Some(id) = cut {
            self.set_aside(id, counters);
        }
    }

    /// The turn the response now streaming belongs to, bound at its first downlink frame.
    pub fn response_turn(&mut self) -> Option<u64> {
        if self.response_turn.is_none() {
            self.response_turn = self
                .relayed_turn
                .or_else(|| self.turn_correlation.and_then(Self::turn_id_of));
        }
        self.response_turn
    }

    /// Close the response now streaming, handing back the identity and the facts of the TURN it
    /// belongs to.
    ///
    /// A response that was CUT OFF finishes after the turn that replaced it has already opened. Its
    /// terminal must end the turn it belongs to and carry that turn's counters; ending the open turn
    /// with the open turn's counters instead billed the cut turn at zero and displaced every later
    /// turn boundary in the session by one.
    pub fn close_response(&mut self) -> (Option<u64>, TurnCounters) {
        let id = self.response_turn.take().or(self.relayed_turn);
        if let Some((superseded, counters)) = self.superseded_turn.take() {
            if Some(superseded) == id {
                // The cut turn's own report. The turn that replaced it stays open, and its counters
                // — which have been accumulating since the cut — stay where they are.
                return (id, counters);
            }
            self.superseded_turn = Some((superseded, counters));
        }
        self.relayed_turn = None;
        (id, self.close_turn())
    }
}
