//! The plane's per-turn bookkeeping: the counters a turn keeps that no usage report carries, and a
//! closed turn's counts per declared class.

use crate::codec::ir::{AudioFormat, IrDuplexUsage};
use busbar_contract::ids::MeterClassId;

use crate::meta;

/// The plane's own bookkeeping for the current, still-open turn.
///
/// Closed (its counts reset to zero) every time a turn is ANSWERED — a usage report, an upstream error or
/// a carrier `stop`, each of which states them on its own facts — and CARRIED, not reset, when a
/// barge-in supersedes the open turn, because a superseded turn is never answered and nothing else
/// would ever state what it served. These are the quantities [`crate::codec::ir::usage::IrDuplexUsage`] does not carry and this plane must
/// derive itself: `audio_seconds_in` from the byte counts of ingress audio frames, `tool_calls` from
/// counting `IrDuplexTool::CallOpen` events as they are decoded.
///
/// **The session is one unit, so its uplink audio is converted ONCE (MONEY-AUDIT STR-2).** Two
/// positions are carried from turn to turn rather than reset with the turn's counts: the bytes of
/// admitted audio short of a whole millisecond (a frame's bytes do not divide into milliseconds
/// evenly, and flooring each frame lost the remainder every frame), and the milliseconds the
/// session's earlier turns already settled. A closed turn bills the DIFFERENCE of the session's
/// cumulative seconds figure ([`class_counts`]), so the sum over every turn is the session's total
/// milliseconds converted once — rounding each turn up on its own billed 20 turns of 1050 ms as 40 s
/// of audio rather than 21 s. The byte remainder is counted under the format the session admits
/// audio in, which is one format for the life of a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnCounters {
    /// Milliseconds of ingress audio admitted since the turn opened.
    pub audio_ms_in: u64,
    /// Tool calls the upstream opened since the turn opened.
    pub tool_calls: u64,
    /// Milliseconds of ingress audio the session's closed turns settled before this one (carried).
    audio_ms_before: u64,
    /// Bytes of admitted ingress audio short of a whole millisecond (carried).
    audio_bytes_rem: u64,
}

impl TurnCounters {
    /// Count `bytes` of admitted uplink audio, read under `format`. The part of a millisecond the
    /// bytes leave over is carried onto the next frame, never floored away.
    pub fn admit_audio(&mut self, format: AudioFormat, bytes: usize) {
        let total = self.audio_bytes_rem.saturating_add(bytes as u64);
        self.audio_ms_in = self.audio_ms_in.saturating_add(format.bytes_to_ms(total));
        self.audio_bytes_rem = total % format.bytes_per_ms();
    }

    /// Count one tool call the upstream opened.
    pub fn open_tool_call(&mut self) {
        self.tool_calls = self.tool_calls.saturating_add(1);
    }

    /// Whether nothing has been counted since the turn opened.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.audio_ms_in == 0 && self.tool_calls == 0
    }

    /// Close the turn: answer its counters as they stood, and leave in their place the next turn's,
    /// zero apart from the session's carried audio position (the settled milliseconds now include
    /// this turn's, and the sub-millisecond remainder rides on).
    pub fn close(&mut self) -> TurnCounters {
        let closed = *self;
        *self = TurnCounters {
            audio_ms_before: closed.audio_ms_before.saturating_add(closed.audio_ms_in),
            audio_bytes_rem: closed.audio_bytes_rem,
            ..TurnCounters::default()
        };
        closed
    }

    /// The `audio_seconds_in` this turn bills: the session's cumulative seconds after it less the
    /// cumulative seconds before it, each converted through [`meta::audio_seconds_in`] — so a
    /// session's turns sum to its total milliseconds converted once.
    #[must_use]
    pub fn audio_seconds_in(&self) -> u64 {
        let after = self.audio_ms_before.saturating_add(self.audio_ms_in);
        meta::audio_seconds_in(after).saturating_sub(meta::audio_seconds_in(self.audio_ms_before))
    }
}

/// A CLOSED TURN'S RAW COUNTS PER DECLARED CLASS — the lines this plane's `meter` emits for a turn
/// whose answer reported `usage` (`None` for an ending that reported none: an upstream error, a
/// carrier stop, a session torn down mid-turn) and whose own bookkeeping is `counters`. Each class is
/// the declared symbol, milliseconds are converted to the seconds `audio_seconds_in` is declared in
/// through [`TurnCounters::audio_seconds_in`] (the session's cumulative figure, converted once), and
/// a zero count is omitted (a zero and an absent line settle
/// alike). Counts only: no rate is read and no figure results.
///
/// This is the plane's one reading of a turn for a host that drives the session itself rather than
/// through the unit loop.
#[must_use]
pub fn class_counts(
    usage: Option<&IrDuplexUsage>,
    counters: TurnCounters,
) -> Vec<(MeterClassId, u64)> {
    let reported = usage.copied().unwrap_or_default();
    // `cached_tokens` is NOT ledgered here: it is a subset of the input token classes above, not a
    // billable class beside them (architect ruling #71 — see `meta::CLASS_CACHED_TOKENS`'s doc).
    // Pricing it too would double-bill the same cached input.
    [
        (meta::CLASS_AUDIO_TOKENS_IN, reported.audio_in),
        (meta::CLASS_AUDIO_TOKENS_OUT, reported.audio_out),
        (meta::CLASS_TEXT_TOKENS_IN, reported.text_in),
        (meta::CLASS_TEXT_TOKENS_OUT, reported.text_out),
        (meta::CLASS_AUDIO_SECONDS_IN, counters.audio_seconds_in()),
        (meta::CLASS_TOOL_CALLS, counters.tool_calls),
    ]
    .into_iter()
    .filter(|(_, n)| *n != 0)
    .collect()
}
