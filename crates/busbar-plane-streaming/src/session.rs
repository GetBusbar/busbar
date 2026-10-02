//! The plane's per-turn bookkeeping: the counters a turn keeps that no usage report carries, and a
//! closed turn's counts per declared class.

use crate::codec::ir::{AudioFormat, IrDuplexUsage};
use busbar_contract::ids::MeterClassId;

use crate::meta;

/// The plane's own bookkeeping for the current, still-open turn.
///
/// Taken (and so reset to zero) every time a turn is ANSWERED — a usage report, an upstream error or
/// a carrier `stop`, each of which states them on its own facts — and CARRIED, not reset, when a
/// barge-in supersedes the open turn, because a superseded turn is never answered and nothing else
/// would ever state what it served. These are the quantities [`crate::codec::ir::usage::IrDuplexUsage`] does not carry and this plane must
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
