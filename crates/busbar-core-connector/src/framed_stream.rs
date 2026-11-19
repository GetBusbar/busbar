// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FRAMED STREAMS: the MIN-3 transport session and the per-stream stall holds it keeps.

// The MIN-3 framing: one `TransportSession` per connection, driven by the task that owns it (IF §8.7, §13).
pub mod session;

/// The `limits.stream_stall_ms` default (IF §12.22; transport instances only).
pub const STREAM_STALL_DEFAULT_MS: u32 = 60_000;
/// The least `limits.stream_stall_ms` K7 admits.
pub const STREAM_STALL_MIN_MS: u32 = 1_000;
/// The most `limits.stream_stall_ms` K7 admits.
pub const STREAM_STALL_MAX_MS: u32 = 600_000;

/// THE PER-STREAM `held` BIT AND ITS STALL DEADLINE (IF §8.7 round 16, §12.22).
///
/// The session task keeps one of these per transport session. A framer's STREAM_FULL for a stream
/// [`hold`](Self::hold)s it: the task makes no further `emit` for that stream and does not poll the
/// exchange or upstream body that feeds it, and the stall deadline is armed once, at the first
/// STREAM_FULL (a repeated STREAM_FULL does not push it out). STREAM_WRITABLE, or the stream's end,
/// [`release`](Self::release)s it. A stream still held at its deadline is returned by
/// [`take_stalled`](Self::take_stalled); the caller then calls `emit(stream, E_RESET, RESET_STALLED)`,
/// ends the feeding exchange as for a peer reset and counts `transport_stream_stalled_total`. The
/// conn's other streams are never touched.
#[derive(Debug)]
pub struct StreamHolds {
    stall: std::time::Duration,
    held: foldhash::HashMap<u64, std::time::Instant>,
    /// The held streams by deadline (kept with `held`): the soonest is the first, and the due ones are
    /// taken from the front, not found by a sweep.
    by_deadline: std::collections::BTreeSet<(std::time::Instant, u64)>,
    /// The streams the last [`Self::take_stalled`] returned (cleared per call, kept for the next).
    stalled: Vec<u64>,
}

impl StreamHolds {
    /// Holds with `stall_ms` clamped into `STREAM_STALL_MIN_MS..=STREAM_STALL_MAX_MS`; `None` is the
    /// default.
    #[must_use]
    pub fn new(stall_ms: Option<u32>) -> Self {
        let ms = stall_ms
            .unwrap_or(STREAM_STALL_DEFAULT_MS)
            .clamp(STREAM_STALL_MIN_MS, STREAM_STALL_MAX_MS);
        Self {
            stall: std::time::Duration::from_millis(u64::from(ms)),
            held: foldhash::HashMap::default(),
            by_deadline: std::collections::BTreeSet::new(),
            stalled: Vec::new(),
        }
    }

    /// STREAM_FULL for `stream` at `now`: held, and the deadline armed if it was not already held.
    pub fn hold(&mut self, stream: u64, now: std::time::Instant) {
        let deadline = now + self.stall;
        if let std::collections::hash_map::Entry::Vacant(slot) = self.held.entry(stream) {
            slot.insert(deadline);
            self.by_deadline.insert((deadline, stream));
        }
    }

    /// STREAM_WRITABLE for `stream`, or its end: no longer held. True when it was held.
    pub fn release(&mut self, stream: u64) -> bool {
        match self.held.remove(&stream) {
            Some(deadline) => {
                self.by_deadline.remove(&(deadline, stream));
                true
            }
            None => false,
        }
    }

    /// Whether the task must leave `stream` alone (no `emit`, no polling of its feed).
    #[must_use]
    pub fn is_held(&self, stream: u64) -> bool {
        self.held.contains_key(&stream)
    }

    /// How many streams are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether no stream is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The soonest stall deadline, for the session task's timer; `None` when nothing is held.
    #[must_use]
    pub fn next_deadline(&self) -> Option<std::time::Instant> {
        self.by_deadline.first().map(|(deadline, _)| *deadline)
    }

    /// Every stream whose deadline is at or before `now`, ascending; each leaves the held set (the
    /// stream is reset, so it is not reported twice).
    pub fn take_stalled(&mut self, now: std::time::Instant) -> &[u64] {
        self.stalled.clear();
        while let Some(&(deadline, stream)) = self.by_deadline.first() {
            if deadline > now {
                break;
            }
            self.by_deadline.pop_first();
            self.held.remove(&stream);
            // Ascending by stream id: each one goes where it belongs (stream ids are unique).
            let at = self.stalled.partition_point(|s| *s < stream);
            self.stalled.insert(at, stream);
        }
        &self.stalled
    }

    /// What the last [`Self::take_stalled`] returned.
    #[must_use]
    pub fn stalled(&self) -> &[u64] {
        &self.stalled
    }
}

#[cfg(test)]
#[path = "tests/framed_stream_tests.rs"]
mod tests;
