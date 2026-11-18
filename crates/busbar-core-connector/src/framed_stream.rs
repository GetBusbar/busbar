// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM, FRAMED BY ITS CLAIM'S FRAMER.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{StatusRow, SIDE_ACCEPT_STREAM};

use crate::compose::HeadWords;
use crate::framer::{AuthBinding, Established, FramerDoor, Framing, Refused, Yielded};

// The MIN-3 framing: one `TransportSession` per connection, driven by the task that owns it (IF §8.7, §13).
pub mod session;

/// How many status rows a framed stream holds inline before they spill to the heap.
const STATUS_ROWS_INLINE: usize = 8;

/// The one stream a [`SIDE_ACCEPT_STREAM`] framing carries.
pub const STREAM: u64 = 1;

/// A stream framer's closing head. Status is producer metadata, never a parsed field.
#[derive(Debug, Default)]
pub struct Closing {
    /// The producer's numeric code, when a closing head carries one.
    pub status: Option<u32>,
    /// The exact declared numbering of the producer's code.
    pub status_namespace: Option<Arc<str>>,
    /// Opaque closing fields in producer order.
    pub fields: Vec<HeadWords>,
}

/// One accepted stream, framed by the framer that answers its claim.
pub struct FramedStream {
    framing: Framing,
    claim: u32,
    rows: smallvec::SmallVec<[StatusRow; STATUS_ROWS_INLINE]>,
    partial: Vec<u8>,
    opening: Vec<HeadWords>,
    deadline_ns: Option<u64>,
}

impl std::fmt::Debug for FramedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedStream")
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

fn fault(error: impl Into<String>) -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: error.into(),
    }
}

impl FramedStream {
    /// Open the stream that arrived at `target` with `head` (its head fields, as the caller sent
    pub fn open(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        scheme: u8,
    ) -> Result<Self, Refused> {
        Self::open_bound(door, claim, target, head, &AuthBinding::NONE, scheme)
    }

    /// [`FramedStream::open`] over `binding`. A stream is framed TICKET-LESS, so a binding with
    pub fn open_bound(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        binding: &AuthBinding,
        scheme: u8,
    ) -> Result<Self, Refused> {
        Self::open_bound_kind(door, claim, target, head, binding, scheme, false)
    }

    /// Open a stream over the transport field grammar without interpreting field names as HTTP.
    pub fn open_neutral(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        scheme: u8,
    ) -> Result<Self, Refused> {
        Self::open_bound_kind(door, claim, target, head, &AuthBinding::NONE, scheme, true)
    }

    fn open_bound_kind(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        binding: &AuthBinding,
        scheme: u8,
        neutral: bool,
    ) -> Result<Self, Refused> {
        binding.ticket_less()?;
        let facts = door.facts();
        let index = facts
            .claims
            .iter()
            .position(|c| *c == claim)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| {
                crate::cold::framing::fault(format_args!(
                    "`{}` does not answer `{claim}`",
                    facts.name
                ))
            })?;
        let mut rows = smallvec::SmallVec::new();
        rows.extend(facts.status_rows.iter().map(|&(claim, lo, hi)| StatusRow {
            claim,
            lo,
            hi,
            class: 0,
        }));
        let established = Established {
            claim: Some(crate::off_path::conns::owned(claim)),
            scheme,
            ..Established::default()
        };
        let (framing, opened) = Framing::begin_ticketless(
            door,
            SIDE_ACCEPT_STREAM,
            target,
            &established,
            head,
            binding,
        )?;
        let opening = if neutral {
            neutral_opening_fields(&opened.wire)?
        } else {
            opening_fields(&opened.wire)?
        };
        let mut stream = Self {
            framing,
            claim: index,
            rows,
            partial: Vec::new(),
            opening,
            deadline_ns: opened.deadline_ns,
        };
        stream.observe(&opened)?;
        Ok(stream)
    }

    /// Initial response fields supplied by the stream's framer at Begin, before any body or
    #[must_use]
    pub fn opening_fields(&self) -> &[HeadWords] {
        &self.opening
    }

    /// The next host-clock instant at which this stream's framer must be called.
    #[must_use]
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline_ns.map(crate::framer::instant_of)
    }

    /// Drive the requested timer, retaining its next deadline and terminal stream failure.
    pub fn timer(&mut self) -> Result<(), Refused> {
        let yielded = self.framing.timer()?;
        self.observe(&yielded)
    }

    fn observe(&mut self, yielded: &Yielded) -> Result<(), Refused> {
        self.deadline_ns = yielded.deadline_ns;
        if let Some(piece) = yielded.pieces.iter().find(|piece| piece.failed) {
            return Err(Refused {
                outcome: Outcome::Failed,
                error: crate::cold::framing::lossy(&piece.bytes),
            });
        }
        Ok(())
    }

    /// The stream's body bytes (`end` = its last); the messages they complete, in order.
    pub fn ingest(&mut self, body: &[u8], end: bool) -> Result<Vec<Vec<u8>>, Refused> {
        let mut y = self.framing.ingest(body, end)?;
        self.observe(&y)?;
        let mut messages = Vec::new();
        for piece in std::mem::take(&mut y.pieces) {
            if piece.fields {
                continue;
            }
            self.partial.extend_from_slice(&piece.bytes);
            if piece.end_of_frame {
                messages.push(std::mem::take(&mut self.partial));
            }
        }
        Ok(messages)
    }

    /// One reply message's bytes (`ends` = they complete it); the stream's body bytes.
    pub fn emit(&mut self, message: &[u8], ends: bool) -> Result<Vec<u8>, Refused> {
        let mut yielded = self.framing.emit(STREAM, message, ends, false)?;
        self.observe(&yielded)?;
        Ok(std::mem::take(&mut yielded.wire))
    }

    /// End the stream refused: `bytes` and the refusal's neutral `status`; the closing field block.
    pub fn refuse(
        &mut self,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Result<Vec<HeadWords>, Refused> {
        let y = self
            .framing
            .refuse(Some(STREAM), bytes, status, head_sent)?;
        closing(&y)
    }

    /// End the stream with the final status the unit stated (`status` in the claim's numbering,
    pub fn finish(
        &mut self,
        status: u32,
        message: &[u8],
        details: &[u8],
    ) -> Result<Vec<HeadWords>, Refused> {
        let y = self
            .framing
            .finish_final(status, message, details, &self.rows, self.claim)?;
        closing(&y)
    }

    /// Refuse the stream, retaining the producer's code and numbering separately from fields.
    pub fn refuse_response(
        &mut self,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Result<Closing, Refused> {
        let yielded = self
            .framing
            .refuse(Some(STREAM), bytes, status, head_sent)?;
        closing_response(&yielded)
    }
}

fn closing_response(yielded: &Yielded) -> Result<Closing, Refused> {
    let mut closing = Closing {
        fields: neutral_opening_fields(&yielded.wire)?,
        ..Closing::default()
    };
    for piece in &yielded.pieces {
        if piece.fields {
            if let Some(status) = piece.status_code {
                if closing.status.replace(status).is_some() {
                    return Err(fault("the closing head states its status more than once"));
                }
                closing.status_namespace.clone_from(&piece.status_namespace);
            }
        }
    }
    Ok(closing)
}

/// The compatibility operator adapter validates ordinary HTTP field names and values.
fn opening_fields(block: &[u8]) -> Result<Vec<HeadWords>, Refused> {
    use busbar_contract::abi::transport::fields;
    let mut read = 0;
    let mut out = Vec::new();
    for (name, value) in fields::lines(block) {
        if name.is_empty()
            || !name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            || value.iter().any(|b| *b < b' ' && *b != b'\t' || *b == 0x7f)
        {
            return Err(fault(
                "the opening field block has an invalid name or value",
            ));
        }
        read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
        out.push(crate::off_path::framing::owned_field(name, value));
    }
    if read != block.len() {
        return Err(fault(
            "the opening field block has an incomplete or malformed line",
        ));
    }
    Ok(out)
}

/// A transport field block must be complete; field names and values belong to its producer.
fn neutral_opening_fields(block: &[u8]) -> Result<Vec<HeadWords>, Refused> {
    use busbar_contract::abi::transport::fields;
    let mut read = 0;
    let mut out = Vec::new();
    for (name, value) in fields::lines(block) {
        if name.is_empty() {
            return Err(fault("the opening field block has an empty name"));
        }
        read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
        out.push(crate::off_path::framing::owned_field(name, value));
    }
    if read != block.len() {
        return Err(fault("the opening field block is incomplete"));
    }
    Ok(out)
}

/// The closing field block an answer wrote, read as field lines.
fn closing(y: &Yielded) -> Result<Vec<HeadWords>, Refused> {
    field_lines(&y.wire)
}

/// FIELD LINES (`name: value` CRLF each, a blank line or the end closing them), read in order. A
pub fn field_lines(block: &[u8]) -> Result<Vec<HeadWords>, Refused> {
    let mut out = Vec::new();
    for line in block.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let pseudo = usize::from(line.first() == Some(&b':'));
        let colon = line[pseudo..]
            .iter()
            .position(|b| *b == b':')
            .map(|c| c + pseudo)
            .ok_or_else(|| fault("the closing field block has a line with no `:`"))?;
        let (name, value) = line.split_at(colon);
        if name.len() == pseudo || name.iter().any(|b| b.is_ascii_whitespace()) {
            return Err(fault("the closing field block has a line with no name"));
        }
        let value = &value[1..];
        let start = value
            .iter()
            .position(|b| *b != b' ' && *b != b'\t')
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|b| *b != b' ' && *b != b'\t')
            .map_or(start, |e| e + 1);
        out.push(crate::off_path::framing::owned_field(
            name,
            &value[start..end.max(start)],
        ));
    }
    Ok(out)
}

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
#[allow(unsafe_code)]
#[path = "tests/framed_stream_tests.rs"]
mod tests;
