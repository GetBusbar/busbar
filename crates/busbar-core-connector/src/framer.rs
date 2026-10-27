// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER A CONNECTION CARRIES: one transport entry's table, driven host-side.
//!
//! A framer is sans-IO (`BUSBAR-1.6.0.md` THE DESIGN, §5; the transport kind's ABI): the connector
//! feeds it what the socket read (`ingest`) and what the caller writes (`emit`), and drains what it
//! answers into HOST buffers — wire bytes for the socket, frame pieces for the caller. A full buffer
//! is back-pressure (`YIELD_MORE`): the connector drains it and calls the same op again with no new
//! bytes. A deadline the framer states (`YIELD_HAS_DEADLINE`) is the connector's to keep: at that
//! instant it calls `timer`. `YIELD_ENDED` ends the connection.
//!
//! How a call reaches the entry is not this crate's business: a [`FramerDoor`] is the entry's table
//! as the host reaches it — the one dispatcher's crossing for a loaded plugin, compiled in or
//! dropped in — so this crate names no plugin and no loader.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome, Span};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{check::check_final_status, StatusRow, CLOSE_NORMAL};
use busbar_contract::abi::transport::{
    AdoptIn, BeginIn, ConnFacts, EmitIn, EncodeIn, FinishIn, FramePiece, FrameSpan, FramerOut,
    FramerSink, FramingIn, HeadSlots, IngestIn, LocateIn, LocateOut, RefuseIn, EMIT_TEXT,
    PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE,
    PIECE_HAS_DECLARED_LEN, PIECE_HAS_RETRY_AFTER, PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE,
    SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};

/// One framer op, its `in` and its `out`, as the connector hands it to a [`FramerDoor`].
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Call<'a> {
    Locate(&'a mut LocateIn, &'a mut LocateOut),
    Begin(&'a mut BeginIn, &'a mut FramerOut),
    Ingest(&'a mut IngestIn, &'a mut FramerOut),
    Emit(&'a mut EmitIn, &'a mut FramerOut),
    Encode(&'a mut EncodeIn, &'a mut FramerOut),
    Refuse(&'a mut RefuseIn, &'a mut FramerOut),
    Finish(&'a mut FinishIn, &'a mut FramerOut),
    Detach(&'a mut FramingIn, &'a mut FramerOut),
    Adopt(&'a mut AdoptIn, &'a mut FramerOut),
    Timer(&'a mut FramingIn, &'a mut FramerOut),
}

/// What one crossing answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crossed {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text of a FAILED or REFUSED answer.
    pub error: Option<Vec<u8>>,
}

/// What a transport entry states about itself, read from its Statement at load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorFacts {
    /// The entry's name.
    pub name: String,
    /// Every scheme it answers for; the first is its own.
    pub claims: Vec<&'static str>,
    /// The tail's ROLE (`ROLE_CARRIER` | `ROLE_FRAMER`, ARCHITECT ruling Q128 U7): a CARRIER is a
    /// byte stream the host's socket or pipe carries as itself (no opening message, nothing framed,
    /// a stream it may secure mid-way); a FRAMER frames messages over the carrier the connector
    /// chose from the target's scheme. The role is stated, never derived from `composes_over`.
    pub role: u32,
    /// The claims it composes over: always empty now (no transport names another); an entry that
    /// states one is refused where it would be served.
    pub composes_over: Vec<&'static str>,
    /// A CARRIER whose own claim selects on the local PORT a connection arrived on (its claim row's
    /// selector forms hold `SelectorForm::Port`): it listens on, and dials, network addresses. The
    /// connector carries a framer's connection over the first such carrier
    /// ([`crate::registry::Transports::address_carrier`]): the carrier under a framer is the
    /// connector's choice from the target, and no transport names another.
    pub ported: bool,
    /// Its status table, row by row: `(claim, lo, hi)`, the code ranges each claim's numbering
    /// has; a stream's final status is judged against its claim's ([`crate::framed_stream`]).
    pub status_rows: Vec<(u32, u32, u32)>,
    /// THE DUPLEX CLAIMS: the ones a stream rides, read off the claim rows of its Statement
    /// (ARCHITECT ruling Q128 U7): each whose unit 0 opens at an UPGRADE (`UNIT0_UPGRADE`) or that
    /// carries a session (`session`). A claim that states neither is a request and its answer, which
    /// the listener it arrived on frames already; a stream on one of these is this entry's to frame.
    pub duplex: Vec<&'static str>,
    /// THE DATAGRAM FRAMER (its tail states `FRAMING_DATAGRAM`): every call carries the datagram
    /// lane and it is driven only by [`crate::datagram::DatagramFraming`] over the host's port and
    /// secure layer; it never frames a stream, whatever its claim rows say.
    pub datagram: bool,
}

/// A transport entry's table, as the host reaches it: a framer's ops ([`FramerDoor::cross`]) and a
/// carrier's ([`FramerDoor::carry`]).
pub trait FramerDoor: Send + Sync {
    /// What the entry states.
    fn facts(&self) -> &DoorFacts;
    /// One crossing: the op, answered into its `out`.
    fn cross(&self, call: Call<'_>) -> Crossed;
    /// A new side of a carried connection: a ticket the entry's carrier ops are driven on inline
    /// (`crate::carrier`). `None` = the entry is no carrier the host can drive.
    fn side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        None
    }
    /// One CARRIER crossing on `side` (a RESUME of the op that pended on it when `resume`). An entry
    /// that carries nothing answers REFUSED.
    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        resume: bool,
        call: crate::carrier::Carry<'_>,
    ) -> Crossed {
        let _ = (side, resume, call);
        Crossed {
            outcome: Outcome::Refused,
            error: None,
        }
    }
    /// A NEW TICKET for a framing's TICKETED ops (`begin`, `ingest`, `emit`: the ops that may call
    /// the host's auth service, which may pend). A framing asks for one at its `begin` and for
    /// another whenever an op must cross while its other tickets each hold a parked op, so a
    /// pending answer parks only its own op: one stream's, never its siblings'. The framing holds
    /// each ticket until it closes or lets an idle one go. `None` = the entry runs every framer
    /// op ticket-less, where a pending answer is a fault and a service that may pend is refused.
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        None
    }
    /// One crossing of a TICKETED framer op on `side`'s ticket (a RESUME of the op that pended on
    /// it when `resume`: the same op, re-issued on the same ticket, so every service it calls
    /// answers its stored result). Any other op crosses as [`FramerDoor::cross`] does.
    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        let _ = (side, resume);
        self.cross(call)
    }
}

/// Why a framer op did not answer READY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Its outcome.
    pub outcome: Outcome,
    /// Its error text.
    pub error: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the framer answered {:?}: {}", self.outcome, self.error)
    }
}

impl std::error::Error for Refused {}

pub(crate) fn refused(c: Crossed) -> Refused {
    Refused {
        outcome: c.outcome,
        error: String::from_utf8_lossy(c.error.as_deref().unwrap_or_default()).into_owned(),
    }
}

/// One frame piece the framer answered, copied out of the host's buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Got {
    /// The stream.
    pub stream: u64,
    /// Its bytes.
    pub bytes: Vec<u8>,
    /// It ends its frame.
    pub end_of_frame: bool,
    /// The status number, where the piece carries one.
    pub status_code: Option<u32>,
    /// The status class (`STATUS_*`).
    pub status_class: u8,
    /// The fault reading (`FAULT_*`), the breaker's leg.
    pub fault: u8,
    /// The far side's `Retry-After`, in seconds, where it asked.
    pub retry_after_secs: Option<u64>,
    /// On a head's field block: the body length the head declared on the wire, as the framer
    /// stated it (`PIECE_HAS_DECLARED_LEN`); handed on untouched.
    pub declared_len: Option<u64>,
    /// The bytes are a field block (`PIECE_FIELDS`): the far end's head, or its trailers.
    pub fields: bool,
    /// The bytes belong to a text message (`PIECE_TEXT`), read up as `FrameMeta::text`.
    pub text: bool,
    /// On the head's first piece: the far end's reason phrase, exactly as sent (the stream's head
    /// slots), where the wire has one.
    pub reason: Option<Vec<u8>>,
    /// The stream FAILED (`PIECE_STREAM_FAILED`): this is its last piece and the bytes are the
    /// reason; its siblings on the connection carry on.
    pub failed: bool,
    /// The stream ENDS whole here (`PIECE_END`): no piece of it follows.
    pub end: bool,
}

impl Got {
    /// Whether this piece ENDS its stream whole: the framer said so (`PIECE_END`,
    /// `busbar_contract::abi::transport`, "streams end by flag"), and nothing else says it. An
    /// EMPTY piece without it is an empty message, text or binary, and is relayed as one; an empty
    /// fields piece is an empty head; a failed stream's piece ends it failed.
    #[must_use]
    pub const fn ends_stream(&self) -> bool {
        self.end
    }
}

/// A stream's head typed slots (`HeadSlots`), copied out of the host's buffers: an accepted
/// stream's method, target and authority, or a dialled answer's reason phrase. Absent = `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Head {
    /// The stream.
    pub stream: u64,
    /// The method (accepted).
    pub method: Option<Vec<u8>>,
    /// The target: path and query (accepted).
    pub target: Option<Vec<u8>>,
    /// The authority the caller named (accepted), where it named one.
    pub authority: Option<Vec<u8>>,
    /// The far end's reason phrase exactly as sent (dialled), where it sent one.
    pub reason: Option<Vec<u8>>,
}

/// Everything one op answered, across its `YIELD_MORE` re-calls.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Yielded {
    /// Head slots, in order.
    pub heads: Vec<Head>,
    /// Bytes owed to the far side, in order.
    pub wire: Vec<u8>,
    /// Frame pieces, in order.
    pub pieces: Vec<Got>,
    /// No frame follows on the connection.
    pub ended: bool,
    /// The monotonic instant (host clock, ns) the framer asked to be called at.
    pub deadline_ns: Option<u64>,
    /// On an `emit`: the bytes were taken and the stream's queue is at the framer's high-water
    /// mark (`YIELD_STREAM_FULL`): the host emits nothing more on that stream until it is
    /// writable again ([`Yielded::writable`]) or its last piece arrives.
    pub full: bool,
    /// The streams the framer says are writable again (`PIECE_WRITABLE` pieces), in order. Such a
    /// piece is a signal to the host and never a frame: it is not among [`Yielded::pieces`].
    pub writable: Vec<u64>,
}

/// The host's buffers a framer op writes into.
#[derive(Debug)]
pub struct Buffers {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    /// Head slots.
    heads: Vec<HeadSlots>,
    /// The framing's side (`SIDE_*`): what its head slots may carry.
    side: u32,
    /// Where each stream's field block stands between pieces.
    lines: FieldLines,
}

/// Where a stream's field block stands between two of its pieces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
    /// At the start of a line.
    Start,
    /// In a field's name.
    Name,
    /// In a field's value.
    Value,
    /// In a value, just after its CR.
    ValueCr,
}

/// THE HOST'S FIELD-BLOCK REASSEMBLY CHECK: per stream, where the block stands across pieces and
/// across framer answers, so a framer's `PIECE_CONTINUED` is never taken on its word. A continued
/// piece must extend an open line's VALUE; a piece that does not say it continues must start a
/// line; a line whose name starts with `:` (a pseudo-field) is refused wherever it starts; a block
/// ends at a line's end. Each refusal is the framer's fault.
#[derive(Debug, Default)]
pub struct FieldLines {
    open: HashMap<u64, Line>,
}

/// What a piece is to its stream's field block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPiece {
    /// A field-block piece: whether it continues a line, and whether it ends the block.
    Fields {
        /// `PIECE_CONTINUED`.
        continued: bool,
        /// `PIECE_END_OF_FRAME`.
        end: bool,
    },
    /// A payload piece.
    Payload,
    /// The stream failed: whatever block it had open is gone with it.
    Failed,
}

impl FieldLines {
    /// Take any piece of `stream`: a field-block piece is judged as [`FieldLines::piece`] judges
    /// it; a payload piece while the stream's block is still open is refused; a failed stream's
    /// state is dropped.
    ///
    /// # Errors
    ///
    /// Why the piece breaks the block, as an operator reads it.
    pub fn take(
        &mut self,
        stream: u64,
        kind: FieldPiece,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        match kind {
            FieldPiece::Fields { continued, end } => self.piece(stream, continued, end, bytes),
            FieldPiece::Payload if self.open.contains_key(&stream) => {
                Err("a payload piece inside an open field block")
            }
            FieldPiece::Payload => Ok(()),
            FieldPiece::Failed => {
                self.open.remove(&stream);
                Ok(())
            }
        }
    }

    /// Take one field-block piece of `stream`.
    ///
    /// # Errors
    ///
    /// Why the piece breaks the block, as an operator reads it.
    pub fn piece(
        &mut self,
        stream: u64,
        continued: bool,
        end: bool,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        let mut at = match (self.open.get(&stream).copied(), continued) {
            (None, true) => return Err("a continued field piece with no line before it"),
            (Some(l @ (Line::Value | Line::ValueCr)), true) => l,
            (Some(_), true) => return Err("a continued field piece that does not extend a value"),
            (None | Some(Line::Start), false) => Line::Start,
            (Some(_), false) => return Err("a field piece that starts inside a line"),
        };
        for &b in bytes {
            at = match at {
                Line::Start => match b {
                    b':' => return Err("a pseudo-field in a field block"),
                    b'\r' | b'\n' => return Err("a field line without a value"),
                    _ => Line::Name,
                },
                Line::Name => match b {
                    b':' => Line::Value,
                    b'\r' | b'\n' => return Err("a field line without a value"),
                    _ => Line::Name,
                },
                Line::Value => match b {
                    b'\r' => Line::ValueCr,
                    b'\n' => return Err("a field line ended without its CR"),
                    _ => Line::Value,
                },
                Line::ValueCr => match b {
                    b'\n' => Line::Start,
                    _ => return Err("a CR without its LF in a field block"),
                },
            };
        }
        if end {
            self.open.remove(&stream);
            if at != Line::Start {
                return Err("a field block that ends inside a line");
            }
        } else {
            self.open.insert(stream, at);
        }
        Ok(())
    }
}

/// The default capacities: wire and frame bytes, and pieces.
pub const WIRE_CAP: usize = 64 * 1024;
/// The frame buffer's capacity.
pub const FRAME_CAP: usize = 64 * 1024;
/// The pieces buffer's capacity.
pub const PIECES_CAP: usize = 64;
/// The head-slots buffer's capacity.
pub const HEADS_CAP: usize = 16;

const EMPTY_PIECE: FramePiece = FramePiece {
    stream: 0,
    offset: 0,
    len: 0,
    code: 0,
    status_class: 0,
    flags: 0,
    fault: 0,
    retry_after_secs: 0,
    declared_len: 0,
};

impl Buffers {
    /// Buffers of the given capacities (each at least one).
    #[must_use]
    pub fn new(wire: usize, frame: usize, pieces: usize) -> Self {
        Self {
            wire: vec![0; wire.max(1)],
            frame: vec![0; frame.max(1)],
            pieces: vec![EMPTY_PIECE; pieces.max(1)],
            heads: vec![HeadSlots::default(); HEADS_CAP],
            side: SIDE_DIAL,
            lines: FieldLines::default(),
        }
    }

    /// The default buffers for a framing on `side`.
    pub(crate) fn for_side(side: u32) -> Self {
        Self {
            side,
            ..Self::default()
        }
    }

    pub(crate) fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: now_ns(),
            now_unix_ns: unix_ns(),
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
        }
    }

    /// The first `len` bytes the last answer wrote into the wire buffer; `None` = out of bounds.
    pub(crate) fn wire_written(&self, len: u64) -> Option<&[u8]> {
        self.wire.get(..usize::try_from(len).ok()?)
    }

    /// The first `len` bytes the last answer wrote into the frame buffer; `None` = out of bounds.
    pub(crate) fn frame_written(&self, len: u64) -> Option<&[u8]> {
        self.frame.get(..usize::try_from(len).ok()?)
    }

    /// Take what one READY answer wrote; `false` = it owes more (`YIELD_MORE`).
    pub(crate) fn take(&mut self, o: &FramerOut, into: &mut Yielded) -> Result<bool, Refused> {
        let y = &o.yielded;
        let bad = |what: &str| Refused {
            outcome: Outcome::Fault,
            error: format!("the framer's answer is out of bounds: {what}"),
        };
        let wire = self
            .wire
            .get(..usize::try_from(y.wire_len).map_err(|_| bad("wire"))?)
            .ok_or_else(|| bad("wire"))?;
        into.wire.extend_from_slice(wire);
        let frame_len = usize::try_from(y.frame_len).map_err(|_| bad("frame"))?;
        let frame = self.frame.get(..frame_len).ok_or_else(|| bad("frame"))?;
        let pieces = self
            .pieces
            .get(..y.pieces_len as usize)
            .ok_or_else(|| bad("pieces"))?;
        let first_piece = into.pieces.len();
        for p in pieces {
            if p.flags & PIECE_WRITABLE != 0 {
                // A STREAM WRITABLE AGAIN: always an empty piece with no other flag, ending no
                // frame and no stream. The host's signal, never a frame handed up.
                if p.len != 0 || p.flags != PIECE_WRITABLE {
                    return Err(bad("a writable piece with bytes or another flag"));
                }
                into.writable.push(p.stream);
                continue;
            }
            let at = usize::try_from(p.offset).map_err(|_| bad("piece"))?;
            let len = usize::try_from(p.len).map_err(|_| bad("piece"))?;
            let bytes = frame
                .get(at..at.checked_add(len).ok_or_else(|| bad("piece"))?)
                .ok_or_else(|| bad("piece"))?;
            let kind = if p.flags & PIECE_STREAM_FAILED != 0 {
                FieldPiece::Failed
            } else if p.flags & PIECE_FIELDS != 0 {
                FieldPiece::Fields {
                    continued: p.flags & PIECE_CONTINUED != 0,
                    end: p.flags & PIECE_END_OF_FRAME != 0,
                }
            } else {
                FieldPiece::Payload
            };
            self.lines
                .take(p.stream, kind, bytes)
                .map_err(|why| Refused {
                    outcome: Outcome::Fault,
                    error: format!("the framer's field block is refused: {why}"),
                })?;
            into.pieces.push(Got {
                stream: p.stream,
                bytes: bytes.to_vec(),
                end_of_frame: p.flags & PIECE_END_OF_FRAME != 0,
                status_code: (p.flags & PIECE_HAS_CODE != 0).then_some(p.code),
                status_class: p.status_class,
                fault: p.fault,
                retry_after_secs: (p.flags & PIECE_HAS_RETRY_AFTER != 0)
                    .then_some(p.retry_after_secs),
                declared_len: (p.flags & PIECE_HAS_DECLARED_LEN != 0).then_some(p.declared_len),
                fields: p.flags & PIECE_FIELDS != 0,
                text: p.flags & PIECE_TEXT != 0,
                reason: None,
                failed: p.flags & PIECE_STREAM_FAILED != 0,
                end: p.flags & PIECE_END != 0,
            });
        }
        let heads = self
            .heads
            .get(..y.heads_len as usize)
            .ok_or_else(|| bad("heads"))?;
        for h in heads {
            let slot = |s: FrameSpan| {
                let at = usize::try_from(s.offset).map_err(|_| bad("head"))?;
                let len = usize::try_from(s.len).map_err(|_| bad("head"))?;
                frame
                    .get(at..at.checked_add(len).ok_or_else(|| bad("head"))?)
                    .map(|b| (!b.is_empty()).then(|| b.to_vec()))
                    .ok_or_else(|| bad("head"))
            };
            let head = Head {
                stream: h.stream,
                method: slot(h.method)?,
                target: slot(h.target)?,
                authority: slot(h.authority)?,
                reason: slot(h.reason)?,
            };
            // An accepted stream's slots are the request's; a dialled one's, the answer's reason.
            let request =
                head.method.is_some() || head.target.is_some() || head.authority.is_some();
            let fits = if self.side == SIDE_ACCEPT {
                request && head.reason.is_none()
            } else {
                !request
            };
            if !fits {
                return Err(bad("head slots of the other side"));
            }
            // A dialled answer's reason rides its stream's head: the first field-block piece of
            // the stream in this answer.
            if let Some(reason) = head.reason.clone() {
                if let Some(g) = into.pieces[first_piece..]
                    .iter_mut()
                    .find(|g| g.stream == head.stream && g.fields)
                {
                    g.reason = Some(reason);
                }
            }
            into.heads.push(head);
        }
        into.ended |= y.flags & YIELD_ENDED != 0;
        into.full |= y.flags & YIELD_STREAM_FULL != 0;
        into.deadline_ns = (y.flags & YIELD_HAS_DEADLINE != 0).then_some(y.next_deadline_ns);
        Ok(y.flags & YIELD_MORE == 0)
    }
}

impl Default for Buffers {
    fn default() -> Self {
        Self::new(WIRE_CAP, FRAME_CAP, PIECES_CAP)
    }
}

/// The host's monotonic clock, nanoseconds since this process first read it (never `0`: a framer
/// states "no deadline" as `0`).
#[must_use]
pub fn now_ns() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX) + 1
}

/// The host's monotonic instant `ns` names.
#[must_use]
pub fn instant_of(ns: u64) -> Instant {
    let now = now_ns();
    let from_now = std::time::Duration::from_nanos(ns.saturating_sub(now));
    Instant::now() + from_now
}

fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Where one connection's framing stands with its entry.
pub struct Framing {
    door: Arc<dyn FramerDoor>,
    token: u64,
    bufs: Buffers,
    /// Its ticketed ops run on tickets ([`FramerDoor::framing_side`]); `false` = ticket-less.
    ticketed: bool,
    /// The tickets it holds that no op is parked on, for its next ticketed op.
    idle: Vec<Box<dyn crate::carrier::Side>>,
    /// THE TICKETED OPS PARKED, each on its own ticket, in the order they parked: a parked `begin`
    /// holds the whole framing; a parked `emit` holds its stream; a parked `ingest` holds what the
    /// framer holds back for the stream whose auth it waits on, and nothing the host sends after.
    parked: Vec<Parked>,
}

/// The most ticketed ops one framing may have parked at once: each holds a ticket of the host's,
/// so a far end that opens stream after stream whose auth pends cannot hold the host's tickets
/// without bound (the framing FAULTs past it).
pub const MAX_PARKED: usize = 256;

/// How many idle tickets a framing keeps for its next ticketed ops; one let go past it.
const IDLE_TICKETS: usize = 1;

/// THE RULE A TICKET-LESS FRAMING BREAKS when its binding has auth points: a framer whose `begin`,
/// `ingest` or `emit` may call the auth service runs those ops only on a ticket, where a pending
/// auth answer parks its own stream; ticket-less, a pending answer is a fault.
pub const TICKET_LESS_AUTH: &str = "a framer whose binding has auth points runs its begin, ingest \
     and emit only on a ticket (an auth call may pend); it is never driven ticket-less";

/// THE AUTH A FRAMING'S BINDING CARRIES, as `begin` hands it to the framer
/// ([`BeginIn::points`], [`BeginIn::auth`]) and as the host judges whether the framer may call
/// the auth service at all: a framing whose binding has auth points is driven only on a ticket
/// ([`TICKET_LESS_AUTH`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthBinding {
    /// [`SIDE_DIAL`]: the auth points the binding's auth needs (`POINT_*`); `0` = no auth.
    pub points: u32,
    /// [`SIDE_DIAL`]: the binding's auth handle; NONE exactly when `points` is `0`.
    pub auth: busbar_contract::abi::host::service::AuthRef,
    /// Accepting: the auth points the guest lines' auths declare, together; `0` = every line's
    /// auth is `none`.
    pub line_points: u32,
}

impl Default for AuthBinding {
    fn default() -> Self {
        Self::NONE
    }
}

impl AuthBinding {
    /// A binding with no auth: the framer never calls the auth service.
    pub const NONE: Self = Self {
        points: 0,
        auth: busbar_contract::abi::host::service::AuthRef::NONE,
        line_points: 0,
    };

    /// Whether the framer may call the auth service on this binding.
    #[must_use]
    pub const fn calls_auth(&self) -> bool {
        self.points != 0 || !self.auth.is_none() || self.line_points != 0
    }

    /// Refused when the binding has auth points: the framing would be driven ticket-less.
    ///
    /// # Errors
    ///
    /// [`TICKET_LESS_AUTH`], REFUSED.
    pub fn ticket_less(&self) -> Result<(), Refused> {
        if self.calls_auth() {
            return Err(Refused {
                outcome: Outcome::Refused,
                error: TICKET_LESS_AUTH.into(),
            });
        }
        Ok(())
    }
}

/// A TICKETED FRAMER OP, as the framing issues it (and re-issues it on a resume): `begin`,
/// `ingest` or `emit`, its bytes borrowed while it crosses and owned once it parks.
#[derive(Debug)]
enum Ticketed<'a> {
    Begin {
        side: u32,
        target: String,
        established: Established,
        opening: Vec<(String, Vec<u8>)>,
        binding: AuthBinding,
    },
    Ingest {
        bytes: std::borrow::Cow<'a, [u8]>,
        end: bool,
    },
    Emit {
        stream: u64,
        bytes: std::borrow::Cow<'a, [u8]>,
        end_of_frame: bool,
        text: bool,
        /// The opening body's length on a dialled request's head emit: `Some` = known.
        body_len: Option<u64>,
    },
}

impl Ticketed<'_> {
    fn owned(self) -> Ticketed<'static> {
        match self {
            Self::Begin {
                side,
                target,
                established,
                opening,
                binding,
            } => Ticketed::Begin {
                side,
                target,
                established,
                opening,
                binding,
            },
            // A parked op's resume carries no new bytes: the framer took them whole when the op
            // first crossed, so none is kept.
            Self::Ingest { end, .. } => Ticketed::Ingest {
                bytes: std::borrow::Cow::Owned(Vec::new()),
                end,
            },
            Self::Emit {
                stream,
                end_of_frame,
                text,
                body_len,
                ..
            } => Ticketed::Emit {
                stream,
                bytes: std::borrow::Cow::Owned(Vec::new()),
                end_of_frame,
                text,
                body_len,
            },
        }
    }

    /// The stream a parked op of this kind holds: an emit's own; `None` for `begin` (which holds
    /// the whole framing) and `ingest` (whose stream only the framer knows).
    const fn stream(&self) -> Option<u64> {
        match self {
            Self::Emit { stream, .. } => Some(*stream),
            Self::Begin { .. } | Self::Ingest { .. } => None,
        }
    }
}

/// A ticketed op parked on its own ticket: the op, what its earlier answers yielded, whether it
/// was a re-call with no new bytes (a `YIELD_MORE` re-call may pend too), and the ticket.
struct Parked {
    op: Ticketed<'static>,
    yielded: Yielded,
    recall: bool,
    ticket: Box<dyn crate::carrier::Side>,
}

impl std::fmt::Debug for Framing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framing")
            .field("entry", &self.door.facts().name)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

pub(crate) fn ready(c: Crossed) -> Result<(), Refused> {
    if c.outcome == Outcome::Ready {
        Ok(())
    } else {
        Err(refused(c))
    }
}

/// An absent string.
const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

fn abi(s: &[u8]) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// What connection security established, owned, for `begin`/`adopt`'s [`ConnFacts`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Established {
    /// The name offered to the far end.
    pub offered_name: Option<String>,
    /// The protocol the handshake agreed.
    pub agreed_protocol: Option<Vec<u8>>,
    /// The claim the connection resolved to.
    pub claim: Option<String>,
    /// The far end's key pin, read off its verified leaf certificate on a secured dial; `None` =
    /// no certificate (the transport pin, ARCHITECT 2026-10-03).
    pub peer_key_pin: Option<String>,
    /// Whether the handshake presented busbar's client identity.
    pub client_identity: bool,
    /// The connection's scheme as `begin` declares it (`BeginIn::scheme`, a `SCHEME_*` code):
    /// `SCHEME_SECURE` when the connector runs connection security on it (a dial through the
    /// security layer, a listener that terminated it), `SCHEME_PLAIN` when it rides in the clear.
    /// The default, `SCHEME_UNDECLARED`, is refused at `begin`: a zero never grants.
    pub scheme: u8,
}

impl Established {
    /// The scheme code for a connection the connector does (`true`) or does not secure.
    #[must_use]
    pub const fn scheme_of(secured: bool) -> u8 {
        if secured {
            busbar_contract::abi::host::service::SCHEME_SECURE
        } else {
            busbar_contract::abi::host::service::SCHEME_PLAIN
        }
    }

    /// A test's connection in the clear: the default with a declared scheme.
    #[cfg(test)]
    pub(crate) fn plain_for_test() -> Self {
        Self {
            scheme: busbar_contract::abi::host::service::SCHEME_PLAIN,
            ..Self::default()
        }
    }

    fn facts(&self) -> ConnFacts {
        let text = |s: Option<&[u8]>| s.map_or(NO_TEXT, abi);
        ConnFacts {
            size: u32::try_from(std::mem::size_of::<ConnFacts>()).unwrap_or(u32::MAX),
            _reserved: 0,
            offered_name: text(self.offered_name.as_deref().map(str::as_bytes)),
            agreed_protocol: text(self.agreed_protocol.as_deref()),
            peer_subject: NO_TEXT,
            peer_issuer: NO_TEXT,
            peer_fingerprint: NO_TEXT,
            claim: text(self.claim.as_deref().map(str::as_bytes)),
            local_certificate: NO_TEXT,
        }
    }
}

/// Where `locate` says a target is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The authority to dial (`host:port`).
    pub authority: String,
    /// The name to offer the far end, where one is.
    pub name: Option<String>,
    /// The target asks for connection security.
    pub secure: bool,
    /// The entry's protocol offer for the handshake (ALPN), most preferred first; empty = it makes
    /// none (THE DESIGN, connections: "the ALPN offer is the framer's").
    pub offer: Vec<Vec<u8>>,
    /// The framer's own head lines on a request to the target (`LocateIn::defaults_buf`), in order:
    /// each one a request that does not state it carries, added before the auth signs the head.
    pub defaults: Vec<crate::compose::HeadWords>,
    /// The framer's head states its body's length (`LocateOut::states_length`): `content-length` is
    /// the framer's own line, written by the framer from the body length the host hands it,
    /// before its auth call; the host adds no line of that name.
    pub states_length: bool,
}

/// A protocol offer in the handshake's ProtocolNameList encoding (each name led by its one-byte
/// length), read into its names; `None` where the bytes are not such a list.
fn protocol_names(mut b: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    while let Some((&len, rest)) = b.split_first() {
        let len = usize::from(len);
        if len == 0 || rest.len() < len {
            return None;
        }
        names.push(rest[..len].to_vec());
        b = &rest[len..];
    }
    Some(names)
}

/// `locate`: where `target` is, per the entry, and its protocol offer. One re-call with the sizes a
/// short answer names.
///
/// # Errors
///
/// The entry refused the target, or answered an offer that is not a protocol list.
pub fn locate(door: &dyn FramerDoor, target: &str) -> Result<Located, Refused> {
    locate_as(door, target, false)
}

/// THE OFFER A LISTENER FRAMED BY `door` MAKES in the handshake (ALPN, most preferred first):
/// `locate` asked for the ACCEPTING side (`LocateIn::accept`). The framer's, as a dial's offer is
/// (`BUSBAR-1.6.0.md` l.477-478), and not the same one: v1.5.5's client offered two protocols,
/// its listener one of them alone.
///
/// # Errors
///
/// The entry refused, or answered an offer that is not a protocol list.
pub fn accept_offer(door: &dyn FramerDoor) -> Result<Vec<Vec<u8>>, Refused> {
    locate_as(door, "", true).map(|l| l.offer)
}

/// THE MOST ROOM THE HOST GIVES ONE `locate` ANSWER, per buffer: a short answer naming more is the
/// transport's FAULT, never an allocation of what it named (the contract admits up to 4 GiB a
/// buffer). An authority, an offered name and head lines are far smaller; a protocol offer is at
/// most `MAX_ALPN_BYTES`, the handshake's own bound.
const LOCATE_CAP: usize = 64 * 1024;

fn locate_as(door: &dyn FramerDoor, target: &str, accept: bool) -> Result<Located, Refused> {
    let (mut auth_cap, mut name_cap, mut alpn_cap) = (256_usize, 256_usize, 256_usize);
    let mut defaults_cap = 256_usize;
    for _ in 0..2 {
        let mut authority = vec![0_u8; auth_cap];
        let mut name = vec![0_u8; name_cap];
        let mut alpn = vec![0_u8; alpn_cap];
        let mut defaults = vec![0_u8; defaults_cap];
        let mut i: LocateIn = blank_in();
        i.target = abi(target.as_bytes());
        i.authority_buf = authority.as_mut_ptr();
        i.authority_cap = authority.len();
        i.name_buf = name.as_mut_ptr();
        i.name_cap = name.len();
        i.alpn_buf = alpn.as_mut_ptr();
        i.alpn_cap = alpn.len();
        i.accept = u32::from(accept);
        i.defaults_buf = defaults.as_mut_ptr();
        i.defaults_cap = defaults.len();
        let mut o: LocateOut = blank_out();
        let c = door.cross(Call::Locate(&mut i, &mut o));
        let short = o.authority_needed > auth_cap as u64
            || o.name_needed > name_cap as u64
            || o.alpn_needed > alpn_cap as u64
            || o.defaults_needed > defaults_cap as u64;
        if c.outcome == Outcome::Failed && short {
            let grow = |needed: u64, cap: usize, what: &str| -> Result<usize, Refused> {
                match usize::try_from(needed) {
                    Ok(n) if n <= LOCATE_CAP => Ok(n.max(cap)),
                    _ => Err(Refused {
                        outcome: Outcome::Fault,
                        error: format!(
                            "the framer's locate answer asks {needed} bytes for its {what}, past \
                             the host's {LOCATE_CAP}"
                        ),
                    }),
                }
            };
            auth_cap = grow(o.authority_needed, auth_cap, "authority")?;
            name_cap = grow(o.name_needed, name_cap, "name")?;
            alpn_cap = grow(o.alpn_needed, alpn_cap, "protocol offer")?;
            defaults_cap = grow(o.defaults_needed, defaults_cap, "head lines")?;
            continue;
        }
        ready(c)?;
        let text = |b: &[u8], n: u64| {
            String::from_utf8_lossy(b.get(..usize::try_from(n).unwrap_or(0)).unwrap_or_default())
                .into_owned()
        };
        let offered = alpn
            .get(..usize::try_from(o.alpn_written).unwrap_or(usize::MAX))
            .and_then(protocol_names)
            .ok_or_else(|| Refused {
                outcome: Outcome::Fault,
                error: "the framer's protocol offer is not a protocol list".into(),
            })?;
        let lines = defaults
            .get(..usize::try_from(o.defaults_written).unwrap_or(usize::MAX))
            .ok_or_else(|| Refused {
                outcome: Outcome::Fault,
                error: "the framer's head lines overrun its buffer".into(),
            })?;
        return Ok(Located {
            authority: text(&authority, o.authority_written),
            name: (o.has_name != 0).then(|| text(&name, o.name_written)),
            secure: o.secure != 0,
            offer: offered,
            defaults: crate::framed_stream::field_lines(lines)?,
            states_length: o.states_length != 0,
        });
    }
    Err(Refused {
        outcome: Outcome::Fault,
        error: "locate answered short twice".into(),
    })
}

/// `encode`: an envelope as the entry's own wire bytes.
///
/// # Errors
///
/// The entry refused to render it.
pub fn encode(
    door: &dyn FramerDoor,
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> Result<Vec<u8>, Refused> {
    encode_head(door, b"", b"", fields, body)
}

/// `encode` with the request's head words, `method` and `target` (empty = none): a framer whose
/// wire has head words takes them as the request's own, byte for byte; one without ignores them.
///
/// # Errors
///
/// The entry refused to render it; a FAULT when it answered `YIELD_MORE` (an encode answers whole).
pub fn encode_head(
    door: &dyn FramerDoor,
    method: &[u8],
    target: &[u8],
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> Result<Vec<u8>, Refused> {
    let fields: Vec<Field> = fields
        .iter()
        .map(|(n, v)| Field {
            name: abi(n.as_bytes()),
            value: abi(v),
        })
        .collect();
    // `encode` renders a whole message at once: room for the body and every field, and the head.
    let room = body.len()
        + fields
            .iter()
            .map(|f| f.name.len + f.value.len + 8)
            .sum::<usize>();
    let mut bufs = Buffers::new(room + method.len() + target.len() + 4096, 1, 1);
    let mut i: EncodeIn = blank_in();
    i.method = abi(method);
    i.target = abi(target);
    i.fields = fields.as_ptr();
    i.fields_len = fields.len();
    i.body = body.as_ptr();
    i.body_len = body.len();
    i.sink = bufs.sink();
    let mut o: FramerOut = blank_out();
    ready(door.cross(Call::Encode(&mut i, &mut o)))?;
    let mut y = Yielded::default();
    // `encode` has no framing to continue: a re-call would render the message again from its
    // start. So it answers whole into the buffer sized for it, and a framer that answers it
    // `YIELD_MORE` owes bytes no re-call can ask for: a FAULT, never a truncated message sent as
    // the whole one.
    if !bufs.take(&o, &mut y)? {
        return Err(Refused {
            outcome: Outcome::Fault,
            error: "the framer answered `encode` with YIELD_MORE: an encode renders the whole \
                    message into one buffer sized for it"
                .to_owned(),
        });
    }
    Ok(y.wire)
}

/// How many `YIELD_MORE` answers in a row may write nothing before the framing FAULTs: a framer
/// that owes more and gives nothing would otherwise hold the host worker forever (Law 0).
pub(crate) const MORE_STALLS: usize = 64;

/// The most bytes one op's `YIELD_MORE` re-calls may write before the framing FAULTs: an op's own
/// input is bounded (a socket read, a write under the write buffer), so a framer that keeps writing
/// past this is not answering it.
pub(crate) const MORE_BYTES: u64 = 64 * 1024 * 1024;

/// Whether one answer wrote anything: wire bytes, frame bytes, a piece or a head.
pub(crate) fn wrote(o: &FramerOut) -> bool {
    let y = &o.yielded;
    y.wire_len != 0 || y.frame_len != 0 || y.pieces_len != 0 || y.heads_len != 0
}

/// The re-calls of one op: their count with nothing written, and the bytes written.
#[derive(Default)]
pub(crate) struct Recalls {
    stalls: usize,
    bytes: u64,
}

impl Recalls {
    /// Count one more answer that owed more: a FAULT once [`MORE_STALLS`] in a row wrote nothing,
    /// or the op's answers wrote past [`MORE_BYTES`].
    pub(crate) fn owed(&mut self, o: &FramerOut) -> Result<(), Refused> {
        self.stalls = if wrote(o) { 0 } else { self.stalls + 1 };
        self.bytes = self
            .bytes
            .saturating_add(o.yielded.wire_len)
            .saturating_add(o.yielded.frame_len);
        if self.stalls >= MORE_STALLS {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: format!(
                    "the framer owed more {MORE_STALLS} times in a row and wrote nothing"
                ),
            });
        }
        if self.bytes > MORE_BYTES {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: format!("the framer's answers to one op ran past {MORE_BYTES} bytes"),
            });
        }
        Ok(())
    }
}

/// Which op a `YIELD_MORE` re-call repeats.
#[derive(Clone, Copy)]
enum Again {
    Ingest,
    Timer,
    Refuse(Option<u64>, u32, bool),
}

impl Framing {
    /// `begin`: open a framing on `side` (`SIDE_*`) for `target`, over what the handshake
    /// established.
    ///
    /// # Errors
    ///
    /// The entry refused to frame the connection.
    pub fn begin(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
    ) -> Result<(Self, Yielded), Refused> {
        Self::begin_with(door, side, target, established, &[])
    }

    /// [`Framing::begin`], handing a dialled framing its OPENING head fields (`BeginIn::fields`:
    /// the request's own lines, never the binding's auth fields, which the framer gets from its
    /// own auth call), for a wire that carries them on the connection's opening rather than on a
    /// message (ARCHITECT Q-L5B-WS-DIAL). Ticket-less: its binding has no auth.
    ///
    /// # Errors
    ///
    /// The entry refused to frame the connection.
    pub fn begin_with(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
    ) -> Result<(Self, Yielded), Refused> {
        Self::begin_ticketless(door, side, target, established, opening, &AuthBinding::NONE)
    }

    /// [`Framing::begin_with`] TICKET-LESS over `binding`: refused, before anything crosses, when
    /// the binding has auth points ([`TICKET_LESS_AUTH`]): its framer's ops may call the auth
    /// service, which may pend, and only a ticketed framing ([`Framing::begin_bound`]) can park
    /// one.
    ///
    /// # Errors
    ///
    /// [`TICKET_LESS_AUTH`], or the entry refused to frame the connection.
    pub fn begin_ticketless(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
        binding: &AuthBinding,
    ) -> Result<(Self, Yielded), Refused> {
        binding.ticket_less()?;
        Self::begin_on(door, None, side, target, established, opening, *binding)
    }

    /// [`Framing::begin_bound`] with a binding that has no auth.
    ///
    /// # Errors
    ///
    /// The entry refused to frame the connection.
    pub fn begin_ticketed(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
    ) -> Result<(Self, Yielded), Refused> {
        Self::begin_bound(door, side, target, established, opening, &AuthBinding::NONE)
    }

    /// [`Framing::begin_with`] ON TICKETS ([`FramerDoor::framing_side`]), over `binding` (handed
    /// to the framer as [`BeginIn::points`] and [`BeginIn::auth`] on a dial): its `begin`,
    /// `ingest` and `emit` are ticketed ops, each of which may call the host's auth service and
    /// answer PENDING. A pending op PARKS on its own ticket ([`Framing::parked`]): it yields
    /// nothing yet, and the holder re-drives it with [`Framing::poll_parked`] once the ticket's
    /// wake fires, re-issuing the same op on the same ticket, so the service answers its stored
    /// result and runs once. A pending answer parks only its own stream: a parked `begin` holds
    /// the framing, a parked `emit` holds its stream's later emits, and every other op crosses on
    /// another ticket meanwhile.
    ///
    /// # Errors
    ///
    /// The entry refused to frame the connection; [`TICKET_LESS_AUTH`] when the entry gives no
    /// ticket and the binding has auth points.
    pub fn begin_bound(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
        binding: &AuthBinding,
    ) -> Result<(Self, Yielded), Refused> {
        let ticket = door.framing_side();
        if ticket.is_none() {
            binding.ticket_less()?;
        }
        Self::begin_on(door, ticket, side, target, established, opening, *binding)
    }

    fn begin_on(
        door: Arc<dyn FramerDoor>,
        ticket: Option<Box<dyn crate::carrier::Side>>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
        binding: AuthBinding,
    ) -> Result<(Self, Yielded), Refused> {
        let mut f = Self {
            door,
            token: 0,
            bufs: Buffers::for_side(side),
            ticketed: ticket.is_some(),
            idle: Vec::new(),
            parked: Vec::new(),
        };
        let op = Ticketed::Begin {
            side,
            target: target.to_owned(),
            established: established.clone(),
            opening: opening.to_vec(),
            binding,
        };
        let y = f.run(op, Yielded::default(), false, false, ticket)?;
        Ok((f, y.unwrap_or_default()))
    }

    /// Whether any ticketed op is parked, waiting for its ticket's wake.
    #[must_use]
    pub fn parked(&self) -> bool {
        !self.parked.is_empty()
    }

    /// Whether the framing's `begin` is parked: no other op crosses until it completes.
    #[must_use]
    pub fn begin_parked(&self) -> bool {
        self.parked
            .iter()
            .any(|p| matches!(p.op, Ticketed::Begin { .. }))
    }

    /// Whether `stream` is held: the framing's `begin` is parked, or an `emit` on `stream` is.
    /// A held stream's next emit waits, in order, for the parked op to complete.
    #[must_use]
    pub fn holds(&self, stream: u64) -> bool {
        self.parked.iter().any(|p| match p.op.stream() {
            Some(s) => s == stream,
            None => matches!(p.op, Ticketed::Begin { .. }),
        })
    }

    /// RE-DRIVE THE PARKED OPS, each on its own ticket: `cx`'s waker registered on the ticket
    /// first, then the same op re-issued on it as a resume. `Ready` with everything the ops that
    /// completed yielded, in the order they parked, once at least one completes; `Pending` while
    /// every one still waits (the wake re-polls). With nothing parked, `Ready` with nothing.
    ///
    /// # Errors
    ///
    /// The framer failed an op.
    pub fn poll_parked(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Yielded, Refused>> {
        if self.parked.is_empty() {
            return std::task::Poll::Ready(Ok(Yielded::default()));
        }
        let mut waiting = std::mem::take(&mut self.parked).into_iter();
        let mut out = Yielded::default();
        let (mut completed, mut failed) = (false, None);
        for p in waiting.by_ref() {
            p.ticket.register(cx.waker());
            match self.run(p.op, p.yielded, p.recall, true, Some(p.ticket)) {
                Ok(Some(y)) => {
                    merge(&mut out, y);
                    completed = true;
                }
                Ok(None) => {}
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = failed {
            // The ops not re-driven stay parked, for the close to cancel.
            self.parked.extend(waiting);
            return std::task::Poll::Ready(Err(e));
        }
        if completed {
            std::task::Poll::Ready(Ok(out))
        } else {
            std::task::Poll::Pending
        }
    }

    /// A ticket for the next ticketed op: an idle one the framing holds, else a new one; `None` on
    /// a ticket-less framing.
    fn take_ticket(&mut self) -> Result<Option<Box<dyn crate::carrier::Side>>, Refused> {
        if !self.ticketed {
            return Ok(None);
        }
        if let Some(t) = self.idle.pop() {
            return Ok(Some(t));
        }
        if self.parked.len() >= MAX_PARKED {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: format!("more than {MAX_PARKED} ops are parked on the framing"),
            });
        }
        self.door.framing_side().map(Some).ok_or_else(|| Refused {
            outcome: Outcome::Fault,
            error: "no ticket is left for the framing's op".into(),
        })
    }

    /// A ticket whose op completed: kept idle for the next op, or let go.
    fn give_back(&mut self, ticket: Option<Box<dyn crate::carrier::Side>>) {
        if let Some(t) = ticket.filter(|_| self.idle.len() < IDLE_TICKETS) {
            self.idle.push(t);
        }
    }

    /// One crossing of `op` on `ticket` (ticket-less when `None`): `recall` is a `YIELD_MORE`
    /// re-call and `resume` a parked op's re-issue, each carrying no new bytes.
    fn cross_ticketed(
        &mut self,
        op: &Ticketed<'_>,
        recall: bool,
        resume: bool,
        ticket: Option<&dyn crate::carrier::Side>,
    ) -> (Crossed, FramerOut) {
        let sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        let door = &self.door;
        let cross = |call: Call<'_>| match ticket {
            Some(side) => door.cross_on(side, resume, call),
            None => door.cross(call),
        };
        let fresh = !recall && !resume;
        let c = match op {
            Ticketed::Begin {
                side,
                target,
                established,
                opening,
                binding,
            } => {
                let facts = established.facts();
                let fields: Vec<Field> = opening
                    .iter()
                    .map(|(n, v)| Field {
                        name: abi(n.as_bytes()),
                        value: abi(v),
                    })
                    .collect();
                let mut i: BeginIn = blank_in();
                i.side = *side;
                i.scheme = established.scheme;
                i.target = abi(target.as_bytes());
                i.facts = &facts;
                if !fields.is_empty() {
                    i.fields = fields.as_ptr();
                    i.fields_len = fields.len();
                }
                if *side == SIDE_DIAL {
                    i.points = binding.points;
                    i.auth = binding.auth;
                }
                i.sink = sink;
                cross(Call::Begin(&mut i, &mut o))
            }
            Ticketed::Ingest { bytes, end } => {
                let mut i: IngestIn = blank_in();
                i.framing = self.token;
                if fresh {
                    i.bytes = bytes.as_ptr();
                    i.len = bytes.len();
                    i.end = u32::from(*end);
                }
                i.sink = sink;
                cross(Call::Ingest(&mut i, &mut o))
            }
            Ticketed::Emit {
                stream,
                bytes,
                end_of_frame,
                text,
                body_len,
            } => {
                let mut i: EmitIn = blank_in();
                i.framing = self.token;
                i.stream = *stream;
                if fresh {
                    i.bytes = bytes.as_ptr();
                    i.len = bytes.len();
                    i.end_of_frame = u32::from(*end_of_frame);
                    i.flags = if *text { EMIT_TEXT } else { 0 };
                }
                // The opening body's length rides every crossing of the head's emit, and only
                // on a dialled framing.
                if let Some(len) = body_len.filter(|_| self.bufs.side == SIDE_DIAL) {
                    i.body_len = len;
                    i.body_len_known = 1;
                }
                i.sink = sink;
                cross(Call::Emit(&mut i, &mut o))
            }
        };
        (c, o)
    }

    /// Run a ticketed op on `ticket` until it owes nothing more: `Some` with what it yielded,
    /// `None` = it answered PENDING on its ticket and is parked (holding the ticket). `resume`
    /// re-issues a parked op. A ticket whose op completed or failed is the framing's again.
    fn run(
        &mut self,
        op: Ticketed<'_>,
        yielded: Yielded,
        recall: bool,
        resume: bool,
        ticket: Option<Box<dyn crate::carrier::Side>>,
    ) -> Result<Option<Yielded>, Refused> {
        let mut ticket = ticket;
        let r = self.run_on(op, yielded, recall, resume, &mut ticket);
        self.give_back(ticket);
        r
    }

    /// [`Framing::run`]'s loop: a parked op takes `ticket` with it.
    fn run_on(
        &mut self,
        op: Ticketed<'_>,
        mut yielded: Yielded,
        mut recall: bool,
        mut resume: bool,
        ticket: &mut Option<Box<dyn crate::carrier::Side>>,
    ) -> Result<Option<Yielded>, Refused> {
        let mut recalls = Recalls::default();
        loop {
            let (c, o) = self.cross_ticketed(&op, recall, resume, ticket.as_deref());
            resume = false;
            if c.outcome == Outcome::Pending {
                if let Some(t) = ticket.take() {
                    self.parked.push(Parked {
                        op: op.owned(),
                        yielded,
                        recall,
                        ticket: t,
                    });
                    return Ok(None);
                }
            }
            ready(c)?;
            let begin = matches!(op, Ticketed::Begin { .. });
            if begin {
                self.token = o.framing;
            }
            if self.bufs.take(&o, &mut yielded)? {
                return Ok(Some(yielded));
            }
            if begin {
                // What `begin` still owes comes out on `timer` re-calls, never another `begin`.
                self.more(Again::Timer, &mut yielded)?;
                return Ok(Some(yielded));
            }
            if recall {
                recalls.owed(&o)?;
            }
            recall = true;
        }
    }

    /// Refused while the framing's `begin` is parked, or (`stream`) while an op parked on that
    /// stream holds it.
    fn idle(&self, stream: Option<u64>) -> Result<(), Refused> {
        let held = match stream {
            Some(s) => self.holds(s),
            None => self.begin_parked(),
        };
        if held {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: "an op is parked on the framing's ticket".into(),
            });
        }
        Ok(())
    }

    /// Refused while any op is parked: the op ends or hands off the whole framing.
    fn quiet(&self) -> Result<(), Refused> {
        if self.parked() {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: "an op is parked on the framing's ticket".into(),
            });
        }
        Ok(())
    }

    /// `adopt`: open a framing over a connection another framing detached, its `leftover` bytes
    /// first.
    ///
    /// # Errors
    ///
    /// The entry refused to adopt it.
    pub fn adopt(
        door: Arc<dyn FramerDoor>,
        side: u32,
        leftover: &[u8],
        established: &Established,
    ) -> Result<(Self, Yielded), Refused> {
        let mut bufs = Buffers::for_side(side);
        let facts = established.facts();
        let mut i: AdoptIn = blank_in();
        i.side = side;
        i.facts = &facts;
        i.leftover = leftover.as_ptr();
        i.leftover_len = leftover.len();
        i.sink = bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(door.cross(Call::Adopt(&mut i, &mut o)))?;
        let mut f = Self {
            door,
            token: o.framing,
            bufs,
            ticketed: false,
            idle: Vec::new(),
            parked: Vec::new(),
        };
        let mut y = Yielded::default();
        if !f.bufs.take(&o, &mut y)? {
            f.more(Again::Ingest, &mut y)?;
        }
        Ok((f, y))
    }

    /// The entry this framing is on.
    #[must_use]
    pub fn door(&self) -> &Arc<dyn FramerDoor> {
        &self.door
    }

    /// Re-call `again` with no new bytes until the framer owes nothing more.
    fn more(&mut self, again: Again, y: &mut Yielded) -> Result<(), Refused> {
        let mut recalls = Recalls::default();
        loop {
            let sink = self.bufs.sink();
            let mut o: FramerOut = blank_out();
            let c = match again {
                Again::Ingest => {
                    let mut i: IngestIn = blank_in();
                    i.framing = self.token;
                    i.sink = sink;
                    self.door.cross(Call::Ingest(&mut i, &mut o))
                }
                Again::Refuse(stream, status, head_sent) => {
                    let mut i: RefuseIn = blank_in();
                    i.framing = self.token;
                    i.stream = stream.unwrap_or(0);
                    i.has_stream = u32::from(stream.is_some());
                    i.status = status;
                    i.head_sent = u32::from(head_sent);
                    i.sink = sink;
                    self.door.cross(Call::Refuse(&mut i, &mut o))
                }
                Again::Timer => {
                    let mut i: FramingIn = blank_in();
                    i.framing = self.token;
                    i.sink = sink;
                    self.door.cross(Call::Timer(&mut i, &mut o))
                }
            };
            ready(c)?;
            if self.bufs.take(&o, y)? {
                return Ok(());
            }
            recalls.owed(&o)?;
        }
    }

    /// `ingest`: what the far side sent (`end` = it ended). On a ticketed framing a PENDING answer
    /// parks it on its own ticket ([`Framing::parked`]): it yields nothing until
    /// [`Framing::poll_parked`] completes it, and the framer took its bytes whole, so a later
    /// `ingest` crosses meanwhile on another ticket, carrying the bytes the far end sent next (the
    /// framer holds back only the stream whose auth it waits on).
    ///
    /// # Errors
    ///
    /// The framer failed the connection; the framing's `begin` is parked.
    pub fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<Yielded, Refused> {
        self.idle(None)?;
        let op = Ticketed::Ingest {
            bytes: std::borrow::Cow::Borrowed(bytes),
            end,
        };
        let ticket = self.take_ticket()?;
        Ok(self
            .run(op, Yielded::default(), false, false, ticket)?
            .unwrap_or_default())
    }

    /// `emit`: bytes for the far side, on `stream`; `text`: they are a text message (`EMIT_TEXT`).
    /// On a ticketed framing a PENDING answer parks it on its own ticket, holding `stream` alone
    /// ([`Framing::holds`]): the other streams' emits keep crossing.
    ///
    /// # Errors
    ///
    /// The framer refused them; `stream` is held.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
    ) -> Result<Yielded, Refused> {
        self.emit_opening(stream, bytes, end_of_frame, text, None)
    }

    /// [`Framing::emit`] of the emit that carries a DIALLED request's head, with the length of
    /// the body the request opens with where the host holds it whole (`body_len`, stated as
    /// [`EmitIn::body_len`]); `None` = a streamed body, whose length no line states. An accepting
    /// framing states none.
    ///
    /// # Errors
    ///
    /// The framer refused them; `stream` is held.
    pub fn emit_opening(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        body_len: Option<u64>,
    ) -> Result<Yielded, Refused> {
        self.idle(Some(stream))?;
        let op = Ticketed::Emit {
            stream,
            bytes: std::borrow::Cow::Borrowed(bytes),
            end_of_frame,
            text,
            body_len,
        };
        let ticket = self.take_ticket()?;
        Ok(self
            .run(op, Yielded::default(), false, false, ticket)?
            .unwrap_or_default())
    }

    /// `refuse`: a refusal's bytes for `stream` (`None` = the whole connection), with its neutral
    /// `status` for the framer to map to its wire (`0` = none stated). `head_sent` = the host already
    /// sent the stream's response head, so the refusal is its closing lines only (never on a
    /// refusal for the whole connection).
    ///
    /// # Errors
    ///
    /// The framer refused to render it.
    pub fn refuse(
        &mut self,
        stream: Option<u64>,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Result<Yielded, Refused> {
        self.idle(stream)?;
        let head_sent = head_sent && stream.is_some();
        let mut i: RefuseIn = blank_in();
        i.framing = self.token;
        i.stream = stream.unwrap_or(0);
        i.has_stream = u32::from(stream.is_some());
        i.status = status;
        i.head_sent = u32::from(head_sent);
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(self.door.cross(Call::Refuse(&mut i, &mut o)))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            self.more(Again::Refuse(stream, status, head_sent), &mut y)?;
        }
        Ok(y)
    }

    /// `timer`: the deadline the framer asked for passed.
    ///
    /// # Errors
    ///
    /// The framer failed the connection.
    pub fn timer(&mut self) -> Result<Yielded, Refused> {
        self.idle(None)?;
        let mut y = Yielded::default();
        self.more(Again::Timer, &mut y)?;
        Ok(y)
    }

    /// `detach`: the bytes the framer took and did not answer, and the framing is over.
    ///
    /// # Errors
    ///
    /// The framer refused to give the connection up.
    pub fn detach(mut self) -> Result<Vec<u8>, Refused> {
        self.quiet()?;
        let mut left = Vec::new();
        let mut recalls = Recalls::default();
        loop {
            let mut i: FramingIn = blank_in();
            i.framing = self.token;
            i.sink = self.bufs.sink();
            let mut o: FramerOut = blank_out();
            ready(self.door.cross(Call::Detach(&mut i, &mut o)))?;
            let n = usize::try_from(o.yielded.frame_len).unwrap_or(usize::MAX);
            left.extend_from_slice(self.bufs.frame.get(..n).ok_or_else(|| Refused {
                outcome: Outcome::Fault,
                error: "the framer's answer is out of bounds: frame".into(),
            })?);
            if o.yielded.flags & YIELD_MORE == 0 {
                self.token = 0;
                return Ok(left);
            }
            recalls.owed(&o)?;
        }
    }

    /// `finish`: close the framing with `reason` (`CLOSE_*`); what it still owes the far side.
    pub fn finish(mut self, reason: u32) -> Yielded {
        self.close(reason)
    }

    /// `finish` on ONE STREAM'S framing ([`busbar_contract::abi::transport::SIDE_ACCEPT_STREAM`]):
    /// close it with the final status the unit stated (ARCHITECT 4l), judged first against the
    /// status rows of the claim the stream arrived on (`rows`, `claim`). A status the claim's
    /// numbering does not have never reaches the framer: the close is refused here and the framing
    /// stays open, so the host can still end the stream another way. What the framer answers is
    /// the stream's closing field block, in `wire`.
    ///
    /// # Errors
    ///
    /// The close breaks [`check_final_status`] (FAULT, nothing crossed), or the framer refused it.
    pub fn finish_final(
        &mut self,
        status: u32,
        message: &[u8],
        details: &[u8],
        rows: &[StatusRow],
        claim: u32,
    ) -> Result<Yielded, Refused> {
        self.quiet()?;
        let mut bytes = Vec::with_capacity(message.len() + details.len());
        bytes.extend_from_slice(message);
        bytes.extend_from_slice(details);
        let span = |offset: usize, len: usize| -> Result<Span, Refused> {
            Ok(Span {
                offset: u32::try_from(offset).map_err(|_| too_long())?,
                len: u32::try_from(len).map_err(|_| too_long())?,
            })
        };
        let mut i: FinishIn = blank_in();
        i.framing = self.token;
        i.reason = CLOSE_NORMAL;
        i.final_status = status;
        i.final_message = span(0, message.len())?;
        i.final_details = span(message.len(), details.len())?;
        i.final_bytes = bytes.as_ptr();
        i.final_bytes_len = bytes.len();
        check_final_status(&i, rows, claim).map_err(|f| Refused {
            outcome: Outcome::Fault,
            error: format!(
                "the stream's final status breaks {:?} at {}",
                f.rule, f.field
            ),
        })?;
        if self.token == 0 {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: "the stream's framing is already closed".into(),
            });
        }
        let mut y = Yielded::default();
        let mut recalls = Recalls::default();
        loop {
            i.sink = self.bufs.sink();
            let mut o: FramerOut = blank_out();
            ready(self.door.cross(Call::Finish(&mut i, &mut o)))?;
            if self.bufs.take(&o, &mut y)? {
                self.token = 0;
                return Ok(y);
            }
            recalls.owed(&o)?;
        }
    }

    fn close(&mut self, reason: u32) -> Yielded {
        let mut y = Yielded::default();
        self.cancel_parked();
        if self.token == 0 {
            return y;
        }
        let mut i: FinishIn = blank_in();
        i.framing = self.token;
        i.reason = reason;
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        if self.door.cross(Call::Finish(&mut i, &mut o)).outcome == Outcome::Ready {
            let _ = self.bufs.take(&o, &mut y);
        }
        self.token = 0;
        y
    }
}

impl Framing {
    /// CANCEL every op parked on the framing's tickets, each on its own (`abi::mechanism::lifecycle`,
    /// `cancel`, made on no ticket: the ticket it cancels rides its `in`).
    fn cancel_parked(&mut self) {
        for p in std::mem::take(&mut self.parked) {
            let side = p.ticket.as_ref();
            let mut i: busbar_contract::abi::mechanism::lifecycle::CancelIn = blank_in();
            i.ticket = side.ticket();
            let mut o: busbar_contract::abi::mechanism::lifecycle::CancelOut = blank_out();
            let _ = self
                .door
                .carry(side, false, crate::carrier::Carry::Cancel(&mut i, &mut o));
        }
    }
}

/// What one more completed op yielded, after what `into` holds: its head slots, wire bytes and
/// pieces in order, its end, and the deadline it stated last.
fn merge(into: &mut Yielded, y: Yielded) {
    into.heads.extend(y.heads);
    into.wire.extend(y.wire);
    into.pieces.extend(y.pieces);
    into.ended |= y.ended;
    into.deadline_ns = y.deadline_ns.or(into.deadline_ns);
}

/// A final status whose message or details no `Span` can carry.
fn too_long() -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: "the stream's final status is longer than a span carries".into(),
    }
}

impl Drop for Framing {
    fn drop(&mut self) {
        let _ = self.close(busbar_contract::abi::transport::CLOSE_NORMAL);
    }
}

#[cfg(test)]
#[path = "tests/framer_tests.rs"]
mod tests;
