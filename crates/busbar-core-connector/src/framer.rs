// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER A CONNECTION CARRIES: one transport entry's table, driven host-side.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::route::{FieldPredicate, RouteMatch};
use busbar_contract::abi::transport::sensitive_fields::SensitiveFields;
use busbar_contract::abi::transport::LineEntry;
use busbar_contract::abi::transport::{check::check_final_status, StatusRow, CLOSE_NORMAL};
use busbar_contract::abi::transport::{
    AdoptIn, BeginIn, ConnFacts, EmitIn, EncodeIn, FinishIn, FramePiece, FrameSpan, FramerOut,
    FramerSink, FramingIn, HeadSlots, IngestIn, LocateIn, LocateOut, RefuseIn, EMIT_TEXT,
    EMIT_TRAILERS, PIECE_CODE_HANDOFF, PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_DECLARED_LEN, PIECE_HAS_RETRY_AFTER, PIECE_INTERIM,
    PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED,
    YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
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
    /// The tail's ROLE (`ROLE_CARRIER` | `ROLE_FRAMER`): a CARRIER is a byte stream the host's
    /// socket or pipe carries as itself (no opening message, nothing framed, a stream it may secure
    /// mid-way); a FRAMER frames messages over the carrier the connector chose from the target's
    /// scheme. The role is stated, never derived from `composes_over`.
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
    /// THE DUPLEX CLAIMS: the ones a stream rides, read off the claim rows of its Statement: each
    /// whose unit 0 opens at an UPGRADE (`UNIT0_UPGRADE`) or that carries a session (`session`). A
    /// claim that states neither is a request and its answer, which the listener it arrived on
    /// frames already; a stream on one of these is this entry's to frame.
    pub duplex: Vec<&'static str>,
    /// THE DATAGRAM FRAMER (its tail states `FRAMING_DATAGRAM`): every call carries the datagram
    /// lane and it is driven only by [`crate::datagram::DatagramFraming`] over the host's port and
    /// secure layer; it never frames a stream, whatever its claim rows say.
    pub datagram: bool,
}

/// A transport entry's table, as the host reaches it: a framer's ops ([`FramerDoor::cross`]) and a
pub trait FramerDoor: Send + Sync {
    /// What the entry states.
    fn facts(&self) -> &DoorFacts;
    /// The entry renders sealed values (`abi::transport::EXT_SEALED_VALUES`): the host hands it
    fn seals_values(&self) -> bool {
        false
    }
    /// One crossing: the op, answered into its `out`.
    fn cross(&self, call: Call<'_>) -> Crossed;
    /// Its tail states `FACT_ACCEPTS`: its framer begins on the accepting side, so a listener may
    fn accepts(&self) -> bool {
        false
    }
    /// The identity of the instance the host opened for it (the one its host service calls are
    fn instance(&self) -> Option<u64> {
        None
    }
    /// The host's opaque I/O owner for this supplier. This is the checked host context handle,
    fn io_owner(&self) -> Option<u64> {
        None
    }
    /// A new side of a carried connection: a ticket the entry's carrier ops are driven on inline
    fn side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        None
    }
    /// One CARRIER crossing on `side` (a RESUME of the op that pended on it when `resume`). An entry
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
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        None
    }
    /// One crossing of a TICKETED framer op on `side`'s ticket (a RESUME of the op that pended on
    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        let _ = (side, resume);
        self.cross(call)
    }

    /// Create host-only framing ownership before Begin/Adopt. Contextless doubles return none.
    fn framing_context(
        &self,
        listener: u64,
        connection: u64,
    ) -> Result<Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>, Refused> {
        let _ = (listener, connection);
        Ok(None)
    }

    /// Create a destination leg using the detached source's trusted admission custody.
    fn adopting_context(
        &self,
        source: Arc<dyn busbar_contract::framing_scope::FramingScope>,
    ) -> Result<Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>, Refused> {
        let _ = source;
        Err(Refused {
            outcome: Outcome::Refused,
            error: "the door cannot inherit a host session".into(),
        })
    }

    /// One framing crossing with its host context, including ticketless operations and resumes.
    fn cross_scoped(
        &self,
        context: Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        side: Option<&dyn crate::carrier::Side>,
        resume: bool,
        call: Call<'_>,
    ) -> Crossed {
        let _ = context;
        match side {
            Some(side) => self.cross_on(side, resume, call),
            None => self.cross(call),
        }
    }

    /// Cancellation carries the same framing ownership as the operation it cancels.
    fn cancel_scoped(
        &self,
        context: Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        side: &dyn crate::carrier::Side,
        call: crate::carrier::Carry<'_>,
    ) -> Crossed {
        let _ = context;
        self.carry(side, false, call)
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
    /// `status_code` is in the numbering of the handshake the connection opened with, the
    /// status-line one (`PIECE_CODE_HANDOFF`), not the claim's own.
    pub handoff: bool,
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

/// A stream's backpressure change, retained in crossing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFlow {
    /// The emit was taken; further emits wait for this stream to become writable.
    Full(u64),
    /// The stream may be emitted on again; this signal is never payload.
    Writable(u64),
}

/// Everything one op answered, across its `YIELD_MORE` re-calls.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Yielded {
    /// A datagram producer still owes a same-op recall or secure-layer settle.
    pub continuing: bool,
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
    /// Stream backpressure changes, including the original stream of resumed emits.
    pub flow: Vec<StreamFlow>,
    /// The INTERIM heads (`PIECE_INTERIM` field blocks, a `1xx` ahead of the final head), in
    /// order. Never the answer's head: they are not among [`Yielded::pieces`], whose first field
    /// block on a stream stays its final head.
    pub interim: Vec<Got>,
    /// The protocol the framer last stated it agreed on an accepted connection
    /// (`FramerYield::agreed`): a 1-based position in its accepting offer; `0` = not stated.
    pub agreed: u32,
    /// Independent reservations for each `pieces` allocation and its later queue/reader owners.
    pub piece_custody: Vec<crate::publication::Custody>,
    /// Host storage custody, declared after payloads so allocation retirement precedes credit.
    pub custody: crate::publication::Custody,
    /// A crossing/output owner retained until the pairing classifies even a late closed batch.
    pub producer: crate::publication::ProducerCustody,
}

impl Drop for Yielded {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.wire);
    }
}

impl Yielded {
    /// Grow on a fresh allocation: reallocating a live Vec would retire credential-bearing wire
    fn extend_wire(&mut self, bytes: &[u8]) {
        let required = self
            .wire
            .len()
            .checked_add(bytes.len())
            .expect("framer wire length overflow");
        if required > self.wire.capacity() {
            let capacity = required.max(self.wire.capacity().saturating_mul(2));
            let mut grown = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&self.wire);
            zeroize::Zeroize::zeroize(&mut self.wire);
            self.wire = std::mem::take(&mut *grown);
        }
        self.wire.extend_from_slice(bytes);
    }

    pub(crate) fn adoption_bound(&self) -> Option<usize> {
        use std::mem::size_of;
        let containers = self.retained_capacity().checked_add(
            self.pieces
                .len()
                .checked_mul(size_of::<crate::publication::Custody>())?,
        )?;
        self.pieces.iter().try_fold(containers, |sum, piece| {
            let bytes = piece
                .bytes
                .capacity()
                .checked_add(piece.reason.as_ref().map_or(0, Vec::capacity))?
                .checked_add(if piece.fields { piece.bytes.len() } else { 0 })?
                .checked_add(
                    3 * size_of::<Got>()
                        + 3 * size_of::<crate::publication::Message>()
                        + 16 * size_of::<usize>(),
                )?;
            sum.checked_add(crate::publication::Memory::reservation_size(bytes)?)
        })
    }

    pub(crate) fn split_piece_custody(&mut self) {
        if !self.custody.tracked() {
            return;
        }
        use std::mem::size_of;
        self.piece_custody = Vec::with_capacity(self.pieces.len());
        for piece in &self.pieces {
            let bytes = piece.bytes.capacity()
                + piece.reason.as_ref().map_or(0, Vec::capacity)
                + if piece.fields { piece.bytes.len() } else { 0 }
                + 3 * size_of::<Got>()
                + 3 * size_of::<crate::publication::Message>()
                + 16 * size_of::<usize>();
            self.piece_custody.push(self.custody.split(bytes));
        }
    }

    pub(crate) fn retained_capacity(&self) -> usize {
        use std::mem::size_of;
        let piece = |got: &Got| got.bytes.capacity() + got.reason.as_ref().map_or(0, Vec::capacity);
        let head = |head: &Head| {
            [&head.method, &head.target, &head.authority, &head.reason]
                .into_iter()
                .map(|slot| slot.as_ref().map_or(0, Vec::capacity))
                .sum::<usize>()
        };
        self.wire.capacity()
            + self.pieces.capacity() * size_of::<Got>()
            + self.interim.capacity() * size_of::<Got>()
            + self.heads.capacity() * size_of::<Head>()
            + self.flow.capacity() * size_of::<StreamFlow>()
            + self.piece_custody.capacity() * size_of::<crate::publication::Custody>()
            + self.interim.iter().map(piece).sum::<usize>()
            + self.heads.iter().map(head).sum::<usize>()
            + self.interim.len()
                * (3 * size_of::<Got>()
                    + 3 * size_of::<crate::publication::Message>()
                    + 16 * size_of::<usize>())
            + 4 * size_of::<Yielded>()
            + 32 * size_of::<usize>()
    }
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

impl Drop for Buffers {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.wire);
    }
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
    /// Work retained by a validated answer. Count each independent copy, including overlapping
    fn output_work(&self, o: &FramerOut) -> u64 {
        use std::mem::size_of;
        let y = &o.yielded;
        let Some(pieces) = self.pieces.get(..y.pieces_len as usize) else {
            return u64::MAX;
        };
        let Some(heads) = self.heads.get(..y.heads_len as usize) else {
            return u64::MAX;
        };
        let mut copied = 0_u64;
        let mut metadata = 0_u64;
        for piece in pieces {
            if piece.flags & PIECE_WRITABLE != 0 {
                metadata = metadata.saturating_add(size_of::<StreamFlow>() as u64);
            } else {
                metadata = metadata.saturating_add(size_of::<Got>() as u64);
                copied = copied.saturating_add(piece.len);
            }
        }
        for head in heads {
            metadata = metadata.saturating_add(size_of::<Head>() as u64);
            for slot in [head.method, head.target, head.authority, head.reason] {
                copied = copied.saturating_add(slot.len);
            }

            copied = copied.saturating_add(head.reason.len);
        }
        if y.flags & YIELD_STREAM_FULL != 0 {
            metadata = metadata.saturating_add(size_of::<StreamFlow>() as u64);
        }
        y.wire_len
            .saturating_add(y.frame_len.max(copied))
            .saturating_add(metadata)
    }

    pub(crate) fn field_storage(&self) -> usize {
        if self.lines.open.capacity() == 0 {
            return 0;
        }
        (self.lines.open.capacity() + 8)
            * 4
            * (std::mem::size_of::<(u64, Line)>() + std::mem::align_of::<(u64, Line)>())
    }
    /// Conservative deep-copy storage for one answer, including independently overlapping
    pub(crate) fn retention_bound(&self) -> Option<usize> {
        use std::mem::size_of;
        let pieces = self.pieces.len();
        let heads = self.heads.len();
        let payload = pieces
            .checked_mul(self.frame.len())?
            .checked_mul(2)?
            .checked_add(heads.checked_mul(5)?.checked_mul(self.frame.len())?)?
            .checked_add(self.wire.len())?;
        let metadata = pieces
            .checked_mul(
                8 * size_of::<Got>()
                    + 8 * size_of::<StreamFlow>()
                    + 8 * size_of::<crate::publication::Message>()
                    + 32 * size_of::<usize>(),
            )?
            .checked_add(heads.checked_mul(4 * size_of::<Head>())?)?
            .checked_add(8 * size_of::<Yielded>() + 64 * size_of::<usize>())?;
        let fields = self
            .lines
            .open
            .capacity()
            .checked_add(pieces)?
            .checked_add(8)?
            .checked_mul(8)?
            .checked_mul(size_of::<(u64, Line)>() + std::mem::align_of::<(u64, Line)>())?;
        payload.checked_add(metadata)?.checked_add(fields)
    }

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
        let mut buffers = Self::default();
        buffers.side = side;
        buffers
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
        into.extend_wire(wire);
        #[cfg(test)]
        crate::support::watch_yielded_wire(&into.wire);
        let frame_len = usize::try_from(y.frame_len).map_err(|_| bad("frame"))?;
        let frame = self.frame.get(..frame_len).ok_or_else(|| bad("frame"))?;
        let pieces = self
            .pieces
            .get(..y.pieces_len as usize)
            .ok_or_else(|| bad("pieces"))?;
        let first_piece = into.pieces.len();
        let first_interim = into.interim.len();
        for p in pieces {
            if p.flags & PIECE_WRITABLE != 0 {
                if p.len != 0 || p.flags != PIECE_WRITABLE {
                    return Err(bad("a writable piece with bytes or another flag"));
                }
                into.flow.push(StreamFlow::Writable(p.stream));
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
            let got = Got {
                stream: p.stream,
                bytes: bytes.to_vec(),
                end_of_frame: p.flags & PIECE_END_OF_FRAME != 0,
                status_code: (p.flags & PIECE_HAS_CODE != 0).then_some(p.code),
                handoff: p.flags & PIECE_CODE_HANDOFF != 0,
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
            };
            if p.flags & PIECE_INTERIM != 0 {
                into.interim.push(got);
            } else {
                into.pieces.push(got);
            }
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
            if let Some(reason) = head.reason.clone() {
                if let Some(index) =
                    busbar_contract::abi::transport::check::head_piece_index(h, pieces)
                {
                    let interim = pieces[index].flags & PIECE_INTERIM != 0;
                    let preceding = pieces[..index]
                        .iter()
                        .filter(|p| {
                            if interim {
                                p.flags & PIECE_INTERIM != 0
                            } else {
                                p.flags & (PIECE_INTERIM | PIECE_WRITABLE) == 0
                            }
                        })
                        .count();
                    let target = if interim {
                        &mut into.interim[first_interim..]
                    } else {
                        &mut into.pieces[first_piece..]
                    };
                    if let Some(g) = target.get_mut(preceding) {
                        g.reason = Some(reason);
                    }
                    if interim {
                        continue;
                    }
                } else if let Some(g) = into.pieces[first_piece..]
                    .iter_mut()
                    .find(|g| g.stream == head.stream && g.fields)
                {
                    g.reason = Some(reason);
                }
            }
            into.heads.push(head);
        }
        into.ended |= y.flags & YIELD_ENDED != 0;
        into.deadline_ns = (y.flags & YIELD_HAS_DEADLINE != 0).then_some(y.next_deadline_ns);
        if y.agreed != 0 {
            into.agreed = y.agreed;
        }
        Ok(y.flags & YIELD_MORE == 0)
    }
}

impl Default for Buffers {
    fn default() -> Self {
        Self::new(WIRE_CAP, FRAME_CAP, PIECES_CAP)
    }
}

/// The one instant every host-clock reading ([`now_ns`]) and every instant it names
static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// The host's monotonic clock, nanoseconds since this process first read it, plus one (never `0`:
#[must_use]
pub fn now_ns() -> u64 {
    let epoch = *EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// The host's monotonic instant `ns` names: the exact inverse of [`now_ns`], so one reading names
#[must_use]
pub fn instant_of(ns: u64) -> Instant {
    let epoch = *EPOCH.get_or_init(Instant::now);
    epoch + std::time::Duration::from_nanos(ns.saturating_sub(1))
}

fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Where one connection's framing stands with its entry.
pub struct Framing {
    door: Arc<dyn FramerDoor>,
    context: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    token: u64,
    bufs: Buffers,
    /// Its ticketed ops run on tickets ([`FramerDoor::framing_side`]); `false` = ticket-less.
    ticketed: bool,
    /// The tickets it holds that no op is parked on, for its next ticketed op.
    idle: Vec<Box<dyn crate::carrier::Side>>,
    /// THE TICKETED OPS PARKED, each on its own ticket, in the order they parked: a parked `begin`
    parked: Vec<Parked>,
}

/// A detached connection's bytes and host ownership, consumed by its adopting framing.
#[derive(Debug)]
pub struct Detached {
    bytes: Vec<u8>,
    context: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
}

impl Drop for Detached {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            context.end();
        }
    }
}

/// The most ticketed ops one framing may have parked at once: each holds a ticket of the host's,
pub const MAX_PARKED: usize = 256;

/// How many idle tickets a framing keeps for its next ticketed ops; one let go past it.
const IDLE_TICKETS: usize = 1;

/// THE RULE A TICKET-LESS FRAMING BREAKS when its binding has auth points: a framer whose `begin`,
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

pub use busbar_contract::abi::transport::guest_policy::GuestLine;

/// A LISTENER'S GUEST LIST, in the kernel's match order, as the connector lends it to a framing
/// accepted on the listener. Held by the framing for its life; its `begin` crossing is handed it
/// as [`BeginIn::lines`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLines {
    policy: Arc<busbar_contract::abi::transport::guest_policy::Policy>,
}

impl Default for GuestLines {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl GuestLines {
    /// A standalone list without a host registration.
    #[must_use]
    pub fn new(lines: Vec<GuestLine>) -> Self {
        Self::registered(0, lines)
    }

    /// A list associated with its host listener registration.
    #[must_use]
    pub fn registered(listener: u64, lines: Vec<GuestLine>) -> Self {
        Self::published(Arc::new(
            busbar_contract::abi::transport::guest_policy::Policy {
                listener,
                generation: 0,
                lines,
            },
        ))
    }

    /// The host-selected immutable policy for an opening or stream grant.
    #[must_use]
    pub fn published(policy: Arc<busbar_contract::abi::transport::guest_policy::Policy>) -> Self {
        Self { policy }
    }

    /// The host listener registration associated with this list.
    #[must_use]
    pub fn listener(&self) -> u64 {
        self.policy.listener
    }

    /// Its lines, in match order.
    #[must_use]
    pub fn lines(&self) -> &[GuestLine] {
        &self.policy.lines
    }

    /// The auth points the lines' auths declare, together.
    #[must_use]
    pub fn points(&self) -> u32 {
        self.lines()
            .iter()
            .fold(0, |points, line| points | line.points)
    }
}

/// THE REFUSAL OF A GUEST LIST LENT TO A DIALLED FRAMING: a guest list is a listener's, lent only
pub const LINES_ON_DIAL: &str = "a dialled framing is lent no guest list";

#[derive(Default)]
struct EmitHead {
    body_len: Option<u64>,
    status: u32,
    extensions: Vec<u8>,
    trailers: bool,
}

/// A TICKETED FRAMER OP, as the framing issues it (and re-issues it on a resume): `begin`,
/// `adopt`, `ingest` or `emit`, its bytes borrowed while it crosses and owned once it parks.
#[derive(Debug)]
enum Ticketed<'a> {
    Begin {
        side: u32,
        target: String,
        established: Established,
        opening: Vec<(String, Vec<u8>)>,
        binding: AuthBinding,
        /// The listener's guest list, on an accepting side.
        guests: Option<Arc<GuestLines>>,
    },
    Adopt {
        side: u32,
        established: Established,
        leftover: std::borrow::Cow<'a, [u8]>,
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
        trailers: bool,
        /// The opening body's length on a dialled request's head emit: `Some` = known.
        body_len: Option<u64>,
        /// An accepted stream's answer status, on the emit that carries its head; `0` otherwise.
        status: u32,
        /// Name-only classification of this request head, retained across resumes and drains.
        extensions: Vec<u8>,
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
                guests,
            } => Ticketed::Begin {
                side,
                target,
                established,
                opening,
                binding,
                guests,
            },
            Self::Adopt {
                side, established, ..
            } => Ticketed::Adopt {
                side,
                established,
                leftover: std::borrow::Cow::Owned(Vec::new()),
            },

            Self::Ingest { end, .. } => Ticketed::Ingest {
                bytes: std::borrow::Cow::Owned(Vec::new()),
                end,
            },
            Self::Emit {
                stream,
                end_of_frame,
                text,
                trailers,
                body_len,
                status,
                extensions,
                ..
            } => Ticketed::Emit {
                stream,
                bytes: std::borrow::Cow::Owned(Vec::new()),
                end_of_frame,
                text,
                trailers,
                body_len,
                status,
                extensions,
            },
        }
    }

    /// The stream a parked op holds: an emit's own; `None` for `begin`/`adopt` (the whole
    const fn stream(&self) -> Option<u64> {
        match self {
            Self::Emit { stream, .. } => Some(*stream),
            Self::Begin { .. } | Self::Adopt { .. } | Self::Ingest { .. } => None,
        }
    }
}

/// A ticketed op parked on its own ticket: the op, what its earlier answers yielded, whether it
struct Parked {
    op: Ticketed<'static>,
    yielded: Yielded,
    recall: bool,
    recalls: Recalls,
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

/// A guest line's field predicates as the contract lends them, borrowing the line's strings.
fn predicates_of(l: &GuestLine) -> Vec<FieldPredicate> {
    l.fields
        .iter()
        .map(|(op, name, value)| FieldPredicate {
            op: *op,
            _reserved: 0,
            name: abi(name.as_bytes()),
            value: abi(value),
        })
        .collect()
}

/// A guest line as the contract lends it ([`LineEntry`]), its route's predicates `predicates`
fn entry_of(l: &GuestLine, predicates: &[FieldPredicate]) -> LineEntry {
    LineEntry {
        line: l.line,
        points: l.points,
        auth: l.auth,
        body_limit: l.body_limit,
        route: RouteMatch {
            methods: l.methods,
            path_form: l.path_form,
            path: abi(l.path.as_bytes()),
            fields: if predicates.is_empty() {
                std::ptr::null()
            } else {
                predicates.as_ptr()
            },
            fields_len: predicates.len(),
            rung: l.rung,
            _reserved: 0,
        },
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
    /// The far end's key pin, read off its verified leaf certificate on a secured dial; `None` = no
    /// certificate (the transport pin).
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
    /// The framer's head states its body's length (`LocateOut::states_length`): it renders no
    /// length of its own, so the host states `content-length` for a non-empty body, last, before
    /// the auth signs the head (`busbar_contract::conn::HeadDefaults::completing`).
    pub states_length: bool,
}

/// A protocol offer in the handshake's ProtocolNameList encoding (each name led by its one-byte
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
pub fn locate(door: &dyn FramerDoor, target: &str) -> Result<Located, Refused> {
    locate_as(door, target, false)
}

/// THE OFFER A LISTENER FRAMED BY `door` MAKES in the handshake (ALPN, most preferred first):
pub fn accept_offer(door: &dyn FramerDoor) -> Result<Vec<Vec<u8>>, Refused> {
    locate_as(door, "", true).map(|l| l.offer)
}

/// THE MOST ROOM THE HOST GIVES ONE `locate` ANSWER, per buffer: a short answer naming more is the
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
        let text = |b: &[u8], n: u64, what: &str| -> Result<String, Refused> {
            let bytes = usize::try_from(n)
                .ok()
                .and_then(|n| b.get(..n))
                .ok_or_else(|| Refused {
                    outcome: Outcome::Fault,
                    error: format!("the framer's {what} overruns its locate buffer"),
                })?;
            Ok(String::from_utf8_lossy(bytes).into_owned())
        };
        let authority = text(&authority, o.authority_written, "authority")?;
        let name = text(&name, o.name_written, "name")?;
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
            authority,
            name: (o.has_name != 0).then_some(name),
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
pub fn encode(
    door: &dyn FramerDoor,
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> Result<Vec<u8>, Refused> {
    encode_head(door, b"", b"", fields, body)
}

/// `encode` with the request's head words, `method` and `target` (empty = none): a framer whose
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

    let taken = bufs.take(&o, &mut y);
    let mut wire = zeroize::Zeroizing::new(std::mem::take(&mut y.wire));
    #[cfg(test)]
    crate::support::watch_encoded_wire(&wire);
    if !taken? {
        return Err(Refused {
            outcome: Outcome::Fault,
            error: "the framer answered `encode` with YIELD_MORE: an encode renders the whole \
                    message into one buffer sized for it"
                .to_owned(),
        });
    }
    Ok(std::mem::take(&mut *wire))
}

/// How many `YIELD_MORE` answers in a row may write nothing before the framing FAULTs: a framer
pub(crate) const MORE_STALLS: usize = 64;

/// The most output/control work one op's `YIELD_MORE` answers may retain before the framing FAULTs:
pub(crate) const MORE_BYTES: u64 = 64 * 1024 * 1024;

/// Whether one answer wrote anything: wire bytes, frame bytes, a piece, head or flow record.
pub(crate) fn wrote(o: &FramerOut) -> bool {
    let y = &o.yielded;
    y.wire_len != 0
        || y.frame_len != 0
        || y.pieces_len != 0
        || y.heads_len != 0
        || y.flags & YIELD_STREAM_FULL != 0
}

/// The re-calls of one op: their count with nothing written, and their output/control work.
#[derive(Default)]
pub(crate) struct Recalls {
    stalls: usize,
    bytes: u64,
}

impl Recalls {
    /// Count one more answer that owed more: a FAULT once [`MORE_STALLS`] in a row wrote nothing,
    pub(crate) fn owed(&mut self, o: &FramerOut, bufs: &Buffers) -> Result<(), Refused> {
        self.owed_with_progress(o, bufs, false)
    }

    fn owed_with_progress(
        &mut self,
        o: &FramerOut,
        bufs: &Buffers,
        control_progress: bool,
    ) -> Result<(), Refused> {
        self.stalls = if wrote(o) || control_progress {
            0
        } else {
            self.stalls.saturating_add(1)
        };
        self.bytes = self.bytes.saturating_add(bufs.output_work(o));
        self.control_progress(control_progress)?;
        if self.stalls >= MORE_STALLS {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: format!(
                    "the framer owed more {MORE_STALLS} times in a row and wrote nothing"
                ),
            });
        }
        Ok(())
    }

    /// A PENDING crossing retains no output, but a newly granted stream still did control work.
    fn control_progress(&mut self, progress: bool) -> Result<(), Refused> {
        if progress {
            self.stalls = 0;
            self.bytes = self.bytes.saturating_add(std::mem::size_of::<
                busbar_contract::abi::transport::guest_policy::Open,
            >() as u64);
        }
        if self.bytes > MORE_BYTES {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: format!(
                    "the framer's output/control work for one op ran past {MORE_BYTES} bytes"
                ),
            });
        }
        Ok(())
    }
}

/// Which op a `YIELD_MORE` re-call repeats.
#[derive(Clone, Copy)]
enum Again {
    Timer,
    Refuse(Option<u64>, u32, bool),
}

impl Framing {
    /// `begin`: open a framing on `side` (`SIDE_*`) for `target`, over what the handshake
    pub fn begin(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
    ) -> Result<(Self, Yielded), Refused> {
        Self::begin_with(door, side, target, established, &[])
    }

    /// [`Framing::begin`], handing a dialled framing its OPENING head fields (`BeginIn::fields`:
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
    pub fn begin_ticketless(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
        binding: &AuthBinding,
    ) -> Result<(Self, Yielded), Refused> {
        binding.ticket_less()?;
        Self::begin_on(
            door,
            None,
            side,
            target,
            established,
            opening,
            *binding,
            None,
        )
    }

    /// [`Framing::begin_bound`] with a binding that has no auth.
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
        Self::begin_on(
            door,
            ticket,
            side,
            target,
            established,
            opening,
            *binding,
            None,
        )
    }

    /// AN ACCEPTING FRAMING LENT ITS LISTENER'S GUEST LIST (THE DESIGN §6, "Auth points and guest
    pub fn begin_lent(
        door: Arc<dyn FramerDoor>,
        side: u32,
        target: &str,
        established: &Established,
        guests: Option<Arc<GuestLines>>,
    ) -> Result<(Self, Yielded), Refused> {
        if side == SIDE_DIAL && guests.is_some() {
            return Err(Refused {
                outcome: Outcome::Fault,
                error: LINES_ON_DIAL.into(),
            });
        }
        let binding = AuthBinding {
            line_points: guests.as_deref().map_or(0, GuestLines::points),
            ..AuthBinding::NONE
        };
        let ticket = door.framing_side();
        if ticket.is_none() {
            binding.ticket_less()?;
        }
        Self::begin_on(
            door,
            ticket,
            side,
            target,
            established,
            &[],
            binding,
            guests,
        )
    }

    /// The framing's token, as its framer names it (`BeginOut::framing`, the `conn` of every host
    #[must_use]
    pub const fn token(&self) -> u64 {
        self.token
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_on(
        door: Arc<dyn FramerDoor>,
        ticket: Option<Box<dyn crate::carrier::Side>>,
        side: u32,
        target: &str,
        established: &Established,
        opening: &[(String, Vec<u8>)],
        binding: AuthBinding,
        guests: Option<Arc<GuestLines>>,
    ) -> Result<(Self, Yielded), Refused> {
        let context = door.framing_context(guests.as_ref().map_or(0, |g| g.listener()), 0)?;
        let guests = context
            .as_ref()
            .and_then(|scope| scope.opening_policy())
            .map(|policy| Arc::new(GuestLines::published(policy)))
            .or(guests);
        let mut f = Self {
            door,
            context,
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
            guests,
        };
        let y = f.run(op, Yielded::default(), false, false, ticket)?;
        Ok((f, y.unwrap_or_default()))
    }

    /// Input still held by the framer, plus pieces copied off earlier yields of operations that
    pub(crate) fn retained_input(&self) -> usize {
        let plugin = self.context.as_ref().map_or(0, |scope| {
            usize::try_from(scope.retained_input()).unwrap_or(usize::MAX)
        });
        self.parked
            .iter()
            .flat_map(|p| &p.yielded.pieces)
            .fold(plugin, |n, p| n.saturating_add(p.bytes.len()))
    }

    /// Whether any ticketed op is parked, waiting for its ticket's wake.
    #[must_use]
    pub fn parked(&self) -> bool {
        !self.parked.is_empty()
    }

    /// Whether the framing's `begin` or `adopt` is parked: no other op crosses until it completes.
    #[must_use]
    pub fn begin_parked(&self) -> bool {
        self.parked
            .iter()
            .any(|p| matches!(p.op, Ticketed::Begin { .. } | Ticketed::Adopt { .. }))
    }

    /// Whether `stream` is held: the framing's `begin`/`adopt` is parked, or an `emit` on it is.
    #[must_use]
    pub fn holds(&self, stream: u64) -> bool {
        self.parked.iter().any(|p| match p.op.stream() {
            Some(s) => s == stream,
            None => matches!(p.op, Ticketed::Begin { .. } | Ticketed::Adopt { .. }),
        })
    }

    /// RE-DRIVE THE PARKED OPS, each on its own ticket: `cx`'s waker registered on the ticket
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
            match self.run_with_recalls(p.op, p.yielded, p.recall, true, Some(p.ticket), p.recalls)
            {
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
        let cross = |call: Call<'_>| door.cross_scoped(self.context.as_ref(), ticket, resume, call);
        let fresh = !recall && !resume;
        let c = match op {
            Ticketed::Begin {
                side,
                target,
                established,
                opening,
                binding,
                guests,
            } => {
                let facts = established.facts();
                let fields: Vec<Field> = opening
                    .iter()
                    .map(|(n, v)| Field {
                        name: abi(n.as_bytes()),
                        value: abi(v),
                    })
                    .collect();

                let lent: &[GuestLine] = match guests.as_deref() {
                    Some(g) if *side != SIDE_DIAL => g.lines(),
                    _ => &[],
                };
                let predicates: Vec<Vec<FieldPredicate>> = lent.iter().map(predicates_of).collect();
                let entries: Vec<LineEntry> = lent
                    .iter()
                    .zip(&predicates)
                    .map(|(l, p)| entry_of(l, p))
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
                if !entries.is_empty() {
                    i.lines = entries.as_ptr();
                    i.lines_len = entries.len();
                }
                if *side == SIDE_DIAL {
                    i.points = binding.points;
                    i.auth = binding.auth;
                }
                i.sink = sink;
                cross(Call::Begin(&mut i, &mut o))
            }
            Ticketed::Adopt {
                side,
                established,
                leftover,
            } => {
                let facts = established.facts();
                let mut i: AdoptIn = blank_in();
                i.side = *side;
                i.facts = &facts;
                if fresh {
                    i.leftover = leftover.as_ptr();
                    i.leftover_len = leftover.len();
                }
                i.sink = sink;
                cross(Call::Adopt(&mut i, &mut o))
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
                trailers,
                body_len,
                status,
                extensions,
            } => {
                let mut i: EmitIn = blank_in();
                i.framing = self.token;
                i.stream = *stream;
                if !extensions.is_empty() {
                    i.head.extensions = Blob {
                        ptr: extensions.as_ptr(),
                        len: extensions.len(),
                        fmt: BLOB_OCTETS,
                        flags: 0,
                    };
                }
                if fresh {
                    i.bytes = bytes.as_ptr();
                    i.len = bytes.len();
                    i.end_of_frame = u32::from(*end_of_frame);
                    i.flags = if *text { EMIT_TEXT } else { 0 }
                        | if *trailers { EMIT_TRAILERS } else { 0 };
                }

                if !recall {
                    i.status = *status;
                }

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
    fn run(
        &mut self,
        op: Ticketed<'_>,
        yielded: Yielded,
        recall: bool,
        resume: bool,
        ticket: Option<Box<dyn crate::carrier::Side>>,
    ) -> Result<Option<Yielded>, Refused> {
        self.run_with_recalls(op, yielded, recall, resume, ticket, Recalls::default())
    }

    fn run_with_recalls(
        &mut self,
        op: Ticketed<'_>,
        yielded: Yielded,
        recall: bool,
        resume: bool,
        ticket: Option<Box<dyn crate::carrier::Side>>,
        recalls: Recalls,
    ) -> Result<Option<Yielded>, Refused> {
        let mut ticket = ticket;
        let operation = ticket.as_ref().map_or(Ticket::NONE, |side| side.ticket());
        if !recall && !resume {
            if let Some(context) = &self.context {
                context.operation_started(operation);
            }
        }
        let r = self.run_on(op, yielded, recall, resume, &mut ticket, recalls);
        if !matches!(&r, Ok(None)) {
            if let Some(context) = &self.context {
                context.operation_finished(operation, r.is_err());
            }
        }
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
        mut recalls: Recalls,
    ) -> Result<Option<Yielded>, Refused> {
        loop {
            let (c, o) = self.cross_ticketed(&op, recall, resume, ticket.as_deref());
            let control_progress = self.context.as_ref().is_some_and(|context| {
                context.take_control_progress(
                    ticket.as_ref().map_or(Ticket::NONE, |side| side.ticket()),
                )
            });
            resume = false;
            if c.outcome == Outcome::Pending {
                if let Err(error) = recalls.control_progress(control_progress) {
                    if let Some(side) = ticket.take() {
                        self.cancel_ticket(side.as_ref());
                    }
                    return Err(error);
                }
                if let Some(t) = ticket.take() {
                    self.parked.push(Parked {
                        op: op.owned(),
                        yielded,
                        recall,
                        recalls,
                        ticket: t,
                    });
                    return Ok(None);
                }
            }
            ready(c)?;
            let begin = matches!(op, Ticketed::Begin { .. });
            let adopt = matches!(op, Ticketed::Adopt { .. });
            if begin || adopt {
                self.token = o.framing;
                if let Some(context) = &self.context {
                    context.confirm(o.framing).map_err(|e| Refused {
                        outcome: Outcome::Refused,
                        error: e.into(),
                    })?;
                }
            }
            if o.yielded.flags & YIELD_STREAM_FULL != 0 {
                if let Ticketed::Emit { stream, .. } = &op {
                    yielded.flow.push(StreamFlow::Full(*stream));
                }
            }
            if self.bufs.take(&o, &mut yielded)? {
                return Ok(Some(yielded));
            }
            recalls.owed_with_progress(&o, &self.bufs, control_progress)?;
            if adopt {
                return self.run_on(
                    Ticketed::Ingest {
                        bytes: std::borrow::Cow::Borrowed(&[]),
                        end: false,
                    },
                    yielded,
                    true,
                    false,
                    ticket,
                    recalls,
                );
            }
            if begin {
                self.more_with_recalls(Again::Timer, &mut yielded, recalls)?;
                return Ok(Some(yielded));
            }
            recall = true;
        }
    }

    /// Refused while the framing's `begin` is parked, or (`stream`) while an op parked on that
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
    pub fn adopt(
        door: Arc<dyn FramerDoor>,
        side: u32,
        leftover: &[u8],
        established: &Established,
    ) -> Result<(Self, Yielded), Refused> {
        Self::adopt_context(
            door,
            side,
            std::borrow::Cow::Borrowed(leftover),
            established,
            None,
        )
    }

    /// Adopt a connection detached by its previous host framing, retaining its listener and
    pub fn adopt_detached(
        door: Arc<dyn FramerDoor>,
        side: u32,
        mut detached: Detached,
        established: &Established,
    ) -> Result<(Self, Yielded), Refused> {
        let context =
            match detached.context.as_ref() {
                Some(source) => Some(door.adopting_context(Arc::clone(source))?.ok_or_else(
                    || Refused {
                        outcome: Outcome::Refused,
                        error: "adoption lost its host framing context".into(),
                    },
                )?),
                None => None,
            };

        drop(detached.context.take());
        Self::adopt_context(
            door,
            side,
            std::borrow::Cow::Owned(std::mem::take(&mut detached.bytes)),
            established,
            context,
        )
    }

    fn adopt_context(
        door: Arc<dyn FramerDoor>,
        side: u32,
        leftover: std::borrow::Cow<'_, [u8]>,
        established: &Established,
        context: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    ) -> Result<(Self, Yielded), Refused> {
        let ticket = door.framing_side();
        let context = match context {
            Some(context) => Some(context),
            None => door.framing_context(0, 0)?,
        };
        let mut framing = Self {
            door,
            context,
            token: 0,
            bufs: Buffers::for_side(side),
            ticketed: ticket.is_some(),
            idle: Vec::new(),
            parked: Vec::new(),
        };
        let op = Ticketed::Adopt {
            side,
            established: established.clone(),
            leftover,
        };
        let yielded = framing.run(op, Yielded::default(), false, false, ticket)?;
        Ok((framing, yielded.unwrap_or_default()))
    }

    /// The entry this framing is on.
    #[must_use]
    pub fn door(&self) -> &Arc<dyn FramerDoor> {
        &self.door
    }

    /// The host ownership of this framing, independent of its operation tickets.
    #[must_use]
    pub fn scope(&self) -> Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>> {
        self.context.as_ref()
    }

    /// Re-call `again` with no new bytes until the framer owes nothing more.
    fn more(&mut self, again: Again, y: &mut Yielded) -> Result<(), Refused> {
        self.more_with_recalls(again, y, Recalls::default())
    }

    fn more_with_recalls(
        &mut self,
        again: Again,
        y: &mut Yielded,
        recalls: Recalls,
    ) -> Result<(), Refused> {
        if let Some(context) = &self.context {
            context.operation_started(Ticket::NONE);
        }
        let result = self.more_on(again, y, recalls);
        if let Some(context) = &self.context {
            context.operation_finished(Ticket::NONE, result.is_err());
        }
        result
    }

    fn more_on(
        &mut self,
        again: Again,
        y: &mut Yielded,
        mut recalls: Recalls,
    ) -> Result<(), Refused> {
        loop {
            let sink = self.bufs.sink();
            let mut o: FramerOut = blank_out();
            let c = match again {
                Again::Refuse(stream, status, head_sent) => {
                    let mut i: RefuseIn = blank_in();
                    i.framing = self.token;
                    i.stream = stream.unwrap_or(0);
                    i.has_stream = u32::from(stream.is_some());
                    i.status = status;
                    i.head_sent = u32::from(head_sent);
                    i.sink = sink;
                    self.door.cross_scoped(
                        self.context.as_ref(),
                        None,
                        false,
                        Call::Refuse(&mut i, &mut o),
                    )
                }
                Again::Timer => {
                    let mut i: FramingIn = blank_in();
                    i.framing = self.token;
                    i.sink = sink;
                    self.door.cross_scoped(
                        self.context.as_ref(),
                        None,
                        false,
                        Call::Timer(&mut i, &mut o),
                    )
                }
            };
            let control_progress = self
                .context
                .as_ref()
                .is_some_and(|context| context.take_control_progress(Ticket::NONE));
            ready(c)?;
            if self.bufs.take(&o, y)? {
                return Ok(());
            }
            recalls.owed_with_progress(&o, &self.bufs, control_progress)?;
        }
    }

    /// `ingest`: what the far side sent (`end` = it ended). On a ticketed framing a PENDING answer
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
    pub fn emit_opening(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        body_len: Option<u64>,
    ) -> Result<Yielded, Refused> {
        self.emit_op(
            stream,
            bytes,
            end_of_frame,
            text,
            EmitHead {
                body_len,
                ..EmitHead::default()
            },
        )
    }

    /// Emit an opening with the host's credential-name classification, outside its wire bytes.
    pub fn emit_opening_sensitive(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        body_len: Option<u64>,
        sensitive: &SensitiveFields,
    ) -> Result<Yielded, Refused> {
        let extensions = sensitive.extensions().map_err(|error| Refused {
            outcome: Outcome::Refused,
            error: error.into(),
        })?;
        self.emit_op(
            stream,
            bytes,
            end_of_frame,
            text,
            EmitHead {
                body_len,
                extensions,
                ..EmitHead::default()
            },
        )
    }

    /// `emit` of an ACCEPTED stream's ANSWER HEAD (`bytes`, a field block,
    pub fn emit_head(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        status: u32,
    ) -> Result<Yielded, Refused> {
        self.emit_op(
            stream,
            bytes,
            end_of_frame,
            false,
            EmitHead {
                status,
                ..EmitHead::default()
            },
        )
    }

    /// End an accepted answer with a neutral field block after its body. The transport renders
    pub fn emit_trailers(&mut self, stream: u64, fields: &[u8]) -> Result<Yielded, Refused> {
        if self.bufs.side != SIDE_ACCEPT {
            return Err(Refused {
                outcome: Outcome::Refused,
                error: "trailers end an accepted answer only".into(),
            });
        }
        self.emit_op(
            stream,
            fields,
            true,
            false,
            EmitHead {
                trailers: true,
                ..EmitHead::default()
            },
        )
    }

    /// The one `emit` op every emit is.
    fn emit_op(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        head: EmitHead,
    ) -> Result<Yielded, Refused> {
        self.idle(Some(stream))?;
        let op = Ticketed::Emit {
            stream,
            bytes: std::borrow::Cow::Borrowed(bytes),
            end_of_frame,
            text,
            trailers: head.trailers,
            body_len: head.body_len,
            status: head.status,
            extensions: head.extensions,
        };
        let ticket = self.take_ticket()?;
        Ok(self
            .run(op, Yielded::default(), false, false, ticket)?
            .unwrap_or_default())
    }

    /// `refuse`: a refusal's bytes for `stream` (`None` = the whole connection), with its neutral
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
        ready(self.door.cross_scoped(
            self.context.as_ref(),
            None,
            false,
            Call::Refuse(&mut i, &mut o),
        ))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            let mut recalls = Recalls::default();
            recalls.owed(&o, &self.bufs)?;
            self.more_with_recalls(Again::Refuse(stream, status, head_sent), &mut y, recalls)?;
        }
        Ok(y)
    }

    /// `timer`: the deadline the framer asked for passed.
    pub fn timer(&mut self) -> Result<Yielded, Refused> {
        self.idle(None)?;
        let mut y = Yielded::default();
        self.more(Again::Timer, &mut y)?;
        Ok(y)
    }

    /// `detach`: the bytes the framer took and did not answer, and the framing is over.
    pub fn detach(mut self) -> Result<Detached, Refused> {
        self.quiet()?;
        let mut left = Vec::new();
        let mut recalls = Recalls::default();
        loop {
            let mut i: FramingIn = blank_in();
            i.framing = self.token;
            i.sink = self.bufs.sink();
            let mut o: FramerOut = blank_out();
            ready(self.door.cross_scoped(
                self.context.as_ref(),
                None,
                false,
                Call::Detach(&mut i, &mut o),
            ))?;
            let n = usize::try_from(o.yielded.frame_len).unwrap_or(usize::MAX);
            left.extend_from_slice(self.bufs.frame.get(..n).ok_or_else(|| Refused {
                outcome: Outcome::Fault,
                error: "the framer's answer is out of bounds: frame".into(),
            })?);
            if o.yielded.flags & YIELD_MORE == 0 {
                self.token = 0;
                if let Some(context) = &self.context {
                    context.detach().map_err(|error| Refused {
                        outcome: Outcome::Refused,
                        error: error.into(),
                    })?;
                }
                let context = self.context.take();
                return Ok(Detached {
                    bytes: left,
                    context,
                });
            }
            recalls.owed(&o, &self.bufs)?;
        }
    }

    /// `finish`: close the framing with `reason` (`CLOSE_*`); what it still owes the far side.
    pub fn finish(mut self, reason: u32) -> Yielded {
        self.close(reason)
    }

    /// `finish` on ONE STREAM'S framing ([`busbar_contract::abi::transport::SIDE_ACCEPT_STREAM`]):
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
        if let Some(context) = &self.context {
            context.closing();
        }
        let mut y = Yielded::default();
        let mut recalls = Recalls::default();
        loop {
            i.sink = self.bufs.sink();
            let mut o: FramerOut = blank_out();
            ready(self.door.cross_scoped(
                self.context.as_ref(),
                None,
                false,
                Call::Finish(&mut i, &mut o),
            ))?;
            if self.bufs.take(&o, &mut y)? {
                self.token = 0;
                if let Some(context) = &self.context {
                    context.end();
                }
                return Ok(y);
            }
            recalls.owed(&o, &self.bufs)?;
        }
    }

    fn close(&mut self, reason: u32) -> Yielded {
        let mut y = Yielded::default();
        if let Some(context) = &self.context {
            context.closing();
        }
        self.cancel_parked();
        if self.token == 0 {
            if let Some(context) = &self.context {
                context.end();
            }
            return y;
        }
        let mut i: FinishIn = blank_in();
        i.framing = self.token;
        i.reason = reason;
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        if self
            .door
            .cross_scoped(
                self.context.as_ref(),
                None,
                false,
                Call::Finish(&mut i, &mut o),
            )
            .outcome
            == Outcome::Ready
        {
            let _ = self.bufs.take(&o, &mut y);
        }
        self.token = 0;
        if let Some(context) = &self.context {
            context.end();
        }
        y
    }
}

impl Framing {
    fn cancel_ticket(&self, side: &dyn crate::carrier::Side) {
        let mut i: busbar_contract::abi::mechanism::lifecycle::CancelIn = blank_in();
        i.ticket = side.ticket();
        let mut o: busbar_contract::abi::mechanism::lifecycle::CancelOut = blank_out();
        let _ = self.door.cancel_scoped(
            self.context.as_ref(),
            side,
            crate::carrier::Carry::Cancel(&mut i, &mut o),
        );
    }

    /// CANCEL every op parked on the framing's tickets, each on its own (`abi::mechanism::lifecycle`,
    fn cancel_parked(&mut self) {
        for p in std::mem::take(&mut self.parked) {
            let side = p.ticket.as_ref();
            self.cancel_ticket(side);
            if let Some(context) = &self.context {
                context.operation_finished(side.ticket(), true);
            }
        }
    }
}

/// What one more completed op yielded, after what `into` holds: its head slots, wire bytes and
fn merge(into: &mut Yielded, mut y: Yielded) {
    into.heads.append(&mut y.heads);
    into.extend_wire(&y.wire);
    #[cfg(test)]
    crate::support::watch_yielded_wire(&into.wire);
    into.pieces.append(&mut y.pieces);
    into.interim.append(&mut y.interim);
    into.flow.append(&mut y.flow);
    into.ended |= y.ended;
    into.deadline_ns = y.deadline_ns.or(into.deadline_ns);
    if y.agreed != 0 {
        into.agreed = y.agreed;
    }
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

#[cfg(test)]
#[path = "tests/framer_deadline_tests.rs"]
mod deadline_tests;
