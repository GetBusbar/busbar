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

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{
    AdoptIn, BeginIn, ConnFacts, EmitIn, EncodeIn, FinishIn, FramePiece, FrameSpan, FramerOut,
    FramerSink, FramingIn, HeadSlots, IngestIn, LocateIn, LocateOut, RefuseIn, EMIT_TEXT,
    PIECE_CONTINUED, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER,
    PIECE_STREAM_FAILED, PIECE_TEXT, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE,
    YIELD_MORE,
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
    /// The claims it composes over; empty = directly over the host's socket.
    pub composes_over: Vec<&'static str>,
}

/// A transport entry's framer table, as the host reaches it.
pub trait FramerDoor: Send + Sync {
    /// What the entry states.
    fn facts(&self) -> &DoorFacts;
    /// One crossing: the op, answered into its `out`.
    fn cross(&self, call: Call<'_>) -> Crossed;
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

fn refused(c: Crossed) -> Refused {
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
    /// The far side's `Retry-After`, in seconds, where it asked.
    pub retry_after_secs: Option<u64>,
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
}

impl Got {
    /// Whether this piece ENDS its stream whole: the EMPTY payload piece that closes a stream's
    /// frames (`busbar_contract::abi::transport`, "streams end by piece"). An empty fields piece is
    /// an empty head, never the end, and a failed stream's piece ends it failed.
    #[must_use]
    pub fn ends_stream(&self) -> bool {
        self.end_of_frame && self.bytes.is_empty() && !self.fields && !self.failed
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
    _reserved: 0,
    retry_after_secs: 0,
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
    fn for_side(side: u32) -> Self {
        Self {
            side,
            ..Self::default()
        }
    }

    fn sink(&mut self) -> FramerSink {
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

    /// Take what one READY answer wrote; `false` = it owes more (`YIELD_MORE`).
    fn take(&mut self, o: &FramerOut, into: &mut Yielded) -> Result<bool, Refused> {
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
                retry_after_secs: (p.flags & PIECE_HAS_RETRY_AFTER != 0)
                    .then_some(p.retry_after_secs),
                fields: p.flags & PIECE_FIELDS != 0,
                text: p.flags & PIECE_TEXT != 0,
                reason: None,
                failed: p.flags & PIECE_STREAM_FAILED != 0,
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
}

impl std::fmt::Debug for Framing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framing")
            .field("entry", &self.door.facts().name)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

fn ready(c: Crossed) -> Result<(), Refused> {
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
}

impl Established {
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
    let (mut auth_cap, mut name_cap, mut alpn_cap) = (256_usize, 256_usize, 256_usize);
    for _ in 0..2 {
        let mut authority = vec![0_u8; auth_cap];
        let mut name = vec![0_u8; name_cap];
        let mut alpn = vec![0_u8; alpn_cap];
        let mut i: LocateIn = blank_in();
        i.target = abi(target.as_bytes());
        i.authority_buf = authority.as_mut_ptr();
        i.authority_cap = authority.len();
        i.name_buf = name.as_mut_ptr();
        i.name_cap = name.len();
        i.alpn_buf = alpn.as_mut_ptr();
        i.alpn_cap = alpn.len();
        let mut o: LocateOut = blank_out();
        let c = door.cross(Call::Locate(&mut i, &mut o));
        let short = o.authority_needed > auth_cap as u64
            || o.name_needed > name_cap as u64
            || o.alpn_needed > alpn_cap as u64;
        if c.outcome == Outcome::Failed && short {
            let grow = |needed: u64, cap: usize| usize::try_from(needed).unwrap_or(0).max(cap);
            auth_cap = grow(o.authority_needed, auth_cap);
            name_cap = grow(o.name_needed, name_cap);
            alpn_cap = grow(o.alpn_needed, alpn_cap);
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
        return Ok(Located {
            authority: text(&authority, o.authority_written),
            name: (o.has_name != 0).then(|| text(&name, o.name_written)),
            secure: o.secure != 0,
            offer: offered,
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
/// The entry refused to render it.
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
    bufs.take(&o, &mut y)?;
    Ok(y.wire)
}

/// Which op a `YIELD_MORE` re-call repeats.
#[derive(Clone, Copy)]
enum Again {
    Ingest,
    Emit(u64),
    Timer,
    Refuse(Option<u64>, u32),
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
    /// the bound auth's fields and the request's own), for a wire that carries them on the
    /// connection's opening rather than on a message (ARCHITECT Q-L5B-WS-DIAL).
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
        let mut bufs = Buffers::for_side(side);
        let facts = established.facts();
        let fields: Vec<Field> = opening
            .iter()
            .map(|(n, v)| Field {
                name: abi(n.as_bytes()),
                value: abi(v),
            })
            .collect();
        let mut i: BeginIn = blank_in();
        i.side = side;
        i.target = abi(target.as_bytes());
        i.facts = &facts;
        if !fields.is_empty() {
            i.fields = fields.as_ptr();
            i.fields_len = fields.len();
        }
        i.sink = bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(door.cross(Call::Begin(&mut i, &mut o)))?;
        let mut f = Self {
            door,
            token: o.framing,
            bufs,
        };
        let mut y = Yielded::default();
        if !f.bufs.take(&o, &mut y)? {
            f.more(Again::Timer, &mut y)?;
        }
        Ok((f, y))
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
                Again::Emit(stream) => {
                    let mut i: EmitIn = blank_in();
                    i.framing = self.token;
                    i.stream = stream;
                    i.sink = sink;
                    self.door.cross(Call::Emit(&mut i, &mut o))
                }
                Again::Refuse(stream, status) => {
                    let mut i: RefuseIn = blank_in();
                    i.framing = self.token;
                    i.stream = stream.unwrap_or(0);
                    i.has_stream = u32::from(stream.is_some());
                    i.status = status;
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
        }
    }

    /// `ingest`: what the far side sent (`end` = it ended).
    ///
    /// # Errors
    ///
    /// The framer failed the connection.
    pub fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<Yielded, Refused> {
        let mut i: IngestIn = blank_in();
        i.framing = self.token;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end = u32::from(end);
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(self.door.cross(Call::Ingest(&mut i, &mut o)))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            self.more(Again::Ingest, &mut y)?;
        }
        Ok(y)
    }

    /// `emit`: bytes for the far side, on `stream`; `text`: they are a text message (`EMIT_TEXT`).
    ///
    /// # Errors
    ///
    /// The framer refused them.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
    ) -> Result<Yielded, Refused> {
        let mut i: EmitIn = blank_in();
        i.framing = self.token;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end_of_frame);
        i.flags = if text { EMIT_TEXT } else { 0 };
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(self.door.cross(Call::Emit(&mut i, &mut o)))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            self.more(Again::Emit(stream), &mut y)?;
        }
        Ok(y)
    }

    /// `refuse`: a refusal's bytes for `stream` (`None` = the whole connection), with its neutral
    /// `status` for the framer to map to its wire (`0` = none stated).
    ///
    /// # Errors
    ///
    /// The framer refused to render it.
    pub fn refuse(
        &mut self,
        stream: Option<u64>,
        bytes: &[u8],
        status: u32,
    ) -> Result<Yielded, Refused> {
        let mut i: RefuseIn = blank_in();
        i.framing = self.token;
        i.stream = stream.unwrap_or(0);
        i.has_stream = u32::from(stream.is_some());
        i.status = status;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(self.door.cross(Call::Refuse(&mut i, &mut o)))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            self.more(Again::Refuse(stream, status), &mut y)?;
        }
        Ok(y)
    }

    /// `timer`: the deadline the framer asked for passed.
    ///
    /// # Errors
    ///
    /// The framer failed the connection.
    pub fn timer(&mut self) -> Result<Yielded, Refused> {
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
        let mut left = Vec::new();
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
        }
    }

    /// `finish`: close the framing with `reason` (`CLOSE_*`); what it still owes the far side.
    pub fn finish(mut self, reason: u32) -> Yielded {
        self.close(reason)
    }

    fn close(&mut self, reason: u32) -> Yielded {
        let mut y = Yielded::default();
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

impl Drop for Framing {
    fn drop(&mut self) {
        let _ = self.close(busbar_contract::abi::transport::CLOSE_NORMAL);
    }
}

#[cfg(test)]
#[path = "tests/framer_tests.rs"]
mod tests;
