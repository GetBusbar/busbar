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

use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{
    AdoptIn, BeginIn, ConnFacts, EmitIn, EncodeIn, Field, FinishIn, FramePiece, FramerOut,
    FramerSink, FramingIn, IngestIn, LocateIn, LocateOut, RefuseIn, PIECE_END_OF_FRAME,
    PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
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
}

/// Everything one op answered, across its `YIELD_MORE` re-calls.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Yielded {
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
}

/// The default capacities: wire and frame bytes, and pieces.
pub const WIRE_CAP: usize = 64 * 1024;
/// The frame buffer's capacity.
pub const FRAME_CAP: usize = 64 * 1024;
/// The pieces buffer's capacity.
pub const PIECES_CAP: usize = 64;

const EMPTY_PIECE: FramePiece = FramePiece {
    stream: 0,
    offset: 0,
    len: 0,
    status_code: 0,
    status_class: 0,
    flags: 0,
    _reserved: [0; 2],
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
        }
    }

    /// Take what one READY answer wrote; `false` = it owes more (`YIELD_MORE`).
    fn take(&self, o: &FramerOut, into: &mut Yielded) -> Result<bool, Refused> {
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
        for p in pieces {
            let at = usize::try_from(p.offset).map_err(|_| bad("piece"))?;
            let len = usize::try_from(p.len).map_err(|_| bad("piece"))?;
            let bytes = frame
                .get(at..at.checked_add(len).ok_or_else(|| bad("piece"))?)
                .ok_or_else(|| bad("piece"))?;
            into.pieces.push(Got {
                stream: p.stream,
                bytes: bytes.to_vec(),
                end_of_frame: p.flags & PIECE_END_OF_FRAME != 0,
                status_code: (p.flags & PIECE_HAS_CODE != 0).then_some(p.status_code),
                status_class: p.status_class,
                retry_after_secs: (p.flags & PIECE_HAS_RETRY_AFTER != 0)
                    .then_some(p.retry_after_secs),
            });
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
}

/// `locate`: where `target` is, per the entry. One re-call with the sizes a short answer names.
///
/// # Errors
///
/// The entry refused the target.
pub fn locate(door: &dyn FramerDoor, target: &str) -> Result<Located, Refused> {
    let (mut auth_cap, mut name_cap) = (256_usize, 256_usize);
    for _ in 0..2 {
        let mut authority = vec![0_u8; auth_cap];
        let mut name = vec![0_u8; name_cap];
        let mut i: LocateIn = blank_in();
        i.target = abi(target.as_bytes());
        i.authority_buf = authority.as_mut_ptr();
        i.authority_cap = authority.len();
        i.name_buf = name.as_mut_ptr();
        i.name_cap = name.len();
        let mut o: LocateOut = blank_out();
        let c = door.cross(Call::Locate(&mut i, &mut o));
        let short = o.authority_needed > auth_cap as u64 || o.name_needed > name_cap as u64;
        if c.outcome == Outcome::Failed && short {
            auth_cap = usize::try_from(o.authority_needed)
                .unwrap_or(0)
                .max(auth_cap);
            name_cap = usize::try_from(o.name_needed).unwrap_or(0).max(name_cap);
            continue;
        }
        ready(c)?;
        let text = |b: &[u8], n: u64| {
            String::from_utf8_lossy(b.get(..usize::try_from(n).unwrap_or(0)).unwrap_or_default())
                .into_owned()
        };
        return Ok(Located {
            authority: text(&authority, o.authority_written),
            name: (o.has_name != 0).then(|| text(&name, o.name_written)),
            secure: o.secure != 0,
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
    let mut bufs = Buffers::new(room + 4096, 1, 1);
    let mut i: EncodeIn = blank_in();
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
    Refuse(Option<u64>),
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
        let mut bufs = Buffers::default();
        let facts = established.facts();
        let mut i: BeginIn = blank_in();
        i.side = side;
        i.target = abi(target.as_bytes());
        i.facts = &facts;
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
        let mut bufs = Buffers::default();
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
                Again::Refuse(stream) => {
                    let mut i: RefuseIn = blank_in();
                    i.framing = self.token;
                    i.stream = stream.unwrap_or(0);
                    i.has_stream = u32::from(stream.is_some());
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

    /// `emit`: bytes for the far side, on `stream`.
    ///
    /// # Errors
    ///
    /// The framer refused them.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end_of_frame: bool,
    ) -> Result<Yielded, Refused> {
        let mut i: EmitIn = blank_in();
        i.framing = self.token;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end_of_frame);
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(self.door.cross(Call::Emit(&mut i, &mut o)))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            self.more(Again::Emit(stream), &mut y)?;
        }
        Ok(y)
    }

    /// `refuse`: a refusal's bytes for `stream` (`None` = the whole connection).
    ///
    /// # Errors
    ///
    /// The framer refused to render it.
    pub fn refuse(&mut self, stream: Option<u64>, bytes: &[u8]) -> Result<Yielded, Refused> {
        let mut i: RefuseIn = blank_in();
        i.framing = self.token;
        i.stream = stream.unwrap_or(0);
        i.has_stream = u32::from(stream.is_some());
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.bufs.sink();
        let mut o: FramerOut = blank_out();
        ready(self.door.cross(Call::Refuse(&mut i, &mut o)))?;
        let mut y = Yielded::default();
        if !self.bufs.take(&o, &mut y)? {
            self.more(Again::Refuse(stream), &mut y)?;
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
