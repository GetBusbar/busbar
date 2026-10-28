// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER A CONNECTION RIDES (TRANSPORT-STACK (2); `BUSBAR-1.6.0.md` THE DESIGN §5): one carrier
//! entry's slots (`listen`, `accept`, `dial`, `read`, `write`, `flush`, `shut`), driven host-side.
//! The connector builds every connection as `carrier -> [TLS] -> framer`, and the carrier is the
//! bottom of it: it dials, accepts, reads and writes over the host's I/O ([`crate::hostio`]), and
//! this crate reaches the wire through it and nothing else.
//!
//! A connection is full-duplex, so it holds TWO sides (`abi::transport`: "TWO TICKETS PER
//! CONNECTION"), each an inline ticket ([`Side`]) with at most one op in flight: `read` on the read
//! side; `dial`, `write`, `flush` and `shut` on the write side. Every op is crossed INLINE on the
//! task that polls the connection — no thread handoff (#30). An op that answers PENDING registered
//! the task's waker on its side's ticket; the next call on that side RESUMES it (`FLAG_RESUME`, the
//! same op on the same ticket) before anything else is asked of it.
//!
//! EACH SIDE HAS ONE OWNER, AND NO LOCK (`BUSBAR-1.6.0.md` §11, M1 DISPATCH RULINGS: "No plugin
//! code runs under a host lock"). The two halves are separate values a [`Carried`] owns outright,
//! and every op takes the connection `&mut`: the task that holds the connection is the one task
//! that drives each half, so no crossing ever waits on, or is waited on through, a host mutex.
//! A close ([`Carried::close`], and its `Drop`) is made by that owner too, on its own thread, with
//! nothing held: the exchanges that share a connection hand its close to whichever of them has it
//! out, and never wait on it.
//!
//! How a call reaches the entry is not this crate's business: the entry's [`FramerDoor`] carries it
//! ([`FramerDoor::carry`]) — the one dispatcher's crossing for a loaded plugin, compiled in or
//! dropped in.

use std::io;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, ConnIn, ConnOut, Destination, DialIn, IoOut, ListenIn, ListenOut, ReadIn,
    ShutIn, WriteIn, CLOSE_NORMAL, DEST_AUTHORITY, DEST_PROGRAM, READ_END_OF_FRAME,
    WRITE_END_OF_FRAME,
};

use crate::framer::{Crossed, FramerDoor};
use crate::hostio::{Admission, HostIo, OpenFailure};

/// ONE SIDE of a carried connection: a ticket its entry's ops are driven on inline, and the task
/// an op pending on it wakes.
pub trait Side: Send + Sync {
    /// The ticket.
    fn ticket(&self) -> Ticket;
    /// Register `waker` as the task an op pending on this side wakes.
    fn register(&self, waker: &Waker);
}

/// One carrier op, its `in` and its `out`, as the connector hands it to a [`FramerDoor`].
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Carry<'a> {
    Listen(&'a mut ListenIn, &'a mut ListenOut),
    Accept(&'a mut AcceptIn, &'a mut AcceptOut),
    Dial(&'a mut DialIn, &'a mut ConnOut),
    Read(&'a mut ReadIn, &'a mut IoOut),
    Write(&'a mut WriteIn, &'a mut IoOut),
    Flush(&'a mut ConnIn, &'a mut OutHead),
    Shut(&'a mut ShutIn, &'a mut OutHead),
    /// The lifecycle's `cancel` of the op pending on a side (`CancelIn::ticket`), made on no ticket.
    Cancel(&'a mut CancelIn, &'a mut CancelOut),
}

/// [`op_of`] a `flush`.
const FLUSH: u8 = 6;

/// The slot a [`Carry`] crosses, to know what is pending on a side.
fn op_of(c: &Carry<'_>) -> u8 {
    match c {
        Carry::Listen(..) => 1,
        Carry::Accept(..) => 2,
        Carry::Dial(..) => 3,
        Carry::Read(..) => 4,
        Carry::Write(..) => 5,
        Carry::Flush(..) => FLUSH,
        Carry::Shut(..) => 7,
        Carry::Cancel(..) => 9,
    }
}

/// The text of a crossing that did not answer READY.
#[must_use]
pub fn text(c: &Crossed) -> String {
    String::from_utf8_lossy(c.error.as_deref().unwrap_or_default()).into_owned()
}

/// A side as its holder drives it: the side, and the op pending on it (`0` = none).
pub struct Driven {
    side: Box<dyn Side>,
    pending: u8,
}

impl std::fmt::Debug for Driven {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driven")
            .field("ticket", &self.side.ticket())
            .field("pending", &self.pending)
            .finish()
    }
}

impl Driven {
    /// A side of `door`'s; `None` when the entry is no carrier the host can drive.
    #[must_use]
    pub fn of(door: &dyn FramerDoor) -> Option<Self> {
        door.side().map(|side| Self { side, pending: 0 })
    }

    /// The side's ticket.
    #[must_use]
    pub fn ticket(&self) -> Ticket {
        self.side.ticket()
    }

    /// Cross `call` on this side with `cx`'s waker registered: a RESUME when the same op pended on
    /// it last. `Pending` keeps the op pending on the side.
    pub fn cross(
        &mut self,
        door: &dyn FramerDoor,
        call: Carry<'_>,
        cx: Option<&mut Context<'_>>,
    ) -> Option<Crossed> {
        if let Some(cx) = cx {
            self.side.register(cx.waker());
        }
        let op = op_of(&call);
        let resume = self.pending == op;
        let c = door.carry(self.side.as_ref(), resume, call);
        if c.outcome == Outcome::Pending {
            self.pending = op;
            return None;
        }
        self.pending = 0;
        Some(c)
    }

    /// Whether an op is pending on this side.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.pending != 0
    }

    /// CANCEL the op pending on this side, if any (`abi::mechanism::lifecycle`, `cancel`).
    pub fn cancel(&mut self, door: &dyn FramerDoor) {
        if self.pending == 0 {
            return;
        }
        let mut i: CancelIn = blank_in();
        i.ticket = self.side.ticket();
        let mut o: CancelOut = blank_out();
        let _ = door.carry(self.side.as_ref(), false, Carry::Cancel(&mut i, &mut o));
        self.pending = 0;
    }
}

const fn abi(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// Where a carrier dials, with the storage its pointers name.
#[derive(Debug, Clone)]
pub enum Dest {
    /// An authority: the address the destination judge pinned (`ip:port`), or a unix-domain path
    /// (`unix:/path`).
    Authority(String),
    /// A program: its absolute path, arguments and whole environment, and its environment
    /// references as config time resolved them ([`crate::spawn_env::HeldEnv`]), and the
    /// supervision key of the member that runs it (`DialIn::supervision_key`; `0` = no member).
    Program(
        busbar_contract::conn::Program,
        crate::spawn_env::HeldEnv,
        u64,
    ),
}

impl Dest {
    /// What the host admits for a dial to this destination: exactly it.
    fn admission(&self) -> Admission {
        match self {
            Self::Authority(a) => Admission::Dial(vec![a.clone()]),
            Self::Program(p, env, _) => Admission::Spawn(p.clone(), env.clone()),
        }
    }
}

/// THE CARRIER OF ONE CONNECTION: its entry, the host I/O it rides, the carrier's connection token,
/// its two halves (the read side and the write side, each a value of its own, driven only through
/// the `&mut` its one owner holds: no lock), and the host handle the dial made (a program's: its
/// pid and exit are the host's to read).
pub struct Carried {
    door: Arc<dyn FramerDoor>,
    io: Arc<HostIo>,
    conn: u64,
    rd: Driven,
    wr: Driven,
    handle: Option<u64>,
    shut: bool,
}

impl std::fmt::Debug for Carried {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carried")
            .field("entry", &self.door.facts().name)
            .field("conn", &self.conn)
            .finish_non_exhaustive()
    }
}

/// Why a carrier would not reach a destination: as the connector's own dial reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialFailure {
    /// The far end, or the carrier, said no.
    Refused(String),
    /// The socket could not be made.
    Failed(String),
}

impl Carried {
    /// DIAL `dest` through the carrier `door`, the host admitting exactly `dest` for it: the
    /// connection comes back at once, its connect settling under [`Carried::poll_connected`].
    ///
    /// # Errors
    ///
    /// The carrier or the host refused, or the socket could not be made.
    pub fn dial(
        door: Arc<dyn FramerDoor>,
        io: Arc<HostIo>,
        dest: &Dest,
    ) -> Result<Self, DialFailure> {
        let refused = || DialFailure::Refused("the transport is no carrier the host drives".into());
        let mut wr = Driven::of(door.as_ref()).ok_or_else(refused)?;
        let rd = Driven::of(door.as_ref()).ok_or_else(refused)?;
        let (args, env): (Vec<AbiStr>, Vec<Field>) = match dest {
            Dest::Program(p, _, _) => (
                p.args.iter().map(|a| abi(a.as_bytes())).collect(),
                p.env
                    .iter()
                    .map(|(k, v)| Field {
                        name: abi(k.as_bytes()),
                        value: abi(v.as_bytes()),
                    })
                    .collect(),
            ),
            Dest::Authority(_) => (Vec::new(), Vec::new()),
        };
        let raw = match dest {
            Dest::Authority(a) => Destination {
                kind: DEST_AUTHORITY,
                _reserved: 0,
                authority: abi(a.as_bytes()),
                program: abi(b""),
                args: std::ptr::null(),
                args_len: 0,
                env: std::ptr::null(),
                env_len: 0,
            },
            Dest::Program(p, _, _) => Destination {
                kind: DEST_PROGRAM,
                _reserved: 0,
                authority: abi(b""),
                program: abi(p.command.as_bytes()),
                args: args.as_ptr(),
                args_len: args.len(),
                env: env.as_ptr(),
                env_len: env.len(),
            },
        };
        io.admit(wr.ticket(), dest.admission());
        let mut i: DialIn = blank_in();
        i.dest = &raw;
        i.supervision_key = match dest {
            Dest::Program(_, _, key) => *key,
            Dest::Authority(_) => 0,
        };
        let mut o: ConnOut = blank_out();
        let c = wr.cross(door.as_ref(), Carry::Dial(&mut i, &mut o), None);
        let (handle, failure) = io.settle(wr.ticket());
        match c {
            Some(c) if c.outcome == Outcome::Ready => Ok(Self {
                door,
                io,
                conn: o.conn,
                rd,
                wr,
                handle,
                shut: false,
            }),
            // The host's own record of an open that failed is the connector's words for it.
            _ if failure.is_some() => Err(match failure {
                Some(OpenFailure::Refused(t)) => DialFailure::Refused(t),
                Some(OpenFailure::Failed(t)) => DialFailure::Failed(t),
                None => DialFailure::Failed(String::new()),
            }),
            Some(c) if c.outcome == Outcome::Refused => Err(DialFailure::Refused(text(&c))),
            Some(c) => Err(DialFailure::Failed(text(&c))),
            None => Err(DialFailure::Failed("a dial may not pend".into())),
        }
    }

    /// The connection `conn` the carrier `door` accepted (host handle `handle`).
    ///
    /// # Errors
    ///
    /// The entry is no carrier the host drives.
    pub fn accepted(
        door: Arc<dyn FramerDoor>,
        io: Arc<HostIo>,
        conn: u64,
        handle: Option<u64>,
    ) -> Option<Self> {
        let rd = Driven::of(door.as_ref())?;
        let wr = Driven::of(door.as_ref())?;
        Some(Self {
            door,
            io,
            conn,
            rd,
            wr,
            handle,
            shut: false,
        })
    }

    /// THE CONNECTION A PLACED SOCKET BECOMES (row 192 C, the placement balancer): `stream` is a
    /// socket a listener of the carrier `door` admitted and handed up bare ([`Carried::hand_up`])
    /// so the balancer could move it to this worker; the carrier accepts it again here, off its
    /// ADOPTION listener ([`crate::hostio::ADOPTION_BIND`], bound once per carrier and host), on
    /// this worker's reactor. Every byte crosses the carrier as on the worker that admitted it.
    /// `None` = the entry is no carrier the host drives, or it would not adopt the socket (which
    /// is dropped, closed).
    #[must_use]
    pub fn adopted(
        door: Arc<dyn FramerDoor>,
        io: Arc<HostIo>,
        stream: std::net::TcpStream,
    ) -> Option<Self> {
        let listener = adoption_listener(door.as_ref(), &io)?;
        let mut side = Driven::of(door.as_ref())?;
        let ticket = side.ticket();
        io.offer(ticket, stream);
        let mut peer = vec![0_u8; usize::try_from(MAX_ADDR).unwrap_or(256)];
        let mut i: AcceptIn = blank_in();
        i.listener = listener;
        i.peer_buf = peer.as_mut_ptr();
        i.peer_cap = peer.len();
        let mut o: AcceptOut = blank_out();
        let c = side.cross(door.as_ref(), Carry::Accept(&mut i, &mut o), None);
        side.cancel(door.as_ref());
        io.withdraw(ticket);
        let (handle, _) = io.settle(ticket);
        match c {
            Some(c) if c.outcome == Outcome::Ready => Self::accepted(door, io, o.conn, handle),
            _ => None,
        }
    }

    /// The carrier entry.
    #[must_use]
    pub fn door(&self) -> &Arc<dyn FramerDoor> {
        &self.door
    }

    /// The host handle the dial made, where the host recorded one.
    #[must_use]
    pub fn handle(&self) -> Option<u64> {
        self.handle
    }

    /// Whether the program a dial spawned has exited (without waiting for it); `false` for a
    /// socket.
    #[must_use]
    pub fn program_exited(&self) -> bool {
        self.handle.is_some_and(|h| self.io.program_exited(h))
    }

    /// The process id of the program a dial spawned; `None` for a socket, or once reaped.
    #[must_use]
    pub fn program_id(&self) -> Option<u32> {
        self.handle.and_then(|h| self.io.program_id(h))
    }

    fn io_error(c: &Crossed) -> io::Error {
        match c.outcome {
            Outcome::Fault => io::Error::other("the carrier faulted"),
            _ => io::Error::other(text(c)),
        }
    }

    /// The dial's connect settled (the carrier's `flush` on a fresh dial): `Ready(Err)` with the
    /// far end's refusal, in the system's words.
    pub fn poll_connected(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        self.poll_flush(cx).map_err(|e| e.to_string())
    }

    /// Every byte the carrier took is on the wire (`flush`).
    ///
    /// # Errors
    ///
    /// The carrier failed the connection.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut i: ConnIn = blank_in();
        i.conn = self.conn;
        let mut o: OutHead = blank_out();
        match self
            .wr
            .cross(self.door.as_ref(), Carry::Flush(&mut i, &mut o), Some(cx))
        {
            None => Poll::Pending,
            Some(c) if c.outcome == Outcome::Ready => Poll::Ready(Ok(())),
            Some(c) => Poll::Ready(Err(Self::io_error(&c))),
        }
    }

    /// Whether a `flush` is pending on the write side (it resumes before anything else is offered).
    #[must_use]
    pub fn flushing(&self) -> bool {
        self.wr.pending == FLUSH
    }

    /// Offer `bytes` (`end` = they complete a frame of the carrier's own wire): how many it took.
    ///
    /// # Errors
    ///
    /// The carrier failed the connection.
    pub fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        end: bool,
    ) -> Poll<io::Result<usize>> {
        let mut i: WriteIn = blank_in();
        i.conn = self.conn;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.flags = if end { WRITE_END_OF_FRAME } else { 0 };
        let mut o: IoOut = blank_out();
        match self
            .wr
            .cross(self.door.as_ref(), Carry::Write(&mut i, &mut o), Some(cx))
        {
            None => Poll::Pending,
            Some(c) if c.outcome == Outcome::Ready => {
                Poll::Ready(Ok(usize::try_from(o.len).unwrap_or(0).min(bytes.len())))
            }
            Some(c) => Poll::Ready(Err(Self::io_error(&c))),
        }
    }

    /// The next bytes into `buf`, and whether they complete a frame of the carrier's own wire;
    /// `(0, false)` is the clean end.
    ///
    /// # Errors
    ///
    /// The carrier failed the connection.
    pub fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, bool)>> {
        let mut i: ReadIn = blank_in();
        i.conn = self.conn;
        i.buf = buf.as_mut_ptr();
        i.cap = buf.len();
        let mut o: IoOut = blank_out();
        match self
            .rd
            .cross(self.door.as_ref(), Carry::Read(&mut i, &mut o), Some(cx))
        {
            None => Poll::Pending,
            Some(c) if c.outcome == Outcome::Ready => Poll::Ready(Ok((
                usize::try_from(o.len).unwrap_or(0).min(buf.len()),
                o.flags & READ_END_OF_FRAME != 0,
            ))),
            Some(c) => Poll::Ready(Err(Self::io_error(&c))),
        }
    }

    /// CLOSE: whatever pends on either side is cancelled, then the carrier's `shut`. Idempotent.
    /// Made by the connection's owner (the `&mut`), so no other crossing on it can be in flight,
    /// and no lock is held across any of the three.
    pub fn close(&mut self) {
        if std::mem::replace(&mut self.shut, true) {
            return;
        }
        self.rd.cancel(self.door.as_ref());
        self.wr.cancel(self.door.as_ref());
        let mut i: ShutIn = blank_in();
        i.conn = self.conn;
        i.reason = CLOSE_NORMAL;
        let mut o: OutHead = blank_out();
        let _ = self
            .wr
            .cross(self.door.as_ref(), Carry::Shut(&mut i, &mut o), None);
    }

    /// TAKE the dialled or accepted socket off the host's table as the byte stream moves on to the
    /// kernel's own serving loop, and forget the carrier's connection.
    #[must_use]
    pub fn hand_up(mut self) -> Option<std::net::TcpStream> {
        let taken = self.handle.and_then(|h| self.io.take_stream(h));
        // The carrier closes a handle the host no longer holds: nothing more.
        self.close();
        taken
    }
}

/// The carrier `door`'s ADOPTION listener on `io`: bound once (the carrier's `listen` on
/// [`crate::hostio::ADOPTION_BIND`], admitted as [`Admission::Adopt`]) and kept for the host's
/// life, one per carrier. `None` = the carrier would not bind it.
fn adoption_listener(door: &dyn FramerDoor, io: &HostIo) -> Option<u64> {
    let key = std::ptr::from_ref(door).cast::<()>().addr();
    let mut adopters = io.adopters();
    if let Some(l) = adopters.get(&key) {
        return Some(*l);
    }
    let mut side = Driven::of(door)?;
    io.admit(side.ticket(), Admission::Adopt);
    let bind = crate::hostio::ADOPTION_BIND;
    let mut addr = vec![0_u8; usize::try_from(MAX_ADDR).unwrap_or(256)];
    let mut i: ListenIn = blank_in();
    i.bind = abi(bind.as_bytes());
    i.addr_buf = addr.as_mut_ptr();
    i.addr_cap = addr.len();
    let mut o: ListenOut = blank_out();
    let c = side.cross(door, Carry::Listen(&mut i, &mut o), None);
    let _ = io.settle(side.ticket());
    match c {
        Some(c) if c.outcome == Outcome::Ready => {
            adopters.insert(key, o.listener);
            Some(o.listener)
        }
        _ => None,
    }
}

impl Drop for Carried {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
#[path = "tests/carrier_tests.rs"]
mod tests;
