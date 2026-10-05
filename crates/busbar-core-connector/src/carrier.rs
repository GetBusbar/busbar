// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER A CONNECTION RIDES (TRANSPORT-STACK (2); `BUSBAR-1.6.0.md` THE DESIGN §5): one carrier
//! entry's slots (`listen`, `accept`, `dial`, `read`, `write`, `flush`, `shut`, `arrival`), driven
//! host-side. The connector builds every connection as `carrier -> [TLS] -> framer`, and the
//! carrier is the bottom of it: it dials, accepts, reads and writes over the host's I/O
//! ([`crate::hostio`]), and this crate reaches the wire through it and nothing else.
//!
//! A connection is full-duplex, so it holds TWO sides (`abi::transport`: "TWO TICKETS PER
//! CONNECTION"), each an inline ticket ([`Side`]) with at most one op in flight: `read` on the read
//! side; `dial`, `write`, `flush` and `shut` on the write side. Every op is crossed INLINE on the
//! task that polls the connection — no thread handoff (#30). An op that answers PENDING registered
//! the task's waker on its side's ticket; the next call on that side RESUMES it (`FLAG_RESUME`, the
//! same op on the same ticket) before anything else is asked of it.
//!
//! How a call reaches the entry is not this crate's business: the entry's [`FramerDoor`] carries it
//! ([`FramerDoor::carry`]) — the one dispatcher's crossing for a loaded plugin, compiled in or
//! dropped in.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, ArrivalIn, ArrivalOut, ConnIn, ConnOut, Destination, DialIn, IoOut,
    ListenIn, ListenOut, ReadIn, ShutIn, WriteIn, CLOSE_NORMAL, DEST_AUTHORITY, DEST_PROGRAM,
    MAX_ADDR, READ_END_OF_FRAME, WRITE_END_OF_FRAME,
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
    Arrival(&'a mut ArrivalIn, &'a mut ArrivalOut),
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
        Carry::Arrival(..) => 8,
        Carry::Cancel(..) => 9,
    }
}

/// THE PROCESS'S ADDRESS CARRIER, as the root installed it once its transports were folded: what a
/// framer's connection on the legacy wire seam ([`crate::wire::HostWire`]) rides. The first install
/// stands.
static ADDRESS_CARRIER: std::sync::OnceLock<Arc<dyn FramerDoor>> = std::sync::OnceLock::new();

/// Install the process's address carrier ([`ADDRESS_CARRIER`]); `false` when one was installed.
pub fn install_address_carrier(door: Arc<dyn FramerDoor>) -> bool {
    ADDRESS_CARRIER.set(door).is_ok()
}

/// The process's address carrier, where the root installed one.
#[must_use]
pub fn address_carrier() -> Option<Arc<dyn FramerDoor>> {
    ADDRESS_CARRIER.get().cloned()
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
    /// A program: its absolute path, arguments and whole environment.
    Program(busbar_contract::conn::Program),
}

impl Dest {
    /// What the host admits for a dial to this destination: exactly it.
    fn admission(&self) -> Admission {
        match self {
            Self::Authority(a) => Admission::Dial(vec![a.clone()]),
            Self::Program(p) => Admission::Spawn(p.clone()),
        }
    }
}

/// THE CARRIER OF ONE CONNECTION: its entry, the host I/O it rides, the carrier's connection token,
/// its two sides (each driven by the one task that reads, or writes, it), and the host handle the
/// dial made (a program's: its pid and exit are the host's to read).
pub struct Carried {
    door: Arc<dyn FramerDoor>,
    io: Arc<HostIo>,
    conn: u64,
    rd: Mutex<Driven>,
    wr: Mutex<Driven>,
    handle: Option<u64>,
    shut: AtomicBool,
}

fn side(m: &Mutex<Driven>) -> MutexGuard<'_, Driven> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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
    pub fn dial(door: Arc<dyn FramerDoor>, io: Arc<HostIo>, dest: &Dest) -> Result<Self, DialFailure> {
        let refused = || DialFailure::Refused("the transport is no carrier the host drives".into());
        let mut wr = Driven::of(door.as_ref()).ok_or_else(refused)?;
        let rd = Driven::of(door.as_ref()).ok_or_else(refused)?;
        let (args, env): (Vec<AbiStr>, Vec<Field>) = match dest {
            Dest::Program(p) => (
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
            Dest::Program(p) => Destination {
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
        let mut o: ConnOut = blank_out();
        let c = wr.cross(door.as_ref(), Carry::Dial(&mut i, &mut o), None);
        let (handle, failure) = io.settle(wr.ticket());
        match c {
            Some(c) if c.outcome == Outcome::Ready => Ok(Self {
                door,
                io,
                conn: o.conn,
                rd: Mutex::new(rd),
                wr: Mutex::new(wr),
                handle,
                shut: AtomicBool::new(false),
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
            rd: Mutex::new(rd),
            wr: Mutex::new(wr),
            handle,
            shut: AtomicBool::new(false),
        })
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
    pub fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        self.poll_flush(cx).map_err(|e| e.to_string())
    }

    /// Every byte the carrier took is on the wire (`flush`).
    ///
    /// # Errors
    ///
    /// The carrier failed the connection.
    pub fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut i: ConnIn = blank_in();
        i.conn = self.conn;
        let mut o: OutHead = blank_out();
        match side(&self.wr).cross(self.door.as_ref(), Carry::Flush(&mut i, &mut o), Some(cx)) {
            None => Poll::Pending,
            Some(c) if c.outcome == Outcome::Ready => Poll::Ready(Ok(())),
            Some(c) => Poll::Ready(Err(Self::io_error(&c))),
        }
    }

    /// Whether a `flush` is pending on the write side (it resumes before anything else is offered).
    #[must_use]
    pub fn flushing(&self) -> bool {
        side(&self.wr).pending == FLUSH
    }

    /// Offer `bytes` (`end` = they complete a frame of the carrier's own wire): how many it took.
    ///
    /// # Errors
    ///
    /// The carrier failed the connection.
    pub fn poll_write(
        &self,
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
        match side(&self.wr).cross(self.door.as_ref(), Carry::Write(&mut i, &mut o), Some(cx)) {
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
    pub fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<(usize, bool)>> {
        let mut i: ReadIn = blank_in();
        i.conn = self.conn;
        i.buf = buf.as_mut_ptr();
        i.cap = buf.len();
        let mut o: IoOut = blank_out();
        match side(&self.rd).cross(self.door.as_ref(), Carry::Read(&mut i, &mut o), Some(cx)) {
            None => Poll::Pending,
            Some(c) if c.outcome == Outcome::Ready => Poll::Ready(Ok((
                usize::try_from(o.len).unwrap_or(0).min(buf.len()),
                o.flags & READ_END_OF_FRAME != 0,
            ))),
            Some(c) => Poll::Ready(Err(Self::io_error(&c))),
        }
    }

    /// What the carrier knows of the connection's far end: its address and the local port.
    #[must_use]
    pub fn arrival(&self) -> Option<(String, u16)> {
        let mut peer = vec![0_u8; usize::try_from(MAX_ADDR).unwrap_or(256)];
        let mut i: ArrivalIn = blank_in();
        i.conn = self.conn;
        i.peer_buf = peer.as_mut_ptr();
        i.peer_cap = peer.len();
        let mut o: ArrivalOut = blank_out();
        let c = side(&self.rd).cross(self.door.as_ref(), Carry::Arrival(&mut i, &mut o), None)?;
        (c.outcome == Outcome::Ready).then(|| {
            let n = usize::try_from(o.peer_written).unwrap_or(0).min(peer.len());
            (
                String::from_utf8_lossy(&peer[..n]).into_owned(),
                u16::try_from(o.local_port).unwrap_or(0),
            )
        })
    }

    /// CLOSE: whatever pends on either side is cancelled, then the carrier's `shut`. Idempotent.
    pub fn close(&self) {
        if self.shut.swap(true, Ordering::AcqRel) {
            return;
        }
        side(&self.rd).cancel(self.door.as_ref());
        let mut wr = side(&self.wr);
        wr.cancel(self.door.as_ref());
        let mut i: ShutIn = blank_in();
        i.conn = self.conn;
        i.reason = CLOSE_NORMAL;
        let mut o: OutHead = blank_out();
        let _ = wr.cross(self.door.as_ref(), Carry::Shut(&mut i, &mut o), None);
    }

    /// Whether the connection was closed.
    #[must_use]
    pub fn is_shut(&self) -> bool {
        self.shut.load(Ordering::Acquire)
    }

    /// TAKE the dialled or accepted socket off the host's table as the byte stream moves on to the
    /// kernel's own serving loop, and forget the carrier's connection.
    #[must_use]
    pub fn hand_up(self) -> Option<std::net::TcpStream> {
        let taken = self.handle.and_then(|h| self.io.take_stream(h));
        // The carrier closes a handle the host no longer holds: nothing more.
        self.close();
        taken
    }
}

impl Drop for Carried {
    fn drop(&mut self) {
        self.close();
    }
}

/// A CARRIED CONNECTION AS A BYTE STREAM (`futures-io` `AsyncRead`/`AsyncWrite`), with the bytes a
/// framer took and did not answer in front of it: what the host serves over a detached connection
/// (the kernel's own loop, an upgrade's next layer). Every byte still crosses the carrier.
pub struct CarrierStream {
    carried: Arc<Carried>,
    first: std::collections::VecDeque<u8>,
}

impl std::fmt::Debug for CarrierStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarrierStream")
            .field("carried", &self.carried)
            .finish_non_exhaustive()
    }
}

impl CarrierStream {
    /// `carried`, read after `first`.
    #[must_use]
    pub fn new(carried: Arc<Carried>, first: Vec<u8>) -> Self {
        Self {
            carried,
            first: first.into(),
        }
    }
}

impl futures::io::AsyncRead for CarrierStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.first.is_empty() {
            let n = self.first.len().min(buf.len());
            for (slot, b) in buf.iter_mut().zip(self.first.drain(..n)) {
                *slot = b;
            }
            return Poll::Ready(Ok(n));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.carried.poll_read(cx, buf).map_ok(|(n, _)| n)
    }
}

impl futures::io::AsyncWrite for CarrierStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.carried.poll_write(cx, buf, false)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.carried.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.carried.poll_flush(cx))?;
        self.carried.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "tests/carrier_tests.rs"]
mod tests;
