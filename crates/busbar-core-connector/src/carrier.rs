// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER A CONNECTION RIDES (TRANSPORT-STACK (2); `BUSBAR-1.6.0.md` THE DESIGN §5): one carrier

use std::io;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, ConnIn, ConnOut, Destination, DialIn, IoOut, ListenIn, ListenOut, ReadIn,
    ShutIn, WriteIn, CLOSE_NORMAL, DEST_AUTHORITY, DEST_PROGRAM, DEST_RETIRED, READ_END_OF_FRAME,
    WRITE_END_OF_FRAME,
};

use crate::framer::{Crossed, FramerDoor};
use crate::hostio::{Admission, HostIo, OpenFailure};

/// ONE SIDE of a carried connection: a ticket its entry's ops are driven on inline, and the task
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
        let program = matches!(dest, Dest::Program(..));
        let owner = door.io_owner();
        if program && owner.is_none() {
            return Err(DialFailure::Refused(
                "a program carrier has no checked host I/O owner".into(),
            ));
        }
        io.admit_for(wr.ticket(), dest.admission(), owner);
        let mut i: DialIn = blank_in();
        i.dest = &raw;
        i.supervision_key = match dest {
            Dest::Program(_, _, key) => *key,
            Dest::Authority(_) => 0,
        };
        let mut o: ConnOut = blank_out();
        let c = wr.cross(door.as_ref(), Carry::Dial(&mut i, &mut o), None);

        if c.is_none() {
            wr.cancel(door.as_ref());
        }
        let (handle, failure) = io.settle(wr.ticket());

        let ready = c.as_ref().is_some_and(|c| c.outcome == Outcome::Ready);
        let program_proven = !program
            || (failure.is_none()
                && owner
                    .zip(handle)
                    .is_some_and(|(owner, handle)| io.program_receipt(owner, handle)));
        if ready && !program_proven {
            let mut rejected = Self {
                door,
                io,
                conn: o.conn,
                rd,
                wr,
                handle,
                shut: false,
            };
            rejected.close();
            if let Some(handle) = handle {
                rejected.io.retire_handle(handle);
            }
            return Err(DialFailure::Refused(
                "the program carrier supplied no successful host spawn receipt".into(),
            ));
        }
        if let (false, Some(h)) = (ready, handle) {
            io.retire_handle(h);
        }
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

    /// THE KEY-RETIRED SIGNAL (`abi::transport::DEST_RETIRED`): tell the carrier `door` that the
    pub fn retire_key(door: &Arc<dyn FramerDoor>, io: &HostIo, key: u64) {
        let Some(mut wr) = Driven::of(door.as_ref()) else {
            return;
        };
        let raw = Destination {
            kind: DEST_RETIRED,
            _reserved: 0,
            authority: abi(b""),
            program: abi(b""),
            args: std::ptr::null(),
            args_len: 0,
            env: std::ptr::null(),
            env_len: 0,
        };
        let mut i: DialIn = blank_in();
        i.dest = &raw;
        i.supervision_key = key;
        let mut o: ConnOut = blank_out();
        let _ = wr.cross(door.as_ref(), Carry::Dial(&mut i, &mut o), None);
        let _ = io.settle(wr.ticket());
    }

    /// The connection `conn` the carrier `door` accepted (host handle `handle`).
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
    pub fn poll_connected(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        self.poll_flush(cx).map_err(|e| e.to_string())
    }

    /// Every byte the carrier took is on the wire (`flush`).
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
    #[must_use]
    pub fn hand_up(mut self) -> Option<std::net::TcpStream> {
        let taken = self.handle.and_then(|h| self.io.take_stream(h));

        self.close();
        taken
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

#[cfg(test)]
#[path = "tests/carrier_dial_retirement_tests.rs"]
mod dial_retirement_tests;

#[cfg(test)]
#[path = "tests/program_receipt_tests.rs"]
mod program_receipt_tests;
