// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `stdio` CARRIER, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2 and §5;
//! TRANSPORT-STACK (2)): the carrier ops over the HOST'S I/O (`busbar_contract::abi::host::io`,
//! `io.*`), and the framer ops refused. The host owns the program and its pipes; this carrier holds
//! only the host's opaque handle and owns the policy over it:
//!
//! * `dial` spawns the PROGRAM it is lent — an absolute path, its arguments and its whole
//!   environment, no shell — through the host (`io.spawn`, which spawns only what it admitted). An
//!   authority is not this carrier's destination, and it listens on nothing.
//! * `read` answers ONE FRAME PER LINE: the bytes up to each `0x0A`, the newline (and one carriage
//!   return before it) stripped; the read that completes a line carries `READ_END_OF_FRAME`, and a
//!   line longer than the host's buffer comes in several reads. A blank line is an empty frame. A
//!   line past [`MAX_LINE_BYTES`] fails the read. At the program's end a final unterminated line
//!   is a frame, then the clean end (`len` `0`, no frame bit).
//! * `write` gathers a frame's bytes until `WRITE_END_OF_FRAME`, then queues them as ONE line, the
//!   `0x0A` appended. A frame holding a newline, or ending in a carriage return, cannot be one line
//!   and is refused before a byte of it is written. What the pipe has not taken is written by the
//!   next `write` or `flush`.
//! * `flush` writes what is queued; `shut` closes the handle (the host kills the program) and
//!   forgets the connection; `arrival` answers no far end and no port.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::io::{Io, IoFailure};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::transport::{
    ArrivalIn, ArrivalOut, ConnIn, ConnOut, DialIn, IoOut, ReadIn, ShutIn, WriteIn,
    CANCEL_NOTHING_MOVED, DEST_PROGRAM, READ_END_OF_FRAME, WRITE_END_OF_FRAME,
};

/// The longest line this carrier frames, before its terminator: the design's per-connection
/// reading budget (a line is one frame on this wire).
pub const MAX_LINE_BYTES: usize = busbar_contract::MAX_CURSOR_BYTES;

/// The most bytes one connection holds queued for the program and not yet taken by its pipe: a
/// `write` past it waits for the pipe to drain.
pub const MAX_QUEUED_BYTES: usize = 256 * 1024;

/// How many bytes one pipe read takes.
const READ_CHUNK: usize = 16 * 1024;

/// Why a read fails.
pub const TOO_LONG: &str = "a line ran past the stdio line ceiling without a newline";
/// Why a write is refused.
pub const NOT_ONE_LINE: &str =
    "a message holding a newline, or ending in a carriage return, is not one line";

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// What one instance carries: its connections, each by the token it minted.
pub struct Carried {
    conns: Mutex<HashMap<u64, Arc<Mutex<Conn>>>>,
    next: AtomicU64,
}

/// One program's connection: the host's handle, the line being cut on the way in, the frame being
/// gathered and the bytes queued on the way out.
#[derive(Default)]
struct Conn {
    io: u64,
    /// Bytes the program wrote, not yet cut into lines.
    inbound: Vec<u8>,
    /// The line being answered, and how much of it is answered.
    line: Option<(Vec<u8>, usize)>,
    /// The program's output ended.
    ended: bool,
    /// The frame being written, gathered until its end.
    message: Vec<u8>,
    /// Bytes owed to the program, from `sent` on.
    outbound: Vec<u8>,
    sent: usize,
}

/// What every slot reads: the SDK's lifecycle state over [`Carried`].
type State = Held<Carried>;

impl Life for Carried {
    /// A PENDING carrier op moved nothing, so a cancel finds nothing moved.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This carrier reads no setting.
    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            conns: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Carried {
    fn conn(&self, token: u64) -> Option<Arc<Mutex<Conn>>> {
        lock(&self.conns).get(&token).cloned()
    }
}

/// The open instance and the host's I/O for this op, or the refusal a call on none earns.
fn carried<'a>(i: &Instance<'a, State>) -> Result<(&'a Carried, Io<'a>), Refusal> {
    let held = i
        .get()
        .ok_or_else(|| Refusal::failed("no open instance"))?;
    let io = held
        .host()
        .map(|h| h.io(i.ticket()))
        .filter(Io::armed)
        .ok_or_else(|| Refusal::failed("the host lent this carrier no I/O"))?;
    Ok((held.life(), io))
}

/// The host's answer, as this op's refusal: the host's policy is REFUSED, the system's FAILED.
fn refusal(e: &IoFailure) -> Refusal {
    match e {
        IoFailure::Refused(t) => Refusal::refused(t.clone()),
        other => Refusal::failed(other.text().to_owned()),
    }
}

/// Run `body` over the instance, its I/O and the connection `conn`, failing the op without one.
macro_rules! over {
    ($inst:expr, $o:expr, $conn:expr, |$io:ident, $c:ident| $body:block) => {{
        let (carried, mut $io) = match carried(&$inst) {
            Ok(x) => x,
            Err(r) => return $o.fail(r),
        };
        let Some(conn) = carried.conn($conn) else {
            return $o.fail(Refusal::failed("no such connection"));
        };
        let mut $c = lock(&conn);
        $body
    }};
}

impl Conn {
    /// The next whole line off `inbound` (the newline and a carriage return before it stripped);
    /// at the program's end, the unterminated rest. `Err` for a line past [`MAX_LINE_BYTES`].
    fn next_line(&mut self) -> Result<Option<Vec<u8>>, &'static str> {
        match self.inbound.iter().position(|&b| b == b'\n') {
            Some(at) => {
                let mut line: Vec<u8> = self.inbound.drain(..=at).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > MAX_LINE_BYTES {
                    return Err(TOO_LONG);
                }
                Ok(Some(line))
            }
            None if self.inbound.len() > MAX_LINE_BYTES => Err(TOO_LONG),
            None if self.ended && !self.inbound.is_empty() => {
                Ok(Some(std::mem::take(&mut self.inbound)))
            }
            None => Ok(None),
        }
    }

    /// Write what is queued, as far as the pipe takes it now: `Pending` while some is left.
    fn drain(&mut self, io: &mut Io<'_>) -> Poll<Result<(), IoFailure>> {
        while self.sent < self.outbound.len() {
            match io.write(self.io, &self.outbound[self.sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(n)) => self.sent += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        self.outbound.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

// ── the roles it does not play ──────────────────────────────────────────────────────────────────

/// A slot of a role this carrier does not play (every framer op; `listen` and `accept`: a stdio
/// carrier listens on nothing): REFUSED.
pub struct Refused<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for Refused<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

// ── the carrier ──────────────────────────────────────────────────────────────────────────────────

/// `dial`: spawn the program, through the host. An authority is not this carrier's destination.
pub struct Dial;
impl SafeSlot for Dial {
    type In = DialIn;
    type Out = ConnOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, DialIn>, mut o: Out<'_, ConnOut>) -> Outcome {
        let Some(dest) = i.dest() else {
            return o.fail(Refusal::failed("dial: no destination"));
        };
        if dest.kind != DEST_PROGRAM {
            return o.fail(Refusal::refused(
                "dial: a stdio carrier reaches a program, never an authority",
            ));
        }
        let (c, mut io) = match carried(&inst) {
            Ok(x) => x,
            Err(r) => return o.fail(r),
        };
        match io.spawn_dest(dest) {
            Ok(h) => {
                let token = c.next.fetch_add(1, Ordering::Relaxed);
                let conn = Conn {
                    io: h,
                    ..Conn::default()
                };
                lock(&c.conns).insert(token, Arc::new(Mutex::new(conn)));
                o.set(|o| &o.conn, token);
                Outcome::Ready
            }
            Err(e) => o.fail(refusal(&e)),
        }
    }
}

/// `read`: the next line, or the rest of the one being answered, into the host's buffer.
pub struct Read;
impl SafeSlot for Read {
    type In = ReadIn;
    type Out = IoOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ReadIn>, mut o: Out<'_, IoOut>) -> Outcome {
        over!(inst, o, i.conn, |io, c| {
            let mut buf = i.buf();
            loop {
                if let Some((line, at)) = c.line.as_mut() {
                    let n = buf.stream(&line[*at..]);
                    *at += n;
                    let done = *at == line.len();
                    if done {
                        c.line = None;
                    }
                    o.set(|o| &o.len, n as u64);
                    o.set(|o| &o.flags, if done { READ_END_OF_FRAME } else { 0 });
                    return Outcome::Ready;
                }
                match c.next_line() {
                    Ok(Some(line)) => {
                        c.line = Some((line, 0));
                        continue;
                    }
                    Ok(None) if c.ended => {
                        o.set(|o| &o.len, 0);
                        return Outcome::Ready;
                    }
                    Ok(None) => {}
                    Err(why) => return o.fail(Refusal::failed(why)),
                }
                let mut chunk = [0_u8; READ_CHUNK];
                match io.read(c.io, &mut chunk) {
                    Poll::Pending => return Outcome::Pending,
                    Poll::Ready(Ok(0)) => c.ended = true,
                    Poll::Ready(Ok(n)) => c.inbound.extend_from_slice(&chunk[..n]),
                    Poll::Ready(Err(e)) => return o.fail(refusal(&e)),
                }
            }
        })
    }
}

/// `write`: a frame's bytes gathered until its end, then queued as one line and written as far as
/// the pipe takes them.
pub struct Write;
impl SafeSlot for Write {
    type In = WriteIn;
    type Out = IoOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, WriteIn>, mut o: Out<'_, IoOut>) -> Outcome {
        let bytes = i.bytes();
        let end = i.flags & WRITE_END_OF_FRAME != 0;
        over!(inst, o, i.conn, |io, c| {
            // What the pipe has not taken goes first; past the cap, nothing more is taken.
            match c.drain(&mut io) {
                Poll::Ready(Err(e)) => return o.fail(refusal(&e)),
                Poll::Pending if c.outbound.len() - c.sent >= MAX_QUEUED_BYTES => {
                    return Outcome::Pending;
                }
                _ => {}
            }
            c.message.extend_from_slice(bytes);
            if end {
                let message = std::mem::take(&mut c.message);
                if message.contains(&b'\n') || message.last() == Some(&b'\r') {
                    return o.fail(Refusal::failed(NOT_ONE_LINE));
                }
                c.outbound.extend_from_slice(&message);
                c.outbound.push(b'\n');
                if let Poll::Ready(Err(e)) = c.drain(&mut io) {
                    return o.fail(refusal(&e));
                }
            }
            o.set(|o| &o.len, bytes.len() as u64);
            Outcome::Ready
        })
    }
}

/// `flush`: what is queued, written: READY once the pipe took it all.
pub struct Flush;
impl SafeSlot for Flush {
    type In = ConnIn;
    type Out = OutHead;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ConnIn>, mut o: Out<'_, OutHead>) -> Outcome {
        over!(inst, o, i.conn, |io, c| {
            match c.drain(&mut io) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(())) => Outcome::Ready,
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `shut`: the handle is closed (the host kills the program) and the connection forgotten. An
/// unknown connection is already closed.
pub struct Shut;
impl SafeSlot for Shut {
    type In = ShutIn;
    type Out = OutHead;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ShutIn>, mut o: Out<'_, OutHead>) -> Outcome {
        let (c, mut io) = match carried(&inst) {
            Ok(x) => x,
            Err(r) => return o.fail(r),
        };
        let gone = lock(&c.conns).remove(&i.conn);
        if let Some(conn) = gone {
            let h = lock(&conn).io;
            let _ = io.close(h);
        }
        Outcome::Ready
    }
}

/// `arrival`: a program has no far end and arrived on no port.
pub struct Arrival;
impl SafeSlot for Arrival {
    type In = ArrivalIn;
    type Out = ArrivalOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ArrivalIn>, mut o: Out<'_, ArrivalOut>) -> Outcome {
        let known = inst
            .get()
            .is_some_and(|h| h.life().conn(i.conn).is_some());
        if known {
            Outcome::Ready
        } else {
            o.fail(Refusal::failed("arrival: no such connection"))
        }
    }
}
