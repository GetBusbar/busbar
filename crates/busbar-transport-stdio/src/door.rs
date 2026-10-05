// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `stdio` DOOR: this transport as a LINE FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`), for the host's connector to frame a PROGRAM's pipes with
//! (ARCHITECT round 4 (e): a plane declares a stdio upstream need; the connector spawns the program
//! its settings name, owns the child and kills it on close). Every slot is a [`SafeSlot`] over the
//! SDK's generic lifecycle (`life(Framings)`): no `unsafe` here.
//!
//! The bytes are the host's: the connector reads the child's stdout and writes its stdin. The
//! framing is the stdio row's, byte for byte the legacy carrier's (`transport.rs`):
//!
//! * `ingest`: ONE FRAME PER LINE — the bytes up to each `0x0A`, the newline (and a carriage return
//!   before it) stripped, each a frame on stream `0` (the piece that ends it carries
//!   `PIECE_END_OF_FRAME`); a final unterminated line is a frame when the far side ends; a line past
//!   [`MAX_LINE_BYTES`] with no newline fails the framing. The far side's end, once every line is
//!   answered, is `YIELD_ENDED`.
//! * `emit`: a message's bytes, gathered until its last piece (`end`), go out as ONE line: the bytes
//!   and the `0x0A` this framer appends. A message holding a newline, or ending in a carriage
//!   return, cannot be one line and is refused before a byte is written.
//! * `encode`: an envelope's body is its line (stdio has no head: an envelope with fields is
//!   refused); `refuse`: the refusal's bytes are one line.
//! * `locate`: REFUSED — a stdio target is a program the connector spawns, never an authority.
//! * every carrier op (`listen` .. `arrival`) is REFUSED: a framer is not a carrier.
//!
//! No op pends and none asks for a deadline; a full sink is back-pressure (`YIELD_MORE`).

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail,
    WriteIn, CANCEL_NOTHING_MOVED, FRAMING_STREAM, PIECE_END_OF_FRAME, ROLE_FRAMER,
    UNIT0_FIRST_LINE, YIELD_ENDED, YIELD_MORE,
};

/// The longest line this framer frames: the legacy carrier's ceiling.
pub const MAX_LINE_BYTES: usize = crate::transport::MAX_LINE_BYTES;

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The claim this entry answers for: the stdio row's key.
pub const KEY: &str = "stdio";

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The schemes `stdio` claims, by name.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

/// The claim's row: no selector forms (a stdio channel has no surface to select on), a session
/// whose first unit opens on its first line.
const CLAIMS: &[Claim] = &[Claim {
    selector_forms: abi_str(""),
    egress_selector_forms: abi_str(""),
    facts: std::ptr::null(),
    facts_len: 0,
    status_namespace: NONE,
    session: 1,
    session_bound: 1,
    unit0_trigger: UNIT0_FIRST_LINE,
    status_at: 0,
    _reserved: 0,
}];

/// The transport kind's tail: a framer over a byte stream the host carries, composing over nothing.
const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
};

/// The door's Statement: the `stdio` line framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// The framings one instance holds.
pub struct Framings {
    framings: Mutex<HashMap<u64, Framing>>,
    next: AtomicU64,
}

type State = Held<Framings>;

impl Life for Framings {
    /// No framer op pends, so a cancel finds nothing in flight.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This framer reads no setting.
    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

impl Framings {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Framing>> {
        self.framings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin(&self, f: Framing) -> u64 {
        let token = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(token, f);
        token
    }
}

/// One connection's framing.
#[derive(Default)]
struct Framing {
    /// Bytes the far side sent, not yet cut into lines.
    inbound: Vec<u8>,
    /// The line being answered, and how much of it is answered.
    line: Option<(Vec<u8>, usize)>,
    /// The far side ended.
    ended: bool,
    /// The message being written, gathered until its last piece.
    message: Vec<u8>,
    /// Wire bytes owed to the far side.
    outbound: VecDeque<u8>,
}

/// Why a framing fails.
const TOO_LONG: &str = "a line ran past the stdio line ceiling without a newline";
const NOT_ONE_LINE: &str =
    "a message holding a newline, or ending in a carriage return, is not one line";

impl Framing {
    /// The next whole line off `inbound` (the newline and a carriage return before it stripped); at
    /// the far side's end, the unterminated rest. `Err` for a line past [`MAX_LINE_BYTES`].
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

    /// Whether a whole line is still owed to the host.
    fn owes_a_line(&self) -> bool {
        self.line.is_some()
            || self.inbound.contains(&b'\n')
            || (self.ended && !self.inbound.is_empty())
    }

    /// `bytes` as one line owed to the far side.
    fn write_line(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.contains(&b'\n') || bytes.last() == Some(&b'\r') {
            return Err(NOT_ONE_LINE);
        }
        self.outbound.extend(bytes);
        self.outbound.push_back(b'\n');
        Ok(())
    }

    /// Answer into `sink` what this framing owes: wire bytes, then whole lines as frames, as many as
    /// the sink holds, then the connection's end once nothing is left.
    fn answer(
        &mut self,
        sink: Lent<'_, FramerSink>,
        o: &mut Out<'_, FramerOut>,
    ) -> Result<(), &'static str> {
        let wire = drain_into(&mut self.outbound, &mut sink.wire());
        o.set(|o| &o.yielded.wire_len, wire as u64);
        let mut pieces = sink.pieces();
        let mut frame = sink.frame();
        let (mut used, mut count) = (0usize, 0usize);
        while pieces.cap() > count && frame.cap() > used {
            if self.line.is_none() {
                match self.next_line()? {
                    Some(line) => self.line = Some((line, 0)),
                    None => break,
                }
            }
            let Some((line, at)) = self.line.as_mut() else {
                break;
            };
            let n = frame.stream(&line[*at..]);
            *at += n;
            let done = *at == line.len();
            pieces.push(FramePiece {
                stream: 0,
                offset: used as u64,
                len: n as u64,
                code: 0,
                status_class: 0,
                flags: if done { PIECE_END_OF_FRAME } else { 0 },
                _reserved: 0,
                retry_after_secs: 0,
            });
            used += n;
            count += 1;
            if done {
                self.line = None;
            } else {
                break;
            }
        }
        o.set(|o| &o.yielded.frame_len, used as u64);
        o.set(
            |o| &o.yielded.pieces_len,
            u32::try_from(count).unwrap_or(u32::MAX),
        );
        let flags = if !self.outbound.is_empty() || self.owes_a_line() {
            YIELD_MORE
        } else if self.ended {
            YIELD_ENDED
        } else {
            0
        };
        o.set(|o| &o.yielded.flags, flags);
        Ok(())
    }
}

/// Move as many bytes off the front of `from` as `to` has room for; answers how many.
fn drain_into(from: &mut VecDeque<u8>, to: &mut HostBuf<'_, u8>) -> usize {
    let (a, b) = from.as_slices();
    let mut n = to.stream(a);
    if n == a.len() {
        n += to.stream(b);
    }
    from.drain(..n);
    n
}

fn framings<'a>(i: &Instance<'a, State>) -> Result<&'a Framings, Refusal> {
    i.get()
        .map(Held::life)
        .ok_or_else(|| Refusal::failed("no open instance"))
}

/// Run `op` on the framing `token` names and answer what it owes into `sink`.
fn with(
    inst: &Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    op: impl FnOnce(&mut Framing) -> Result<(), &'static str>,
) -> Outcome {
    let s = match framings(inst) {
        Ok(s) => s,
        Err(r) => return o.fail(r),
    };
    let mut framings = s.lock();
    let Some(f) = framings.get_mut(&token) else {
        return o.fail(Refusal::failed("no such framing"));
    };
    match op(f).and_then(|()| f.answer(sink, o)) {
        Ok(()) => Outcome::Ready,
        Err(why) => o.fail(Refusal::failed(why)),
    }
}

// ── the carrier ops: refused ─────────────────────────────────────────────────────────────────────

/// A carrier op: REFUSED. The pipes are the host's, so this framer carries nothing.
pub struct NotACarrier<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotACarrier<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`: REFUSED. A stdio target is a program the host spawns; it names no authority to dial.
pub struct Locate;
impl SafeSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, LocateIn>, mut o: Out<'_, LocateOut>) -> Outcome {
        o.fail(Refusal::failed(
            "locate: a stdio target is a program the host spawns, not an authority",
        ))
    }
}

/// `begin`: either side; nothing is owed to the far side first.
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, _: Lent<'_, BeginIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let token = s.begin(Framing::default());
        o.set(|o| &o.framing, token);
        Outcome::Ready
    }
}

/// `adopt`: the bytes another framer left unconsumed are this connection's first bytes.
pub struct Adopt;
impl SafeSlot for Adopt {
    type In = AdoptIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, AdoptIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let mut f = Framing::default();
        f.inbound.extend_from_slice(i.leftover());
        if let Err(why) = f.answer(i.field(|x| &x.sink), &mut o) {
            return o.fail(Refusal::failed(why));
        }
        let token = s.begin(f);
        o.set(|o| &o.framing, token);
        Outcome::Ready
    }
}

/// `ingest`: the bytes join the inbound; each whole line is a frame.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.inbound.extend_from_slice(bytes);
            f.ended |= i.end != 0;
            Ok(())
        })
    }
}

/// `emit`: a message's pieces, gathered; its last piece sends it as one line.
pub struct Emit;
impl SafeSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, EmitIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let bytes = i.bytes();
        let end = i.end_of_frame != 0;
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.message.extend_from_slice(bytes);
            if !end {
                return Ok(());
            }
            let message = std::mem::take(&mut f.message);
            f.write_line(&message)
        })
    }
}

/// `refuse`: the refusal's bytes are one line.
pub struct Refuse;
impl SafeSlot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, RefuseIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.write_line(bytes)
        })
    }
}

/// `timer`: this framer asks for no deadline; a call answers what is still owed.
pub struct Timer;
impl SafeSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |_| Ok(()))
    }
}

/// `finish`: the framing is forgotten; no frame follows.
pub struct Finish;
impl SafeSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        if s.lock().remove(&i.framing).is_none() {
            return o.fail(Refusal::failed("finish: no such framing"));
        }
        o.set(|o| &o.yielded.flags, YIELD_ENDED);
        Outcome::Ready
    }
}

/// `detach`: every byte ingested and not yet answered, into `frame`, and the framing is forgotten.
pub struct Detach;
impl SafeSlot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let mut framings = s.lock();
        let Some(f) = framings.get_mut(&i.framing) else {
            return o.fail(Refusal::failed("detach: no such framing"));
        };
        // What was ingested and not answered: the rest of the line being answered, then the
        // bytes not yet cut into lines.
        let mut rest: VecDeque<u8> = f
            .line
            .take()
            .map(|(line, at)| line[at..].to_vec())
            .unwrap_or_default()
            .into();
        rest.extend(f.inbound.drain(..));
        let n = drain_into(&mut rest, &mut i.field(|x| &x.sink).frame());
        o.set(|o| &o.yielded.frame_len, n as u64);
        if rest.is_empty() {
            framings.remove(&i.framing);
            o.set(|o| &o.yielded.flags, YIELD_ENDED);
        } else {
            f.inbound = rest.into_iter().collect();
            o.set(|o| &o.yielded.flags, YIELD_MORE);
        }
        Outcome::Ready
    }
}

/// `encode`: stdio has no head, so an envelope is its body, as one line; fields are refused.
pub struct Encode;
impl SafeSlot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    type State = State;
    fn call(_: Instance<'_, State>, i: Lent<'_, EncodeIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        if i.fields_len != 0 {
            return o.fail(Refusal::failed("encode: a stdio line carries no fields"));
        }
        let body = i.body();
        if body.contains(&b'\n') || body.last() == Some(&b'\r') {
            return o.fail(Refusal::failed(NOT_ONE_LINE));
        }
        let mut wire = i.field(|x| &x.sink).wire();
        if body.len() + 1 > wire.cap() {
            return o.fail(Refusal::failed(
                "encode: the wire buffer is smaller than the line",
            ));
        }
        wire.extend(body);
        wire.extend(b"\n");
        o.set(|o| &o.yielded.wire_len, body.len() as u64 + 1);
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Framings),
    kind_ops: {
        listen: Safe<NotACarrier<ListenIn, ListenOut>>,
        accept: Safe<NotACarrier<AcceptIn, AcceptOut>>,
        dial: Safe<NotACarrier<DialIn, ConnOut>>,
        read: Safe<NotACarrier<ReadIn, IoOut>>,
        write: Safe<NotACarrier<WriteIn, IoOut>>,
        flush: Safe<NotACarrier<ConnIn, OutHead>>,
        shut: Safe<NotACarrier<ShutIn, OutHead>>,
        arrival: Safe<NotACarrier<ArrivalIn, ArrivalOut>>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}
