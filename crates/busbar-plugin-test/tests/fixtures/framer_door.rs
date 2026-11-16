// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host target's own stream framer: an SDK-authored LINE framer (`FRAMING_STREAM`,
//! `FACT_ACCEPTS`) the stream target serves (`tests/target_stream.rs`, `[[bin]]
//! framer_target`). Each connection's lines are text messages on stream 1, and an EMIT writes its
//! bytes and a newline to the wire. It hands at most eight frame bytes and eight wire bytes per
//! answer and owes the rest (`YIELD_MORE`), so every exchange crosses re-calls.
//!
//! Its echo check, on the wire: an EMIT not marked text echoes `not-text`, and an EMIT on a full
//! stream echoes `emit-while-full`, instead of the bytes. Two lines act: `pending` answers
//! PENDING with no ticket (which the SDK judges FAULT); the echo of `full` answers the stream full
//! (`YIELD_STREAM_FULL`) with a deadline at once, and only TIMER hands the stream writable again.
//! EOF drops a partial line and ends the stream; FINISH writes `closed <reason>`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::*;

type Marker = busbar_contract::plugin::markers::TransportKind;

/// The most frame bytes, and wire bytes, one answer hands: the fixture's own small cap.
const STEP: usize = 8;
/// The one stream a connection's lines arrive on.
const STREAM: u64 = 1;

const CLAIMS: &[AbiStr] = &[abi_str("host-fixture-lines")];
const ROWS: &[Claim] = &[Claim::EMPTY];
const TAIL: TransportTail = {
    let mut tail = TransportTail::EMPTY.with_claim_rows(ROWS);
    tail.role = ROLE_FRAMER;
    tail.framing = FRAMING_STREAM;
    tail.facts = FACT_ACCEPTS;
    tail.frame_piece_size = FRAME_PIECE_SIZE;
    tail
};

/// One framing: what it read and what it owes the host.
#[derive(Default)]
struct Conn {
    /// The line read so far, not yet ended.
    line: Vec<u8>,
    /// Wire bytes owed.
    wire: Vec<u8>,
    /// Pieces owed: their bytes and `PIECE_*` flags.
    pieces: VecDeque<(Vec<u8>, u16)>,
    /// The stream was answered full and no TIMER has handed it writable yet.
    full: bool,
    /// When to call TIMER; `0` = never.
    deadline: u64,
    /// No frame follows.
    ended: bool,
    /// FINISH has written its line.
    closing: bool,
}

struct Fixture {
    next: AtomicU64,
    conns: Mutex<HashMap<u64, Conn>>,
}

impl Fixture {
    fn conns(&self) -> MutexGuard<'_, HashMap<u64, Conn>> {
        self.conns.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Life for Fixture {
    type Kind = Marker;
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            next: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
        })
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// Hands the host what `c` owes, at most [`STEP`] wire and frame bytes, and the yield flags.
fn fill(c: &mut Conn, sink: Lent<'_, FramerSink>, o: &mut Out<'_, FramerOut>) {
    let mut wire = sink.wire();
    let n = c.wire.len().min(STEP).min(wire.cap());
    wire.extend(&c.wire[..n]);
    c.wire.drain(..n);
    let (mut frame, mut pieces) = (sink.frame(), sink.pieces());
    let room = STEP.min(frame.cap());
    let mut frame_len = 0;
    while pieces.asked() < pieces.cap() {
        let Some((bytes, flags)) = c.pieces.front_mut() else {
            break;
        };
        let take = bytes.len().min(room - frame_len);
        if take == 0 && !bytes.is_empty() {
            break;
        }
        let whole = take == bytes.len();
        pieces.push(FramePiece {
            stream: STREAM,
            offset: frame_len as u64,
            len: take as u64,
            flags: if whole {
                *flags
            } else {
                *flags & !PIECE_END_OF_FRAME
            },
            ..FramePiece::ZERO
        });
        frame.extend(&bytes[..take]);
        frame_len += take;
        if whole {
            c.pieces.pop_front();
        } else {
            bytes.drain(..take);
        }
    }
    let more = !c.wire.is_empty() || !c.pieces.is_empty();
    let mut y = o.get().yielded;
    y.wire_len = wire.written() as u64;
    y.frame_len = frame_len as u64;
    y.pieces_len = pieces.written() as u32;
    y.flags = 0;
    y.next_deadline_ns = c.deadline;
    if more {
        y.flags |= YIELD_MORE;
    }
    if c.deadline != 0 {
        y.flags |= YIELD_HAS_DEADLINE;
    }
    if !more && c.ended {
        y.flags |= YIELD_ENDED;
    }
    o.set(|x| &x.yielded, y);
}

struct Refuses<I, O>(std::marker::PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Refuses<I, O> {
    type Kind = Marker;
    type In = I;
    type Out = O;
    type State = Held<Fixture>;
    fn call(_: Instance<'_, Self::State, Marker>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

/// `begin`: a new framing on the accepting side.
struct Begin;
impl SafeSlot for Begin {
    type Kind = Marker;
    type In = BeginIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, BeginIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return o.fail(Refusal::refused("begin: an open instance only"));
        };
        if i.side() != SIDE_ACCEPT {
            return o.fail(Refusal::refused("begin: the fixture accepts only"));
        }
        let f = held.life();
        let token = f.next.fetch_add(1, Ordering::SeqCst);
        let mut c = Conn::default();
        fill(&mut c, i.sink(), &mut o);
        f.conns().insert(token, c);
        o.set(|x| &x.framing, token);
        Outcome::Ready
    }
}

/// `ingest`: each ended line a text message; EOF ends the stream.
struct Ingest;
impl SafeSlot for Ingest {
    type Kind = Marker;
    type In = IngestIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return o.fail(Refusal::refused("ingest: an open instance only"));
        };
        let mut conns = held.life().conns();
        let Some(c) = conns.get_mut(&i.framing()) else {
            return o.fail(Refusal::failed("ingest: no such framing"));
        };
        c.line.extend_from_slice(i.bytes());
        while let Some(at) = c.line.iter().position(|b| *b == b'\n') {
            let rest = c.line.split_off(at + 1);
            let mut line = std::mem::replace(&mut c.line, rest);
            line.pop();
            if line == b"pending" {
                return Outcome::Pending;
            }
            c.pieces.push_back((line, PIECE_TEXT | PIECE_END_OF_FRAME));
        }
        if i.end() == 1 && !c.ended {
            c.line.clear();
            c.pieces
                .push_back((Vec::new(), PIECE_END | PIECE_END_OF_FRAME));
            c.ended = true;
        }
        fill(c, i.sink(), &mut o);
        Outcome::Ready
    }
}

/// `emit`: the bytes and a newline to the wire, after the echo check.
struct Emit;
impl SafeSlot for Emit {
    type Kind = Marker;
    type In = EmitIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, EmitIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return o.fail(Refusal::refused("emit: an open instance only"));
        };
        let mut conns = held.life().conns();
        let Some(c) = conns.get_mut(&i.framing()) else {
            return o.fail(Refusal::failed("emit: no such framing"));
        };
        let mut full = false;
        // A re-call (`YIELD_MORE`) is lent nothing and ends no frame: it only drains.
        if i.end_of_frame() == 1 {
            if c.full {
                c.wire.extend_from_slice(b"emit-while-full\n");
            } else if i.stream() != STREAM || i.flags() & EMIT_TEXT == 0 {
                c.wire.extend_from_slice(b"not-text\n");
            } else {
                c.wire.extend_from_slice(i.bytes());
                c.wire.push(b'\n');
                if i.bytes() == b"full" {
                    c.full = true;
                    c.deadline = i.sink().now_monotonic_ns();
                    full = true;
                }
            }
        }
        fill(c, i.sink(), &mut o);
        if full {
            let mut y = o.get().yielded;
            y.flags |= YIELD_STREAM_FULL;
            o.set(|x| &x.yielded, y);
        }
        Outcome::Ready
    }
}

/// `timer`: a full stream is writable again.
struct Timer;
impl SafeSlot for Timer {
    type Kind = Marker;
    type In = FramingIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return o.fail(Refusal::refused("timer: an open instance only"));
        };
        let mut conns = held.life().conns();
        let Some(c) = conns.get_mut(&i.framing()) else {
            return o.fail(Refusal::failed("timer: no such framing"));
        };
        if c.full {
            c.full = false;
            c.pieces.push_back((Vec::new(), PIECE_WRITABLE));
        }
        c.deadline = 0;
        fill(c, i.sink(), &mut o);
        Outcome::Ready
    }
}

/// `finish`: `closed <reason>` to the wire; the framing goes once it owes nothing.
struct Finish;
impl SafeSlot for Finish {
    type Kind = Marker;
    type In = FinishIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return o.fail(Refusal::refused("finish: an open instance only"));
        };
        let mut conns = held.life().conns();
        let framing = i.framing();
        let Some(c) = conns.get_mut(&framing) else {
            return o.fail(Refusal::failed("finish: no such framing"));
        };
        if !c.closing {
            c.closing = true;
            c.pieces.clear();
            c.full = false;
            c.deadline = 0;
            c.ended = true;
            c.wire
                .extend_from_slice(format!("closed {}\n", i.reason()).as_bytes());
        }
        fill(c, i.sink(), &mut o);
        if c.wire.is_empty() {
            conns.remove(&framing);
        }
        Outcome::Ready
    }
}

type No<I, O> = Safe<Refuses<I, O>>;
busbar_contract::plugin_door! {
    ops: Ops,
    statement: statement("host-fixture-framer", "1.6.0", 16).with_claims(CLAIMS).with_kind_tail(&TAIL),
    lifecycle: life(Fixture),
    kind_ops: {
        listen: No<ListenIn, ListenOut>, accept: No<AcceptIn, AcceptOut>,
        dial: No<DialIn, ConnOut>, read: No<ReadIn, IoOut>, write: No<WriteIn, IoOut>,
        flush: No<ConnIn, OutHead>, shut: No<ShutIn, OutHead>,
        arrival: No<ArrivalIn, ArrivalOut>, locate: No<LocateIn, LocateOut>,
        begin: Safe<Begin>, ingest: Safe<Ingest>, emit: Safe<Emit>,
        encode: No<EncodeIn, FramerOut>, refuse: No<RefuseIn, FramerOut>,
        finish: Safe<Finish>, detach: No<FramingIn, FramerOut>,
        adopt: No<AdoptIn, FramerOut>, timer: Safe<Timer>,
    },
}
