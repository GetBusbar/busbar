// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `hyper_io!` SDK macro, expanded here as a framer expands it: the pipe carries bytes both
//! ways and pends past its high water, the timer runs on host time only, and `fill` splits what does
//! not fit and states the yield flags. `fill` runs from a slot body on the SDK's safe surface, the
//! only place a `Lent` exists.

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::Bytes;
use hyper::rt::{Read, ReadBuf, Timer, Write};

busbar_contract::hyper_io!(hyper::body::Bytes);

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::Entry;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    slot, FramePiece, FramerOut, FramingIn, HeadSlots, PIECE_CONTINUED, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_HAS_CODE, PIECE_STREAM_FAILED, PIECE_WRITABLE, YIELD_ENDED,
    YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};
use hyper_io::{
    field_cut, fill, mark_stream_full, HeadWords, HostIo, Owed, Piece, WRITE_HIGH_WATER,
};

fn noop_cx<R>(f: impl FnOnce(&mut Context<'_>) -> R) -> R {
    let waker = std::task::Waker::noop();
    f(&mut Context::from_waker(waker))
}

#[test]
fn the_pipe_reads_what_was_ingested_and_hands_up_what_was_written() {
    let io = HostIo::new(1_000);
    let mut s = io.stream();
    io.ingest(b"hello", false);
    let mut store = [std::mem::MaybeUninit::<u8>::uninit(); 16];
    let mut rb = ReadBuf::uninit(&mut store);
    let got = noop_cx(|cx| Pin::new(&mut s).poll_read(cx, rb.unfilled()));
    assert!(matches!(got, Poll::Ready(Ok(()))));
    assert_eq!(rb.filled(), b"hello");
    // Nothing more and no end: the read waits.
    let mut rb = ReadBuf::uninit(&mut store);
    let got = noop_cx(|cx| Pin::new(&mut s).poll_read(cx, rb.unfilled()));
    assert!(got.is_pending());
    // The far side's end reads as zero bytes.
    io.ingest(b"", true);
    let got = noop_cx(|cx| Pin::new(&mut s).poll_read(cx, rb.unfilled()));
    assert!(matches!(got, Poll::Ready(Ok(()))));
    assert!(rb.filled().is_empty());

    let wrote = noop_cx(|cx| Pin::new(&mut s).poll_write(cx, b"abc"));
    assert!(matches!(wrote, Poll::Ready(Ok(3))));
    assert!(io.wire_pending());
    assert_eq!(io.take_wire(2), b"ab");
    assert_eq!(io.take_wire(9), b"c");
    assert!(!io.wire_pending());
}

#[test]
fn a_write_past_the_high_water_pends_until_the_host_drains() {
    let io = HostIo::new(0);
    let mut s = io.stream();
    let big = vec![7_u8; WRITE_HIGH_WATER];
    assert!(matches!(
        noop_cx(|cx| Pin::new(&mut s).poll_write(cx, &big)),
        Poll::Ready(Ok(_))
    ));
    assert!(noop_cx(|cx| Pin::new(&mut s).poll_write(cx, b"x")).is_pending());
    let _ = io.take_wire(1);
    assert!(matches!(
        noop_cx(|cx| Pin::new(&mut s).poll_write(cx, b"x")),
        Poll::Ready(Ok(1))
    ));
}

#[test]
fn the_timer_runs_on_host_time_and_states_its_next_deadline() {
    let io = HostIo::new(5_000);
    let t = io.timer();
    let mut sleep = t.sleep(Duration::from_nanos(1_000));
    assert_eq!(io.next_deadline(), Some(6_000));
    assert!(noop_cx(|cx| sleep.as_mut().poll(cx)).is_pending());
    io.set_time(5_999);
    assert!(noop_cx(|cx| sleep.as_mut().poll(cx)).is_pending());
    io.set_time(6_000);
    assert!(noop_cx(|cx| sleep.as_mut().poll(cx)).is_ready());
    assert_eq!(io.next_deadline(), None, "a passed sleep is no deadline");
    let s2 = t.sleep_until_ns(9_000);
    assert_eq!(io.next_deadline(), Some(9_000));
    drop(s2);
    assert_eq!(io.next_deadline(), None, "a dropped sleep is no deadline");
}

#[test]
fn rounds_repeat_only_while_something_woke() {
    let io = HostIo::new(0);
    let mut n = 0;
    io.rounds(|_| {
        n += 1;
        Ok::<(), ()>(())
    })
    .expect("no error");
    assert_eq!(n, 1, "nothing woke: one round");
    let mut m = 0;
    io.rounds(|cx| {
        m += 1;
        if m < 3 {
            cx.waker().wake_by_ref();
        }
        Ok::<(), ()>(())
    })
    .expect("no error");
    assert_eq!(m, 3);
    assert_eq!(io.rounds(|_| Err("stop")), Err("stop"));
}

struct Owes {
    io: HostIo,
    pieces: VecDeque<Piece>,
    ended: bool,
}

impl Owed for Owes {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        self.io.take_wire(cap)
    }
    fn wire_pending(&self) -> bool {
        self.io.wire_pending()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.pieces
    }
    fn next_deadline(&self) -> Option<u64> {
        self.io.next_deadline()
    }
    fn ended(&self) -> bool {
        self.ended
    }
}

thread_local! {
    /// The framing `FillSlot` fills from, for the one call `run_fill` makes.
    static OWES: RefCell<Option<Owes>> = const { RefCell::new(None) };
    /// The call is an `emit` that left its stream full.
    static FULL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `fill` as a framer calls it: from a slot body on the SDK's safe surface, over the sink the host
/// lent (a `Lent` exists only there).
struct FillSlot;

impl SafeSlot for FillSlot {
    type In = FramingIn;
    type Out = FramerOut;
    type State = ();
    fn call(_: Instance<'_, ()>, i: Lent<'_, FramingIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        OWES.with(|c| {
            let mut owes = c.borrow_mut();
            let owes = owes.as_mut().expect("a framing to fill from");
            fill(owes, i.field(|x| &x.sink), &mut o, |c| {
                if c == 0 {
                    1
                } else {
                    3
                }
            });
        });
        if FULL.with(std::cell::Cell::get) {
            mark_stream_full(&mut o);
        }
        Outcome::Ready
    }
}

/// What one `fill` wrote: the answer, the wire, the frame, the pieces and the head slots.
type Filled = (FramerOut, Vec<u8>, Vec<u8>, Vec<FramePiece>, Vec<HeadSlots>);

fn run_fill(o: &mut Owes, caps: (usize, usize, usize)) -> Filled {
    run_fill_heads(o, caps, 4)
}

fn run_fill_heads(o: &mut Owes, caps: (usize, usize, usize), heads_cap: usize) -> Filled {
    let mut wire = vec![0_u8; caps.0];
    let mut frame = vec![0_u8; caps.1];
    // SAFETY: plain C data; all-zero is valid.
    let mut pieces: Vec<FramePiece> = vec![unsafe { std::mem::zeroed() }; caps.2];
    // SAFETY: plain C data; all-zero is valid.
    let mut i: FramingIn = unsafe { std::mem::zeroed() };
    i.sink.wire = wire.as_mut_ptr();
    i.sink.wire_cap = wire.len();
    i.sink.frame = frame.as_mut_ptr();
    i.sink.frame_cap = frame.len();
    i.sink.pieces = pieces.as_mut_ptr();
    i.sink.pieces_cap = pieces.len();
    let mut heads = vec![HeadSlots::default(); heads_cap];
    i.sink.heads = heads.as_mut_ptr();
    i.sink.heads_cap = heads.len();
    // SAFETY: plain C data; all-zero is valid.
    let mut out: FramerOut = unsafe { std::mem::zeroed() };
    let placeholder = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::new(),
        ended: false,
    };
    OWES.with(|c| *c.borrow_mut() = Some(std::mem::replace(o, placeholder)));
    // SAFETY: `i`'s sink points at the vectors above, live for the call; no instance is read.
    let r = unsafe {
        <Safe<FillSlot> as Entry>::enter(std::ptr::null_mut(), slot::TIMER, &i, &mut out)
    };
    assert_eq!(r, Outcome::Ready);
    *o = OWES
        .with(|c| c.borrow_mut().take())
        .expect("the framing back");
    let y = out.yielded;
    wire.truncate(y.wire_len as usize);
    frame.truncate(y.frame_len as usize);
    pieces.truncate(y.pieces_len as usize);
    heads.truncate(y.heads_len as usize);
    (out, wire, frame, pieces, heads)
}

#[test]
fn fill_splits_what_does_not_fit_and_says_more() {
    let io = HostIo::new(0);
    noop_cx(|cx| {
        let _ = Pin::new(&mut io.stream()).poll_write(cx, b"wire!");
    });
    let mut o = Owes {
        io,
        pieces: VecDeque::from([
            Piece::data(1, Bytes::from_static(b"abcdef")),
            Piece {
                status: Some(5),
                ..Piece::failure(1, "why")
            },
        ]),
        ended: true,
    };
    let (out, wire, frame, pieces, _) = run_fill(&mut o, (3, 4, 4));
    assert_eq!(wire, b"wir");
    assert_eq!(frame, b"abcd");
    assert_eq!(pieces.len(), 1);
    assert_eq!(
        pieces[0].flags & PIECE_END_OF_FRAME,
        0,
        "a split piece is not the frame's end"
    );
    assert_eq!(
        out.yielded.flags, YIELD_MORE,
        "more owed, and not ended yet"
    );

    let (out, wire, frame, pieces, _) = run_fill(&mut o, (8, 16, 4));
    assert_eq!(wire, b"e!");
    assert_eq!(frame, b"efwhy");
    assert_eq!(pieces.len(), 2);
    assert_eq!(pieces[0].flags, PIECE_END_OF_FRAME);
    assert_eq!(
        pieces[1].flags,
        PIECE_END_OF_FRAME | PIECE_STREAM_FAILED | PIECE_HAS_CODE
    );
    assert_eq!((pieces[1].code, pieces[1].status_class), (5, 3));
    assert_eq!(out.yielded.flags, YIELD_ENDED);
}

/// A STREAM'S OWN BACKPRESSURE through the SDK: an `emit` that left its stream full says so beside
/// whatever else the answer says, and a writable piece goes out empty, flagged writable and nothing
/// else (it ends no frame), between the stream's other pieces in order.
#[test]
fn an_emit_says_its_stream_is_full_and_a_writable_piece_ends_nothing() {
    let mut o = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::from([
            Piece::data(3, Bytes::from_static(b"ab")),
            Piece::writable(3),
            Piece::data(3, Bytes::from_static(b"cd")),
        ]),
        ended: false,
    };
    FULL.with(|f| f.set(true));
    let (out, _, frame, pieces, _) = run_fill(&mut o, (8, 8, 8));
    FULL.with(|f| f.set(false));
    assert_eq!(out.yielded.flags, YIELD_STREAM_FULL);
    assert_eq!(frame, b"abcd");
    let flags: Vec<u16> = pieces.iter().map(|p| p.flags).collect();
    assert_eq!(
        flags,
        vec![PIECE_END_OF_FRAME, PIECE_WRITABLE, PIECE_END_OF_FRAME]
    );
    assert_eq!((pieces[1].stream, pieces[1].len), (3, 0));
    let (out, ..) = run_fill(&mut o, (8, 8, 8));
    assert_eq!(out.yielded.flags & YIELD_STREAM_FULL, 0, "only when marked");
}

#[test]
fn fill_states_the_next_deadline() {
    let io = HostIo::new(0);
    let _sleep = io.timer().sleep_until_ns(42);
    let mut o = Owes {
        io,
        pieces: VecDeque::new(),
        ended: false,
    };
    let (out, ..) = run_fill(&mut o, (1, 1, 1));
    assert_eq!(out.yielded.flags, YIELD_HAS_DEADLINE);
    assert_eq!(out.yielded.next_deadline_ns, 42);
}

/// A stream's head words ride its head slots, in the answer that carries the head's first piece,
/// their bytes ahead of the piece's; a field block is cut only where a continuation extends a value.
#[test]
fn fill_hands_the_head_words_in_the_slots_and_cuts_a_field_block_inside_a_value() {
    let mut o = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::from([Piece {
            head: Some(HeadWords {
                method: Bytes::from_static(b"POST"),
                target: Bytes::from_static(b"/s/m"),
                ..HeadWords::default()
            }),
            ..Piece::fields(3, Bytes::from_static(b"x-a: 1234567\r\n"))
        }]),
        ended: false,
    };
    let (_, _, frame, pieces, heads) = run_fill(&mut o, (1, 20, 4));
    assert_eq!(heads.len(), 1);
    let h = heads[0];
    assert_eq!(h.stream, 3);
    let at = |s: busbar_contract::abi::transport::FrameSpan| {
        &frame[s.offset as usize..(s.offset + s.len) as usize]
    };
    assert_eq!(at(h.method), b"POST");
    assert_eq!(at(h.target), b"/s/m");
    assert_eq!((h.authority.len, h.reason.len), (0, 0));
    // 12 bytes of room are left: the cut falls inside the value.
    assert_eq!(pieces.len(), 1);
    assert_eq!(pieces[0].flags, PIECE_FIELDS);
    assert_eq!(&frame[8..], b"x-a: 1234567");
    let (_, _, frame, pieces, heads) = run_fill(&mut o, (1, 20, 4));
    assert!(
        heads.is_empty(),
        "the words went with the head's first piece"
    );
    assert_eq!(
        pieces[0].flags,
        PIECE_FIELDS | PIECE_CONTINUED | PIECE_END_OF_FRAME
    );
    assert_eq!(frame, b"\r\n");
    // Never inside a name: back to the line's start.
    assert_eq!(field_cut(b"x-a: 1\r\nx-bb: 2\r\n", 12, false), 8);
    assert_eq!(field_cut(b"x-a: 1\r\nx-bb: 2\r\n", 14, false), 14);
}

/// A host that takes no head slots is handed none, and the piece still moves.
#[test]
fn fill_drops_the_head_words_for_a_host_that_takes_no_slots() {
    let mut o = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::from([Piece {
            head: Some(HeadWords::reason(Bytes::from_static(b"OK"))),
            ..Piece::fields(1, Bytes::new())
        }]),
        ended: false,
    };
    let (_, _, frame, pieces, heads) = run_fill_heads(&mut o, (1, 8, 4), 0);
    assert!(heads.is_empty());
    assert!(frame.is_empty());
    assert_eq!(pieces[0].flags, PIECE_FIELDS | PIECE_END_OF_FRAME);
}
