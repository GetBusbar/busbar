// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `hyper_io!` SDK macro, expanded here as a framer expands it: the pipe carries bytes both

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
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{FramePiece, FramerOut, FramingIn, HeadSlots};
use busbar_contract::transport::codes::{
    slot, PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE,
    PIECE_HAS_DECLARED_LEN, PIECE_STREAM_FAILED, PIECE_WRITABLE, YIELD_ENDED, YIELD_HAS_DEADLINE,
    YIELD_MORE, YIELD_STREAM_FULL,
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

    let mut rb = ReadBuf::uninit(&mut store);
    let got = noop_cx(|cx| Pin::new(&mut s).poll_read(cx, rb.unfilled()));
    assert!(got.is_pending());

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

    fn wire_into(&mut self, into: &mut HostBuf<'_, u8>) {
        self.io.wire_into(into);
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
struct FillSlot;

impl SafeSlot for FillSlot {
    type Kind = busbar_contract::plugin::markers::TransportKind;
    type In = FramingIn;
    type Out = FramerOut;
    type State = ();
    fn call(
        _: Instance<'_, (), busbar_contract::plugin::markers::TransportKind>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        OWES.with(|c| {
            let mut owes = c.borrow_mut();
            let owes = owes.as_mut().expect("a framing to fill from");
            fill(
                owes,
                i.field(|x| &x.sink),
                &mut o,
                |c| if c == 0 { 1 } else { 3 },
                |c| if c == 0 { 0 } else { 2 },
            );
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

    assert_eq!((pieces[0].fault, pieces[1].fault), (0, 2));
    assert_eq!(out.yielded.flags, YIELD_ENDED);
}

/// A PIECE MAY STATE ITS OWN FAULT READING. A framer that maps an answer into its claim's numbering
#[test]
fn fill_writes_a_pieces_own_fault_reading_over_the_tables() {
    let mut o = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::from([
            Piece {
                status: Some(5),
                fault: Some(1),
                ..Piece::fields(1, Bytes::from_static(b"a: b\r\n"))
            },
            Piece {
                status: Some(5),
                ..Piece::failure(1, "why")
            },
        ]),
        ended: true,
    };
    let (_, _, _, pieces, _) = run_fill(&mut o, (8, 32, 4));
    assert_eq!(pieces.len(), 2);
    assert_eq!(
        (pieces[0].code, pieces[0].status_class, pieces[0].fault),
        (5, 3, 1),
        "the piece's own reading, its class still the table's"
    );
    assert_eq!(pieces[1].fault, 2, "no reading of its own: the table's");
}

/// Fill reports stream end separately from an empty frame.
#[test]
fn fill_says_the_stream_end_and_an_empty_frame_is_not_it() {
    let mut o = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::from([Piece::data(1, Bytes::new()), Piece::end(1)]),
        ended: false,
    };
    let (_, _, frame, pieces, _) = run_fill(&mut o, (8, 8, 4));
    assert!(frame.is_empty());
    assert_eq!(pieces.len(), 2);
    assert_eq!((pieces[0].len, pieces[0].flags), (0, PIECE_END_OF_FRAME));
    assert_eq!(
        (pieces[1].len, pieces[1].flags),
        (0, PIECE_END | PIECE_END_OF_FRAME)
    );
}

/// A STREAM'S OWN BACKPRESSURE through the SDK: an `emit` that left its stream full says so beside
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

/// A head's declared body length rides its field block's piece as `PIECE_HAS_DECLARED_LEN` and
#[test]
fn fill_states_a_heads_declared_length_where_it_declared_one() {
    let mut o = Owes {
        io: HostIo::new(0),
        pieces: VecDeque::from([
            Piece {
                declared_len: Some(1 << 33),
                ..Piece::fields(1, Bytes::from_static(b"k: v\r\n"))
            },
            Piece::fields(3, Bytes::from_static(b"k: v\r\n")),
        ]),
        ended: false,
    };
    let (_, _, _, pieces, _) = run_fill(&mut o, (1, 64, 4));
    assert_eq!(pieces.len(), 2);
    assert_eq!(
        (pieces[0].flags, pieces[0].declared_len),
        (
            PIECE_FIELDS | PIECE_END_OF_FRAME | PIECE_HAS_DECLARED_LEN,
            1 << 33
        )
    );
    assert_eq!(
        (pieces[1].flags, pieces[1].declared_len),
        (PIECE_FIELDS | PIECE_END_OF_FRAME, 0)
    );
}

/// A child spawned while the executor polls its parent must write during the same host drive.
#[test]
fn a_spawned_child_runs_before_the_host_drive_returns() {
    use hyper::rt::Executor;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    for pending_parent in [false, true] {
        let io = HostIo::new(0);
        let mut spawn = Some(HostIo::exec(&io));
        let mut stream = Some(io.stream());
        let polls = Arc::new(AtomicUsize::new(0));
        let parent_polls = Arc::clone(&polls);
        HostIo::exec(&io).execute(std::future::poll_fn(move |_| {
            parent_polls.fetch_add(1, Ordering::Relaxed);
            if let Some(spawn) = spawn.take() {
                let mut stream = stream.take().expect("one child owns the stream");
                spawn.execute(std::future::poll_fn(move |cx| {
                    Pin::new(&mut stream)
                        .poll_write(cx, b"child wire")
                        .map(|result| {
                            assert_eq!(result.expect("write through the real host pipe"), 10);
                        })
                }));
            }
            if pending_parent {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }));
        io.rounds(|_| Ok::<(), ()>(())).expect("drive");
        assert_eq!(
            io.take_wire(64),
            b"child wire",
            "newly spawned work is not stranded"
        );
        assert_eq!(
            polls.load(Ordering::Relaxed),
            if pending_parent { 2 } else { 1 }
        );
    }
}

/// A pending task that creates no new work must not spin until MAX_ROUNDS on every host call.
#[test]
fn a_pending_task_without_a_child_is_polled_once_per_host_drive() {
    use hyper::rt::Executor;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let io = HostIo::new(0);
    let polls = Arc::new(AtomicUsize::new(0));
    let task_polls = Arc::clone(&polls);
    HostIo::exec(&io).execute(std::future::poll_fn(move |_| {
        task_polls.fetch_add(1, Ordering::Relaxed);
        Poll::<()>::Pending
    }));
    io.rounds(|_| Ok::<(), ()>(())).expect("drive");
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    assert!(!io.wire_pending());
    io.rounds(|_| Ok::<(), ()>(()))
        .expect("a later explicit host drive");
    assert_eq!(polls.load(Ordering::Relaxed), 2);
}

// ── pipe hygiene (TRANSPORT-TLS T5) ──────────────────────────────────────────────────────────────
//
// The pipe holds the far side's request head (with its `Authorization`) in `rx` and the wire owed
// to it in `tx`. Every byte it is done with is wiped: on delivery to hyper, on a take of the wire,
// in the old block a growth releases, and on drop; and a drained pipe gives back what a large
// message grew it to. The blocks are inspected by the allocator below, before it frees them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::mem::MaybeUninit;

/// Blocks one test may watch at once.
const WATCHES: usize = 4;

/// The most a drained pipe keeps (T5's `PIPE_KEEP`).
const KEEP: usize = 64 * 1024;

thread_local! {
    /// Watched blocks: base address and the initialized range `[from, to)` inspected at free.
    static WATCHED: Cell<[Option<(usize, usize, usize)>; WATCHES]> =
        const { Cell::new([None; WATCHES]) };
    /// What each watched block's free saw: whether its range was all zero.
    static SEEN: Cell<[Option<bool>; WATCHES]> = const { Cell::new([None; WATCHES]) };
}

struct InspectBeforeFree;

// SAFETY: every allocation operation is forwarded unchanged to System (`realloc` is the trait's
// default: allocate, copy, `dealloc`, so a block a growth releases passes through `dealloc`). The
// observer reads only a range this thread registered as written, of a block still live.
unsafe impl GlobalAlloc for InspectBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the allocator caller supplies a valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let address = pointer.addr();
        let _ = WATCHED.try_with(|watched| {
            let mut all = watched.get();
            for (slot, watch) in all.iter_mut().enumerate() {
                let Some((base, from, to)) = *watch else {
                    continue;
                };
                if base != address {
                    continue;
                }
                *watch = None;
                let zero = to <= layout.size()
                    && (from..to).all(|index| {
                        // SAFETY: the test registered `[from, to)` as bytes the pipe wrote into
                        // this block; the block is still live (it is freed below), and the read
                        // goes through dealloc's own pointer.
                        unsafe { pointer.add(index).read_volatile() == 0 }
                    });
                let _ = SEEN.try_with(|seen| {
                    let mut s = seen.get();
                    s[slot] = Some(zero);
                    seen.set(s);
                });
            }
            watched.set(all);
        });
        // SAFETY: pointer and layout describe the allocator caller's live allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

/// Watch the block at `base` in `slot`: when it is freed, record whether `[from, to)` was zero.
fn watch(slot: usize, base: *const u8, from: usize, to: usize) {
    assert!(from < to);
    WATCHED.with(|watched| {
        let mut all = watched.get();
        assert!(all[slot].is_none(), "slot {slot} already watched");
        all[slot] = Some((base.addr(), from, to));
        watched.set(all);
    });
    SEEN.with(|seen| {
        let mut s = seen.get();
        s[slot] = None;
        seen.set(s);
    });
}

/// What the watched block's free saw (`None`: not freed yet).
fn seen(slot: usize) -> Option<bool> {
    SEEN.with(|seen| seen.get()[slot])
}

/// The bearer a request head carries; no wiped block may keep it.
const BEARER: &[u8] = b"authorization: Bearer sk-SENTINEL-T5-0123456789abcdef\r\n";

/// A request head of exactly `len` bytes carrying [`BEARER`], padded with non-zero bytes.
fn request_head(len: usize) -> Vec<u8> {
    let mut head = b"POST /v1/chat/completions HTTP/1.1\r\nhost: upstream\r\n".to_vec();
    head.extend_from_slice(BEARER);
    head.resize(len - 4, b'x');
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), len);
    head
}

/// The base of the read half's block. The deque goes out and back through a `Vec`, which moves
/// no allocation (`Vec: From<VecDeque>` keeps the buffer; `VecDeque: From<Vec>` is O(1)).
fn rx_base(io: &HostIo) -> *const u8 {
    io.pipe_for_test(|rx, _| {
        let v = Vec::from(std::mem::take(rx));
        let base = v.as_ptr();
        *rx = VecDeque::from(v);
        base
    })
}

/// Read everything ingested, as hyper does, `chunk` bytes at most per read.
fn read_all(io: &HostIo, chunk: usize) -> Vec<u8> {
    let mut s = io.stream();
    let mut store = vec![MaybeUninit::<u8>::uninit(); chunk];
    let mut got = Vec::new();
    while io.pending_input() > 0 {
        let mut rb = ReadBuf::uninit(&mut store);
        let polled = noop_cx(|cx| Pin::new(&mut s).poll_read(cx, rb.unfilled()));
        assert!(matches!(polled, Poll::Ready(Ok(()))));
        assert!(!rb.filled().is_empty());
        got.extend_from_slice(rb.filled());
    }
    got
}

/// Write `bytes` through the pipe's write half, as hyper does.
fn write(io: &HostIo, bytes: &[u8]) {
    let wrote = noop_cx(|cx| Pin::new(&mut io.stream()).poll_write(cx, bytes));
    assert!(matches!(wrote, Poll::Ready(Ok(n)) if n == bytes.len()));
}

/// A 1 KiB request head with a sentinel bearer, delivered to hyper, leaves no byte of it in the
/// read half's block: delivery wipes what it hands up.
#[test]
fn pipe_rx_wipes_on_delivery() {
    let io = HostIo::new(0);
    let head = request_head(1024);
    io.ingest(&head, false);
    assert_eq!(read_all(&io, 2048), head);
    assert_eq!(io.pending_input(), 0);

    let rx = Vec::from(io.pipe_for_test(|rx, _| std::mem::take(rx)));
    assert!(rx.is_empty());
    assert!(rx.capacity() >= head.len());
    watch(0, rx.as_ptr(), 0, head.len());
    drop(rx);
    assert_eq!(
        seen(0),
        Some(true),
        "the delivered head (and its bearer) stayed in the pipe's read block"
    );
}

/// A take of the wire (`take_wire`, and `wire_into` as `fill` calls it) leaves the rest at the
/// front and nothing behind it: the vacated tail is wiped.
#[test]
fn pipe_tx_wipes_after_take_wire() {
    let head = request_head(1024);

    let io = HostIo::new(0);
    write(&io, &head);
    assert_eq!(io.take_wire(512), &head[..512]);
    let tx = io.pipe_for_test(|_, tx| std::mem::take(tx));
    assert_eq!(tx, &head[512..]);
    watch(0, tx.as_ptr(), tx.len(), head.len());
    drop(tx);
    assert_eq!(
        seen(0),
        Some(true),
        "take_wire left a stale copy of the wire behind the rest"
    );

    let io = HostIo::new(0);
    write(&io, &head);
    let mut o = Owes {
        io,
        pieces: VecDeque::new(),
        ended: false,
    };
    let (_, wire, ..) = run_fill(&mut o, (256, 1, 1));
    assert_eq!(wire, &head[..256]);
    let tx = o.io.pipe_for_test(|_, tx| std::mem::take(tx));
    assert_eq!(tx, &head[256..]);
    watch(1, tx.as_ptr(), tx.len(), head.len());
    drop(tx);
    assert_eq!(
        seen(1),
        Some(true),
        "wire_into left a stale copy of the wire behind the rest"
    );
}

/// A growth of either half releases its old block only wiped, and keeps every byte in order.
#[test]
fn pipe_growth_wipes_old_block() {
    let head = request_head(1024);
    let more = vec![b'y'; 4096];

    let io = HostIo::new(0);
    io.ingest(&head, false);
    watch(0, rx_base(&io), 0, head.len());
    io.ingest(&more, false);
    assert_eq!(
        seen(0),
        Some(true),
        "the read half grew and released its old block unwiped"
    );
    let mut all = head.clone();
    all.extend_from_slice(&more);
    assert_eq!(read_all(&io, 1500), all);

    let io = HostIo::new(0);
    write(&io, &head);
    watch(1, io.pipe_for_test(|_, tx| tx.as_ptr()), 0, head.len());
    write(&io, &more);
    assert_eq!(
        seen(1),
        Some(true),
        "the write half grew and released its old block unwiped"
    );
    assert_eq!(io.take_wire(usize::MAX), all);
}

/// A drained pipe keeps at most 64 KiB per half, whatever a large message grew it to, and still
/// carries the next message.
#[test]
fn pipe_shrinks_after_large_message() {
    let io = HostIo::new(0);
    let large = vec![b'z'; 1 << 20];
    io.ingest(&large, false);
    assert_eq!(read_all(&io, 64 * 1024).len(), large.len());
    let rx_cap = io.pipe_for_test(|rx, _| rx.capacity());
    assert!(rx_cap <= KEEP, "a drained read half kept {rx_cap} bytes");

    let big = vec![b'w'; WRITE_HIGH_WATER];
    write(&io, &big[..WRITE_HIGH_WATER / 2]);
    write(&io, &big[WRITE_HIGH_WATER / 2..]);
    assert_eq!(io.take_wire(usize::MAX), big);
    let tx_cap = io.pipe_for_test(|_, tx| tx.capacity());
    assert!(tx_cap <= KEEP, "a drained write half kept {tx_cap} bytes");

    let head = request_head(1024);
    io.ingest(&head, false);
    assert_eq!(read_all(&io, 4096), head);
    write(&io, &head);
    assert_eq!(io.take_wire(usize::MAX), head);
}

/// Dropping the drive wipes what the pipe still holds, both halves.
#[test]
fn pipe_drop_wipes() {
    let head = request_head(1024);
    let io = HostIo::new(0);
    let stream = io.stream();
    io.ingest(&head, false);
    write(&io, &head);
    watch(0, rx_base(&io), 0, head.len());
    watch(1, io.pipe_for_test(|_, tx| tx.as_ptr()), 0, head.len());
    drop(stream);
    assert_eq!(seen(0), None, "the pipe lives while the drive does");
    drop(io);
    assert_eq!(
        seen(0),
        Some(true),
        "the dropped pipe's read block kept the head"
    );
    assert_eq!(
        seen(1),
        Some(true),
        "the dropped pipe's write block kept the wire"
    );
}

/// A body grown through `extend_wiped` releases its old block only wiped, and the shared view
/// `held_bytes` makes keeps its wiping owner until the last view drops, then frees it wiped.
#[test]
fn shared_body_owner_wipes_growth_and_only_releases_the_last_view() {
    let mut body = Vec::with_capacity(1);
    hyper_io::extend_wiped(&mut body, b"a");
    watch(0, body.as_ptr(), 0, body.len());
    hyper_io::extend_wiped(&mut body, b" private body");
    assert_eq!(
        seen(0),
        Some(true),
        "the body grew and released its old block unwiped"
    );
    watch(1, body.as_ptr(), 0, body.len());
    // Adopted without a copy: the wiping owner keeps the watched allocation.
    let bytes = hyper_io::held_bytes(busbar_contract::secure::SecureVec::from(body));
    let view = bytes.slice(2..);
    drop(bytes);
    assert_eq!(seen(1), None, "the owner lives while a view does");
    assert_eq!(&view[..], b"private body");
    drop(view);
    assert_eq!(
        seen(1),
        Some(true),
        "the last view's drop freed the body unwiped"
    );
}
