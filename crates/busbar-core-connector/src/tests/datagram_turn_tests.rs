// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checked-batch continuation and the finite bidirectional publication boundary.

use super::*;
use busbar_contract::abi::transport::{FramePiece, PIECE_END_OF_FRAME, ROLE_FRAMER, YIELD_MORE};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

const CALLER_LINE: u64 = 11;
const UPSTREAM_LINE: u64 = 21;
const CALLER_CHANNEL: u64 = 12;
const START: &[u8] = b"start";
const CALLER_FRAME: &[u8] = b"a";
const UPSTREAM_FRAME: &[u8] = b"b";
const CALLER_MESSAGE: &[u8] = b"caller Emit channel";

#[derive(Clone, Copy)]
enum Origin {
    Caller,
    Upstream,
    FiniteCaller,
    FiniteUpstream,
}

struct CrossedEmit {
    pointer: usize,
    len: usize,
    end: bool,
    text: bool,
    more: bool,
    capacity: usize,
}

#[derive(Default)]
struct Output {
    pieces: VecDeque<(u64, Vec<u8>)>,
    emitted: Vec<CrossedEmit>,
    expanded: bool,
    recall_failure: Option<RecallFailure>,
}

#[derive(Clone, Copy)]
enum RecallFailure {
    Failed,
    Unwind,
}

struct Branching {
    facts: DoorFacts,
    origin: Origin,
    output: Mutex<Output>,
    finished: AtomicUsize,
}

impl Branching {
    fn new(origin: Origin) -> Arc<Self> {
        Arc::new(Self {
            facts: DoorFacts {
                name: "datagram-turn".into(),
                claims: vec!["datagram-turn"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: Vec::new(),
                datagram: true,
            },
            origin,
            output: Mutex::new(Output::default()),
            finished: AtomicUsize::new(0),
        })
    }
}

impl FramerDoor for Branching {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(_, out) => out.framing = CALLER_LINE,
            Call::Emit(input, out) => {
                let mut output = self.output.lock().unwrap();
                // SAFETY: this input lends exactly len initialized application bytes.
                let bytes = unsafe { std::slice::from_raw_parts(input.bytes, input.len) };
                if bytes.is_empty() {
                    if let Some(failure) = output.recall_failure.take() {
                        drop(output);
                        match failure {
                            RecallFailure::Failed => {
                                return Crossed {
                                    outcome: Outcome::Failed,
                                    error: None,
                                }
                            }
                            RecallFailure::Unwind => panic!("the recall unwinds"),
                        }
                    }
                }
                if !bytes.is_empty() {
                    assert!(
                        output.pieces.is_empty(),
                        "fresh input before same-op recall"
                    );
                    if matches!(self.origin, Origin::FiniteCaller | Origin::FiniteUpstream) {
                        let (depth, path) = bytes.split_first().unwrap();
                        if *depth == 0 {
                            output.pieces.push_back((CALLER_CHANNEL, path.to_vec()));
                        } else {
                            let stream = match self.origin {
                                Origin::FiniteCaller => CALLER_LINE,
                                _ => UPSTREAM_LINE,
                            };
                            for bit in [0, 1] {
                                let mut next = vec![*depth - 1];
                                next.extend_from_slice(path);
                                next.push(bit);
                                output.pieces.push_back((stream, next));
                            }
                        }
                    } else {
                        let generated = match self.origin {
                            Origin::Caller if bytes == START => Some((CALLER_LINE, CALLER_FRAME)),
                            Origin::Upstream if bytes == CALLER_FRAME && !output.expanded => {
                                Some((UPSTREAM_LINE, UPSTREAM_FRAME))
                            }
                            _ => None,
                        };
                        if let Some((stream, value)) = generated {
                            output.expanded = true;

                            for _ in 0..=input.sink.pieces_cap {
                                output.pieces.push_back((stream, value.to_vec()));
                            }
                        } else if matches!(self.origin, Origin::Caller) && bytes == UPSTREAM_FRAME {
                            output
                                .pieces
                                .push_back((CALLER_CHANNEL, CALLER_MESSAGE.to_vec()));
                        }
                    }
                }
                let mut used = 0;
                let mut pieces = 0;
                while pieces < input.sink.pieces_cap {
                    let Some((stream, bytes)) = output.pieces.front() else {
                        break;
                    };
                    if used + bytes.len() > input.sink.frame_cap {
                        break;
                    }
                    // SAFETY: both loans were capacity-checked; the spans are initialized
                    // exactly once and copied out by the host before the next crossing.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            input.sink.frame.add(used),
                            bytes.len(),
                        );
                        input.sink.pieces.add(pieces).write(FramePiece {
                            stream: *stream,
                            offset: used as u64,
                            len: bytes.len() as u64,
                            flags: PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                    used += bytes.len();
                    pieces += 1;
                    output.pieces.pop_front();
                }
                let more = !output.pieces.is_empty();
                out.yielded.frame_len = used as u64;
                out.yielded.pieces_len = pieces as u32;
                if more {
                    out.yielded.flags = YIELD_MORE;
                }
                output.emitted.push(CrossedEmit {
                    pointer: input.bytes as usize,
                    len: input.len,
                    end: input.end_of_frame != 0,
                    text: input.flags & busbar_contract::abi::transport::EMIT_TEXT != 0,
                    more,
                    capacity: input.sink.pieces_cap,
                });
            }
            Call::Finish(..) => {
                self.finished.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

fn framing(door: &Arc<Branching>) -> DatagramFraming {
    DatagramFraming::accept_minted(door.clone(), "127.0.0.1:9".parse().unwrap())
        .unwrap()
        .0
}

#[test]
fn a_checked_batch_pauses_before_a_same_op_empty_input_recall() {
    let door = Branching::new(Origin::Caller);
    let mut framing = framing(&door);
    let mut turn = framing
        .emit_turn(CALLER_LINE, START, true, true, Instant::now())
        .unwrap();
    let first = turn.next_batch().unwrap().unwrap();
    assert!(!first.pieces.is_empty());
    {
        let output = door.output.lock().unwrap();
        assert_eq!(output.emitted.len(), 1, "publication pause made no recall");
        assert_eq!(output.emitted[0].pointer, START.as_ptr() as usize);
        assert_eq!(output.emitted[0].len, START.len());
        assert!(output.emitted[0].end && output.emitted[0].text && output.emitted[0].more);
    }
    let second = turn.next_batch().unwrap().unwrap();
    assert_eq!(second.pieces.len(), 1);
    assert!(turn.next_batch().unwrap().is_none());
    drop(turn);
    let output = door.output.lock().unwrap();
    assert_eq!(output.emitted.len(), 2);
    assert_eq!(output.emitted[1].len, 0);
    assert!(!output.emitted[1].end && !output.emitted[1].text && !output.emitted[1].more);
    let expected = output.emitted[0].capacity + 1;
    let delivered: Vec<_> = first
        .pieces
        .iter()
        .chain(&second.pieces)
        .map(|piece| (piece.stream, piece.bytes.clone()))
        .collect();
    assert_eq!(
        delivered,
        vec![(CALLER_LINE, CALLER_FRAME.to_vec()); expected]
    );
    drop(output);
    drop(framing);
    assert_eq!(door.finished.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelling_a_partly_published_turn_finishes_its_accepted_input_once() {
    let door = Branching::new(Origin::Caller);
    let mut framing = framing(&door);
    {
        let mut turn = framing
            .emit_turn(CALLER_LINE, START, true, false, Instant::now())
            .unwrap();
        let first = turn.next_batch().unwrap().unwrap();
        assert!(!first.pieces.is_empty());
    }
    assert_eq!(door.finished.load(Ordering::SeqCst), 1);
    assert!(framing
        .emit(CALLER_LINE, CALLER_FRAME, true, false, Instant::now())
        .is_err());
    drop(framing);
    assert_eq!(door.finished.load(Ordering::SeqCst), 1);
    assert_eq!(
        door.output.lock().unwrap().emitted.len(),
        1,
        "no cancelled recall crossed"
    );
}

#[test]
fn a_failed_or_unwinding_recall_finishes_the_accepted_operation_once() {
    for failure in [RecallFailure::Failed, RecallFailure::Unwind] {
        let door = Branching::new(Origin::Caller);
        let mut framing = framing(&door);
        door.output.lock().unwrap().recall_failure = Some(failure);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut turn = framing
                .emit_turn(CALLER_LINE, START, true, false, Instant::now())
                .unwrap();
            assert!(turn.next_batch().unwrap().is_some());
            let error = turn.next_batch();
            assert!(error.is_err());
            assert!(turn.next_batch().unwrap().is_none());
        }));
        assert_eq!(result.is_err(), matches!(failure, RecallFailure::Unwind));
        assert_eq!(door.finished.load(Ordering::SeqCst), 1);
        drop(framing);
        assert_eq!(door.finished.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn a_finite_pair_can_both_owe_same_op_recalls_before_either_host_batch_is_published() {
    let caller = Branching::new(Origin::Caller);
    let upstream = Branching::new(Origin::Upstream);
    let mut a = framing(&caller);
    let mut b = framing(&upstream);
    let mut a_turn = a
        .emit_turn(CALLER_LINE, START, true, false, Instant::now())
        .unwrap();
    let mut a_output = a_turn.next_batch().unwrap().unwrap();
    let mut a_batch = std::mem::take(&mut a_output.pieces).into_iter();
    drop(a_output);
    let first_a = a_batch.next().unwrap();
    let mut b_turn = b
        .emit_turn(UPSTREAM_LINE, &first_a.bytes, true, false, Instant::now())
        .unwrap();
    let b_batch = b_turn.next_batch().unwrap().unwrap();

    assert!(
        a_batch.len() > 0,
        "A still owns output after forwarding just its first frame"
    );
    assert!(
        !b_batch.pieces.is_empty(),
        "B produced output that needs fresh input at A"
    );
    assert!(caller.output.lock().unwrap().emitted.last().unwrap().more);
    assert!(upstream.output.lock().unwrap().emitted.last().unwrap().more);

    let a_output = caller.output.lock().unwrap();
    let b_output = upstream.output.lock().unwrap();
    assert_eq!(a_batch.len(), a_output.emitted[0].capacity - 1);
    assert_eq!(b_batch.pieces.len(), b_output.emitted[0].capacity);
    assert_eq!(a_output.pieces.len(), 1);
    assert_eq!(b_output.pieces.len(), 1);
    assert!(b_batch
        .pieces
        .iter()
        .all(|g| g.bytes.as_slice() == UPSTREAM_FRAME));
    drop((a_output, b_output));

    drop((b_batch, a_batch, b_turn, a_turn));
    assert_eq!(caller.finished.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.finished.load(Ordering::SeqCst), 1);
}

/// Each real framer crossing answers at most two short pieces and completes immediately. The
#[test]
fn distinct_finite_emits_outgrow_two_retained_slots_without_using_the_recall_budget() {
    for fifo in [true, false] {
        for depth in [2_u8, 3, 5] {
            let caller = Branching::new(Origin::FiniteCaller);
            let upstream = Branching::new(Origin::FiniteUpstream);
            let mut a = framing(&caller);
            let mut b = framing(&upstream);
            let now = Instant::now();
            let mut awaiting = VecDeque::from([(true, vec![depth])]);
            let mut high_water = awaiting.len();
            let mut delivered = Vec::new();
            loop {
                let next = if fifo {
                    awaiting.pop_front()
                } else {
                    awaiting.pop_back()
                };
                let Some((at_caller, bytes)) = next else {
                    break;
                };
                let (framing, stream, line) = if at_caller {
                    (&mut a, CALLER_LINE, CALLER_LINE)
                } else {
                    (&mut b, UPSTREAM_LINE, UPSTREAM_LINE)
                };
                let mut answer = framing.emit(stream, &bytes, true, false, now).unwrap();
                for piece in std::mem::take(&mut answer.pieces) {
                    if piece.stream == line {
                        awaiting.push_back((!at_caller, piece.bytes));
                    } else {
                        assert_eq!(piece.stream, CALLER_CHANNEL);
                        delivered.push(piece.bytes);
                    }
                }
                high_water = high_water.max(awaiting.len());
            }
            let leaves = 1_usize << depth;
            assert_eq!(
                high_water,
                if fifo { leaves } else { usize::from(depth) + 1 },
                "depth {depth}, FIFO={fifo}: retained publication frontier"
            );
            assert!(high_water > 2);
            let mut expected: Vec<Vec<u8>> = (0..leaves)
                .map(|path| {
                    (0..depth)
                        .rev()
                        .map(|bit| ((path >> bit) & 1) as u8)
                        .collect()
                })
                .collect();
            if !fifo {
                expected.reverse();
            }
            assert_eq!(delivered, expected);
            let a_output = caller.output.lock().unwrap();
            let b_output = upstream.output.lock().unwrap();
            assert_eq!(
                a_output.emitted.len() + b_output.emitted.len(),
                2 * leaves - 1
            );
            assert!(a_output
                .emitted
                .iter()
                .chain(&b_output.emitted)
                .all(|call| call.len != 0 && !call.more));
            assert!(a_output.pieces.is_empty() && b_output.pieces.is_empty());
        }
    }
}

#[test]
fn the_same_branching_framers_have_finite_feedback_with_the_callers_own_channel_origin() {
    let caller = Branching::new(Origin::Caller);
    let upstream = Branching::new(Origin::Upstream);
    let mut a = framing(&caller);
    let mut b = framing(&upstream);
    let now = Instant::now();
    let mut a_output = a.emit(CALLER_LINE, START, true, false, now).unwrap();
    let mut channel = Vec::new();
    for frame in std::mem::take(&mut a_output.pieces) {
        let mut b_output = b
            .emit(UPSTREAM_LINE, &frame.bytes, true, false, now)
            .unwrap();
        for feedback in std::mem::take(&mut b_output.pieces) {
            let mut originating_at_a = a
                .emit(CALLER_LINE, &feedback.bytes, true, false, now)
                .unwrap();
            channel.extend(std::mem::take(&mut originating_at_a.pieces));
        }
    }
    let expected = upstream.output.lock().unwrap().emitted[0].capacity + 1;
    let delivered: Vec<_> = channel
        .into_iter()
        .map(|piece| (piece.stream, piece.bytes))
        .collect();
    assert_eq!(
        delivered,
        vec![(CALLER_CHANNEL, CALLER_MESSAGE.to_vec()); expected]
    );
    assert!(caller.output.lock().unwrap().pieces.is_empty());
    assert!(upstream.output.lock().unwrap().pieces.is_empty());
}

#[test]
fn a_paused_turn_exposes_secure_wire_without_replaying_the_application_bytes() {
    const MESSAGE: &[u8] = b"streamed secure route";
    let mut r = rig(Knobs::default());
    r.first_check();
    r.pump(200);
    assert!(r.host.presented());
    let before = r.door.st.lock().unwrap().emitted.len();
    let mut turn = r.host.emit_turn(1, MESSAGE, true, false, r.now).unwrap();
    assert!(turn.next_batch().unwrap().is_some());
    let mut delivered = Vec::new();
    while let Some((to, datagram)) = turn.poll_send() {
        assert_eq!(to, r.far.addr);
        r.far.a.ingest(r.host_addr, &datagram, r.now);
    }
    while let Some(up) = r.far.a.poll_up() {
        if let Up::Plaintext(bytes) = up {
            delivered.push(bytes);
        }
    }
    assert_eq!(delivered, vec![MESSAGE.to_vec()]);
    assert!(turn.next_batch().unwrap().is_none());
    drop(turn);
    assert_eq!(
        &r.door.st.lock().unwrap().emitted[before..],
        &[MESSAGE.to_vec()]
    );
}
