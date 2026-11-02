// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Drive the actual host loops. A finite sentinel ends a defective implementation too, so a
//! missing resource bound fails an assertion instead of leaving an unbounded test worker.

use super::*;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const STREAM: u64 = 7;

#[derive(Clone, Copy, Debug)]
enum Records {
    Pieces(u16),
    Heads,
    Full,
    EmptyFull,
    Wire,
    OverlappingPieces,
    EmptyFlags,
}

impl Records {
    fn minimum_work(self) -> usize {
        match self {
            Self::Pieces(_) => PIECES_CAP * size_of::<Got>(),
            Self::Heads => HEADS_CAP * size_of::<Head>(),
            Self::Full => WIRE_CAP + size_of::<StreamFlow>(),
            Self::EmptyFull => size_of::<StreamFlow>(),
            Self::Wire => WIRE_CAP,
            Self::OverlappingPieces => PIECES_CAP * FRAME_CAP,
            Self::EmptyFlags => 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Driven {
    Ingest,
    Emit,
    Timer,
    Begin,
    Adopt,
    Refuse,
}

struct BurstDoor {
    inner: TestDoor,
    driven: Driven,
    records: Records,
    limit: usize,
    pending_at: Option<usize>,
    calls: AtomicUsize,
    resumed: AtomicBool,
}

impl BurstDoor {
    fn new(driven: Driven, records: Records, limit: usize, pending_at: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            inner: TestDoor::identity("t"),
            driven,
            records,
            limit,
            pending_at,
            calls: AtomicUsize::new(0),
            resumed: AtomicBool::new(false),
        })
    }

    fn begin(self: &Arc<Self>) -> Result<(Framing, Yielded), Refused> {
        Framing::begin_ticketed(
            self.clone(),
            SIDE_DIAL,
            "t",
            &Established::plain_for_test(),
            &[],
        )
    }

    fn drive(self: &Arc<Self>) -> Result<Yielded, Refused> {
        if matches!(self.driven, Driven::Adopt) {
            return Framing::adopt(
                self.clone(),
                SIDE_DIAL,
                b"input",
                &Established::plain_for_test(),
            )
            .map(|(_, output)| output);
        }
        let (mut framing, output) = self.begin()?;
        let output = match self.driven {
            Driven::Ingest => framing.ingest(b"input", false),
            Driven::Emit => framing.emit(STREAM, b"input", true, false),
            Driven::Timer => framing.timer(),
            Driven::Begin => Ok(output),
            Driven::Refuse => framing.refuse(Some(STREAM), b"refused", 0, false),
            Driven::Adopt => unreachable!(),
        }?;
        if framing.parked() {
            assert!(output.pieces.is_empty());
            assert!(output.heads.is_empty());
            return match framing.poll_parked(&mut noop_cx()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => panic!("the fixture pends only once"),
            };
        }
        Ok(output)
    }
}

#[allow(unsafe_code)]
impl FramerDoor for BurstDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: 7,
                generation: 1,
            },
            host: Arc::new(AuthHost::default()),
        }))
    }

    fn cross_on(&self, _: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        self.resumed.fetch_or(resume, Ordering::SeqCst);
        self.cross(call)
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let ready = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        let (sink, out, input_len) = match call {
            Call::Begin(input, out) => {
                out.framing = STREAM;
                if !matches!(self.driven, Driven::Begin) {
                    return ready;
                }
                (input.sink, out, 0)
            }
            Call::Adopt(input, out) => {
                out.framing = STREAM;
                assert!(matches!(self.driven, Driven::Adopt));
                (input.sink, out, input.leftover_len)
            }
            Call::Ingest(input, out) if matches!(self.driven, Driven::Ingest | Driven::Adopt) => {
                (input.sink, out, input.len)
            }
            Call::Emit(input, out) if matches!(self.driven, Driven::Emit) => {
                (input.sink, out, input.len)
            }
            Call::Timer(input, out) if matches!(self.driven, Driven::Timer | Driven::Begin) => {
                (input.sink, out, 0)
            }
            Call::Refuse(input, out) if matches!(self.driven, Driven::Refuse) => {
                (input.sink, out, input.len)
            }
            _ => return ready,
        };
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        if index != 0 {
            assert_eq!(input_len, 0, "recalls lend no new input");
        }
        if self.pending_at == Some(index) {
            return Crossed {
                outcome: Outcome::Pending,
                error: None,
            };
        }
        if index == self.limit {
            return ready;
        }
        out.yielded.flags = YIELD_MORE;
        match self.records {
            Records::Pieces(_) | Records::OverlappingPieces => {
                let flags = match self.records {
                    Records::Pieces(flags) => flags,
                    _ => PIECE_END_OF_FRAME,
                };
                let len = if matches!(self.records, Records::OverlappingPieces) {
                    // SAFETY: the host loans this entire frame buffer for this crossing.
                    unsafe {
                        std::ptr::write_bytes(sink.frame, b'x', sink.frame_cap);
                    }
                    out.yielded.frame_len = sink.frame_cap as u64;
                    sink.frame_cap as u64
                } else {
                    0
                };
                for index in 0..sink.pieces_cap {
                    // SAFETY: the checked loop index is inside the host's piece loan.
                    unsafe {
                        sink.pieces.add(index).write(FramePiece {
                            stream: STREAM,
                            flags,
                            len,
                            ..FramePiece::ZERO
                        });
                    }
                }
                out.yielded.pieces_len = sink.pieces_cap as u32;
            }
            Records::Heads => {
                for index in 0..sink.heads_cap {
                    // SAFETY: the checked loop index is inside the host's head loan.
                    unsafe {
                        sink.heads.add(index).write(HeadSlots {
                            stream: STREAM,
                            ..HeadSlots::default()
                        });
                    }
                }
                out.yielded.heads_len = sink.heads_cap as u32;
            }
            Records::Wire | Records::Full => {
                // SAFETY: the host loans this entire wire buffer for this crossing.
                unsafe {
                    std::ptr::write_bytes(sink.wire, b'w', sink.wire_cap);
                }
                out.yielded.wire_len = sink.wire_cap as u64;
                if matches!(self.records, Records::Full) {
                    out.yielded.flags |= YIELD_STREAM_FULL;
                }
            }
            Records::EmptyFlags => {
                out.yielded.flags |= YIELD_HAS_DEADLINE | YIELD_ENDED;
                out.yielded.next_deadline_ns = sink.now_monotonic_ns;
            }
            Records::EmptyFull => out.yielded.flags |= YIELD_STREAM_FULL,
        }
        ready
    }
}

#[test]
fn retained_empty_records_exhaust_the_existing_budget_in_every_host_recall_loop() {
    for driven in [
        Driven::Ingest,
        Driven::Emit,
        Driven::Timer,
        Driven::Begin,
        Driven::Adopt,
        Driven::Refuse,
    ] {
        for records in [Records::Pieces(PIECE_END_OF_FRAME), Records::Heads] {
            let limit = MORE_BYTES as usize / records.minimum_work() + 1;
            let door = BurstDoor::new(driven, records, limit, None);
            let error = door
                .drive()
                .expect_err("metadata-only MORE must exhaust the output budget");
            assert_eq!(error.outcome, Outcome::Fault, "{driven:?} {records:?}");
            assert!(door.calls.load(Ordering::SeqCst) <= limit);
        }
    }
}

#[test]
fn interim_and_writable_records_cannot_escape_the_output_budget() {
    for flags in [
        PIECE_FIELDS | PIECE_INTERIM | PIECE_END_OF_FRAME,
        PIECE_WRITABLE,
    ] {
        let records = Records::Pieces(flags);
        let record_size = if flags == PIECE_WRITABLE {
            size_of::<StreamFlow>()
        } else {
            size_of::<Got>()
        };
        let limit = MORE_BYTES as usize / (PIECES_CAP * record_size) + 1;
        let door = BurstDoor::new(Driven::Ingest, records, limit, None);
        assert_eq!(door.drive().unwrap_err().outcome, Outcome::Fault);
    }
}

#[test]
fn pending_recall_keeps_the_metadata_already_retained_by_its_operation() {
    for records in [Records::Pieces(PIECE_END_OF_FRAME), Records::Heads] {
        let limit = MORE_BYTES as usize / records.minimum_work() + 1;
        let door = BurstDoor::new(Driven::Ingest, records, limit + 1, Some(limit / 2));
        assert_eq!(door.drive().unwrap_err().outcome, Outcome::Fault);
        assert!(door.resumed.load(Ordering::SeqCst));
    }
}

#[test]
fn flow_records_and_independently_copied_overlapping_spans_are_charged() {
    for records in [Records::Full, Records::OverlappingPieces] {
        let limit = MORE_BYTES as usize / records.minimum_work() + 1;
        let door = BurstDoor::new(Driven::Emit, records, limit, None);
        assert_eq!(door.drive().unwrap_err().outcome, Outcome::Fault);
    }
}

#[test]
fn finite_empty_piece_head_and_wire_bursts_keep_their_order_and_contents() {
    let count = MORE_STALLS + 1;
    for records in [
        Records::Pieces(PIECE_END_OF_FRAME),
        Records::Heads,
        Records::Wire,
    ] {
        let door = BurstDoor::new(Driven::Ingest, records, count, None);
        let output = door.drive().unwrap();
        match records {
            Records::Pieces(_) => {
                assert_eq!(output.pieces.len(), count * PIECES_CAP);
                assert!(output.pieces.iter().all(|piece| piece.stream == STREAM
                    && piece.bytes.is_empty()
                    && piece.end_of_frame
                    && !piece.end));
            }
            Records::Heads => {
                assert_eq!(output.heads.len(), count * HEADS_CAP);
                assert!(output
                    .heads
                    .iter()
                    .all(|head| head.stream == STREAM && head.reason.is_none()));
            }
            Records::Wire => assert_eq!(output.wire, vec![b'w'; count * WIRE_CAP]),
            _ => unreachable!(),
        }
        assert_eq!(door.calls.load(Ordering::SeqCst), count + 1);
    }
}

#[test]
fn deadline_and_end_flags_do_not_turn_empty_more_into_progress() {
    let door = BurstDoor::new(Driven::Timer, Records::EmptyFlags, MORE_STALLS + 1, None);
    assert_eq!(door.drive().unwrap_err().outcome, Outcome::Fault);
    assert_eq!(door.calls.load(Ordering::SeqCst), MORE_STALLS);
}

#[test]
fn a_finite_burst_of_empty_stream_flow_records_remains_progress() {
    let count = MORE_STALLS + 1;
    let door = BurstDoor::new(Driven::Emit, Records::EmptyFull, count, None);
    let output = door.drive().unwrap();
    assert_eq!(output.flow, vec![StreamFlow::Full(STREAM); count]);
    assert!(output.pieces.is_empty());
    assert!(output.wire.is_empty());
}
