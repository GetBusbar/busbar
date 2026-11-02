// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Inspect only initialized wire bytes through the allocator's live deallocation pointer.

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

const WIRE: &[u8] = b"authorization: Bearer retained-framer-credential\r\n";
const BODY: &[u8] = b"application body stays unchanged";
const STREAMS: [u64; 2] = [7, 9];

#[derive(Clone, Copy)]
enum Mode {
    InvalidFrame,
    InvalidPiece,
    InvalidHead,
    Growth,
    Pending,
    Unwind,
}

struct WireDoor {
    inner: TestDoor,
    mode: Mode,
    timer: bool,
    calls: Mutex<HashMap<u64, usize>>,
    tickets: AtomicU32,
    cancels: AtomicUsize,
    resumes: AtomicUsize,
}

impl WireDoor {
    fn new(mode: Mode, timer: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: TestDoor::identity("bytes"),
            mode,
            timer,
            calls: Mutex::default(),
            tickets: AtomicU32::new(1),
            cancels: AtomicUsize::new(0),
            resumes: AtomicUsize::new(0),
        })
    }

    fn begin(self: &Arc<Self>) -> Framing {
        Framing::begin_ticketed(
            self.clone(),
            SIDE_DIAL,
            "t",
            &Established::plain_for_test(),
            &[],
        )
        .unwrap()
        .0
    }

    #[allow(unsafe_code)]
    fn answer(&self, stream: u64, sink: FramerSink, out: &mut FramerOut) -> Crossed {
        let index = {
            let mut calls = self.calls.lock().unwrap();
            let next = calls.entry(stream).or_default();
            let index = *next;
            *next += 1;
            index
        };
        if matches!(self.mode, Mode::Pending) && index == 1 {
            return Crossed {
                outcome: Outcome::Pending,
                error: None,
            };
        }
        if matches!(self.mode, Mode::Unwind) && index == 1 {
            panic!("fixture crossing unwound after retaining wire");
        }
        assert!(WIRE.len() <= sink.wire_cap);
        // SAFETY: the host loans this checked wire prefix through the current crossing.
        unsafe {
            std::ptr::copy_nonoverlapping(WIRE.as_ptr(), sink.wire, WIRE.len());
        }
        out.yielded.wire_len = WIRE.len() as u64;
        match self.mode {
            Mode::InvalidFrame => out.yielded.frame_len = u64::MAX,
            Mode::InvalidPiece => {
                assert!(sink.pieces_cap > 0);
                // SAFETY: the host loans at least one initialized piece slot. Its deliberately
                // invalid span is metadata only; the host must refuse it without reading bytes.
                unsafe {
                    sink.pieces.write(FramePiece {
                        stream,
                        len: 1,
                        ..FramePiece::ZERO
                    });
                }
                out.yielded.pieces_len = 1;
            }
            Mode::InvalidHead => {
                assert!(sink.heads_cap > 0);
                // SAFETY: the host loans at least one head slot, whose invalid span is refused.
                unsafe {
                    sink.heads.write(HeadSlots {
                        stream,
                        reason: FrameSpan { offset: 0, len: 1 },
                        ..HeadSlots::default()
                    });
                }
                out.yielded.heads_len = 1;
            }
            Mode::Growth | Mode::Pending | Mode::Unwind => {
                if index == 1 {
                    // SAFETY: initialize the full host wire loan, forcing actual MORE growth.
                    unsafe {
                        std::ptr::write_bytes(sink.wire, b'g', sink.wire_cap);
                    }
                    out.yielded.wire_len = sink.wire_cap as u64;
                }
                if index < 2 {
                    out.yielded.flags = YIELD_MORE;
                } else {
                    assert!(BODY.len() <= sink.frame_cap && sink.pieces_cap > 0);
                    // SAFETY: both checked loans contain these initialized application bytes
                    // and the single piece describing them.
                    unsafe {
                        std::ptr::copy_nonoverlapping(BODY.as_ptr(), sink.frame, BODY.len());
                        sink.pieces.write(FramePiece {
                            stream,
                            len: BODY.len() as u64,
                            flags: PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                    out.yielded.frame_len = BODY.len() as u64;
                    out.yielded.pieces_len = 1;
                }
            }
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

impl FramerDoor for WireDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: self.tickets.fetch_add(1, Ordering::SeqCst),
                generation: 1,
            },
            host: Arc::new(AuthHost::default()),
        }))
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Emit(input, out) => self.answer(input.stream, input.sink, out),
            Call::Timer(input, out) if self.timer => self.answer(0, input.sink, out),
            other => self.inner.cross(other),
        }
    }
    fn cross_on(&self, _: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        if resume {
            self.resumes.fetch_add(1, Ordering::SeqCst);
        }
        self.cross(call)
    }
    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        _: bool,
        call: crate::carrier::Carry<'_>,
    ) -> Crossed {
        let crate::carrier::Carry::Cancel(input, _) = call else {
            panic!("expected cancellation");
        };
        assert_eq!(input.ticket, side.ticket());
        self.cancels.fetch_add(1, Ordering::SeqCst);
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

fn all_retired_wiped(observed: &[Option<bool>]) {
    assert!(!observed.is_empty(), "the actual wire owners were observed");
    assert!(
        observed.iter().all(|wiped| *wiped == Some(true)),
        "wire retirement: {observed:?}"
    );
}

#[test]
fn invalid_frame_piece_or_head_after_wire_copy_retires_the_copy_wiped() {
    for mode in [Mode::InvalidFrame, Mode::InvalidPiece, Mode::InvalidHead] {
        for timer in [false, true] {
            let door = WireDoor::new(mode, timer);
            let (_, observed) = crate::support::observe_yielded_wires(|| {
                let mut framing = door.begin();
                let error = if timer {
                    framing.timer()
                } else {
                    framing.emit(STREAMS[0], BODY, true, false)
                }
                .unwrap_err();
                assert_eq!(error.outcome, Outcome::Fault);
            });
            all_retired_wiped(&observed);
        }
    }
}

#[test]
fn more_growth_and_final_wire_drop_wipe_every_retired_allocation_without_changing_body() {
    for timer in [false, true] {
        let door = WireDoor::new(Mode::Growth, timer);
        let (_, observed) = crate::support::observe_yielded_wires(|| {
            let mut framing = door.begin();
            let output = if timer {
                framing.timer()
            } else {
                framing.emit(STREAMS[0], BODY, true, false)
            }
            .unwrap();
            let mut expected = WIRE.to_vec();
            expected.extend(vec![b'g'; WIRE_CAP]);
            expected.extend_from_slice(WIRE);
            assert_eq!(output.wire, expected);
            assert_eq!(output.pieces.len(), 1);
            assert_eq!(output.pieces[0].bytes, BODY);
            assert!(output.pieces[0].end_of_frame);
        });
        all_retired_wiped(&observed);
        assert!(observed.len() > 1, "actual MORE reallocation was observed");
    }
}

#[test]
fn cancelling_or_dropping_a_parked_recall_wipes_its_previously_retained_wire() {
    for explicit in [false, true] {
        let door = WireDoor::new(Mode::Pending, false);
        let (_, observed) = crate::support::observe_yielded_wires(|| {
            let mut framing = door.begin();
            assert_eq!(
                framing.emit(STREAMS[0], BODY, true, false).unwrap(),
                Yielded::default()
            );
            assert!(framing.parked());
            if explicit {
                framing.cancel_parked();
                assert!(!framing.parked());
            }
        });
        all_retired_wiped(&observed);
        assert_eq!(door.cancels.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn resumed_operations_merge_in_order_and_wipe_source_and_grown_destination_wire() {
    let door = WireDoor::new(Mode::Pending, false);
    let (_, observed) = crate::support::observe_yielded_wires(|| {
        let mut framing = door.begin();
        for stream in STREAMS {
            framing.emit(stream, BODY, true, false).unwrap();
        }
        let output = match framing.poll_parked(&mut noop_cx()) {
            std::task::Poll::Ready(Ok(output)) => output,
            other => panic!("both parked operations resume: {other:?}"),
        };
        assert_eq!(output.wire, WIRE.repeat(STREAMS.len() * 2));
        assert_eq!(
            output
                .pieces
                .iter()
                .map(|piece| piece.stream)
                .collect::<Vec<_>>(),
            STREAMS
        );
        assert!(output.pieces.iter().all(|piece| piece.bytes == BODY));
    });
    all_retired_wiped(&observed);
    assert!(
        observed.len() > STREAMS.len(),
        "merge sources and destination allocations were observed"
    );
    assert_eq!(door.resumes.load(Ordering::SeqCst), STREAMS.len());
}

#[test]
fn unwinding_a_later_crossing_wipes_wire_retained_by_earlier_more_answers() {
    let door = WireDoor::new(Mode::Unwind, false);
    let (_, observed) = crate::support::observe_yielded_wires(|| {
        let mut framing = door.begin();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            framing.emit(STREAMS[0], BODY, true, false)
        }));
        assert!(unwound.is_err());
    });
    all_retired_wiped(&observed);
}
