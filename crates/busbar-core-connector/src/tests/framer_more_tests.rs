// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Drive the actual host loops. A finite sentinel ends a defective implementation too, so a

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
    /// The crossing in flight is a resume (stated by `cross_on`): it re-lends per-op metadata on
    /// purpose, so the re-call guard skips it.
    resuming: AtomicBool,
}

/// A re-call's `*In` with the fields a re-call is ALLOWED to carry reset by `allow`, beside the
/// blank one: a YIELD_MORE re-call CARRIES NO NEW BYTES and no per-op metadata, so the two must
/// read the same. A field added later is caught here unless it is added to an allowlist.
fn masked<T>(input: &T, allow: impl FnOnce(&mut T, &T)) -> (String, String)
where
    T: busbar_contract::abi::sdk::door::AbiIn + Copy + std::fmt::Debug,
{
    let blank: T = blank_in();
    let mut masked = *input;
    allow(&mut masked, &blank);
    (format!("{masked:?}"), format!("{blank:?}"))
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
            resuming: AtomicBool::new(false),
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
        self.resuming.store(resume, Ordering::SeqCst);
        self.cross(call)
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let ready = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        let resuming = self.resuming.swap(false, Ordering::SeqCst);
        // The allowlist per re-call: exactly the fields every crossing stamps (`cross_ticketed`'s
        // Ingest and Emit arms, `more_on`'s Refuse and Timer re-calls). Begin and Adopt are never
        // re-called as themselves (they continue as Timer and Ingest).
        let (sink, out, input_len, recall) = match call {
            Call::Begin(input, out) => {
                out.framing = STREAM;
                if !matches!(self.driven, Driven::Begin) {
                    return ready;
                }
                (input.sink, out, 0, None)
            }
            Call::Adopt(input, out) => {
                out.framing = STREAM;
                assert!(matches!(self.driven, Driven::Adopt));
                (input.sink, out, input.leftover_len, None)
            }
            Call::Ingest(input, out) if matches!(self.driven, Driven::Ingest | Driven::Adopt) => {
                let recall = masked(&*input, |m, b| {
                    m.framing = b.framing;
                    m.sink = b.sink;
                });
                (input.sink, out, input.len, Some(recall))
            }
            Call::Emit(input, out) if matches!(self.driven, Driven::Emit) => {
                let recall = masked(&*input, |m, b| {
                    m.framing = b.framing;
                    m.stream = b.stream;
                    m.sink = b.sink;
                });
                (input.sink, out, input.len, Some(recall))
            }
            Call::Timer(input, out) if matches!(self.driven, Driven::Timer | Driven::Begin) => {
                let recall = masked(&*input, |m, b| {
                    m.framing = b.framing;
                    m.sink = b.sink;
                });
                (input.sink, out, 0, Some(recall))
            }
            Call::Refuse(input, out) if matches!(self.driven, Driven::Refuse) => {
                let recall = masked(&*input, |m, b| {
                    m.framing = b.framing;
                    m.stream = b.stream;
                    m.has_stream = b.has_stream;
                    m.status = b.status;
                    m.head_sent = b.head_sent;
                    m.sink = b.sink;
                });
                (input.sink, out, input.len, Some(recall))
            }
            _ => return ready,
        };
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        if index != 0 {
            assert_eq!(input_len, 0, "recalls lend no new input");
            if !resuming {
                let (masked, blank) = recall.expect("only a re-callable op is re-called");
                assert_eq!(
                    masked, blank,
                    "{:?}: a YIELD_MORE re-call lends nothing beyond its allowlist",
                    self.driven
                );
            }
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

/// What one `emit` crossing lent the framer: its byte count, its end mark, its extensions blob
/// length and whether it stated the opening body's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EmitLent {
    len: usize,
    end: u32,
    extensions: usize,
    body_len_known: u32,
}

/// A dial framer whose first `emit` fills the host's whole wire loan and owes more: the shape of an
/// opening larger than [`WIRE_CAP`].
struct OverflowingEmitDoor {
    inner: TestDoor,
    lent: std::sync::Mutex<Vec<EmitLent>>,
}

#[allow(unsafe_code)]
impl FramerDoor for OverflowingEmitDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let ready = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        match call {
            Call::Begin(_, out) => out.framing = STREAM,
            Call::Emit(input, out) => {
                let mut lent = self.lent.lock().unwrap();
                lent.push(EmitLent {
                    len: input.len,
                    end: input.end_of_frame,
                    extensions: input.head.extensions.len,
                    body_len_known: input.body_len_known,
                });
                if lent.len() == 1 {
                    let sink = input.sink;
                    // SAFETY: the host loans this entire wire buffer for this crossing.
                    unsafe { std::ptr::write_bytes(sink.wire, b'w', sink.wire_cap) };
                    out.yielded.wire_len = sink.wire_cap as u64;
                    out.yielded.flags = YIELD_MORE;
                }
            }
            _ => {}
        }
        ready
    }
}

#[test]
fn an_opening_larger_than_the_wire_loan_recalls_without_its_opening_metadata() {
    let door = Arc::new(OverflowingEmitDoor {
        inner: TestDoor::identity("t"),
        lent: std::sync::Mutex::new(Vec::new()),
    });
    let (mut framing, _) =
        Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    let sensitive = SensitiveFields::new(vec!["authorization".into()]).unwrap();
    let opening = vec![b'o'; WIRE_CAP + 1];
    let body_len = (WIRE_CAP + 1) as u64 - 64;
    framing
        .emit_opening_sensitive(STREAM, &opening, true, false, Some(body_len), &sensitive)
        .unwrap();
    let lent = door.lent.lock().unwrap().clone();
    assert_eq!(lent.len(), 2, "one fresh emit, one YIELD_MORE re-call");
    assert_eq!(lent[0].len, opening.len());
    assert_ne!(
        lent[0].extensions, 0,
        "the fresh call carries the classification"
    );
    assert_eq!(
        lent[0].body_len_known, 1,
        "the fresh call states the body length"
    );
    assert_eq!(
        lent[1],
        EmitLent {
            len: 0,
            end: 0,
            extensions: 0,
            body_len_known: 0,
        },
        "a re-call carries nothing the first call already lent (transport ABI: recalls lend no new input)"
    );
}

/// Records the time each `ingest` crossing states. An ingest that lends bytes asks for one
/// re-call, so one ingest operation crosses twice.
struct Stated {
    inner: TestDoor,
    seen: std::sync::Mutex<Vec<(u64, u64)>>,
}

impl FramerDoor for Stated {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(_, out) => out.framing = STREAM,
            Call::Ingest(input, out) => {
                self.seen
                    .lock()
                    .unwrap()
                    .push((input.sink.now_monotonic_ns, input.sink.now_unix_ns));
                if input.len != 0 {
                    out.yielded.flags = YIELD_MORE;
                }
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

/// One framing operation takes one clock reading: its first crossing and its `YIELD_MORE` re-call
/// state the same monotonic and wall time, and a later operation states a later one.
#[test]
fn every_crossing_of_one_operation_states_one_reading_and_a_later_operation_a_later_one() {
    let door = Arc::new(Stated {
        inner: TestDoor::identity("t"),
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let (mut framing, _) =
        Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    framing.ingest(b"first", false).expect("the first ingest");
    std::thread::sleep(std::time::Duration::from_millis(2));
    framing.ingest(b"second", false).expect("the second ingest");
    let seen = door.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4, "each ingest crosses twice: {seen:?}");
    assert_eq!(seen[0], seen[1], "one operation, one reading");
    assert_eq!(seen[2], seen[3], "one operation, one reading");
    assert!(
        seen[2].0 > seen[0].0,
        "a later operation states a later monotonic time"
    );
    assert!(seen[0].0 != 0 && seen[0].1 != 0, "both clocks are stated");
}
