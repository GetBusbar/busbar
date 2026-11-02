// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host side of a framer: a full sink is re-called with no new bytes until every byte is out,

use std::sync::Arc;

use busbar_contract::abi::transport::{SIDE_ACCEPT, SIDE_DIAL};

use super::*;
use crate::support::{Knobs, TestDoor};

struct FailedQueryEncode {
    inner: TestDoor,
    mode: EncodeRefusal,
}

#[derive(Debug, Clone, Copy)]
enum EncodeRefusal {
    InvalidSpan,
    More,
    Failed,
}

#[allow(unsafe_code)]
impl FramerDoor for FailedQueryEncode {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Encode(input, output) => {
                let target = input.target;
                assert!(target.len <= input.sink.wire_cap);
                // SAFETY: encode's target and output sink are host loans valid for this call;
                // the checked capacity contains every initialized target byte.
                unsafe {
                    std::ptr::copy_nonoverlapping(target.ptr, input.sink.wire, target.len);
                }
                crate::support::watch_scratch(input.sink.wire, target.len);
                output.yielded.wire_len = target.len as u64;
                if matches!(self.mode, EncodeRefusal::InvalidSpan) {
                    output.yielded.frame_len = u64::MAX;
                }
                if matches!(self.mode, EncodeRefusal::More) {
                    output.yielded.flags = busbar_contract::abi::transport::YIELD_MORE;
                }
                Crossed {
                    outcome: if matches!(self.mode, EncodeRefusal::Failed) {
                        Outcome::Failed
                    } else {
                        Outcome::Ready
                    },
                    error: None,
                }
            }
            other => self.inner.cross(other),
        }
    }
}

#[test]
fn refused_query_encodes_wipe_scratch_and_any_partial_copied_output() {
    const TARGET: &[u8] = b"/path?credential=unique-private-value";
    for mode in [
        EncodeRefusal::InvalidSpan,
        EncodeRefusal::More,
        EncodeRefusal::Failed,
    ] {
        let door = FailedQueryEncode {
            inner: TestDoor::identity("bytes"),
            mode,
        };
        let (answer, scratch, partial) = crate::support::observe_wipe(std::ptr::null(), 0, || {
            encode_head(&door, b"GET", TARGET, &[], &[])
        });
        assert!(answer.is_err());
        assert_eq!(scratch, Some(true), "scratch mode={mode:?}");
        assert_eq!(
            partial,
            (!matches!(mode, EncodeRefusal::Failed)).then_some(true),
            "partial mode={mode:?}"
        );
    }
}

#[path = "framer_loan_tests.rs"]
mod loan_tests;

#[path = "framer_more_tests.rs"]
mod more_tests;

#[path = "framer_wire_tests.rs"]
mod wire_tests;

#[test]
fn sdk_sink_keeps_deferred_final_reason_with_its_first_piece_after_an_interim() {
    use std::collections::VecDeque;

    use busbar_contract::abi::sdk::transport::sink::{HeadWords, Owed, Piece};
    use busbar_contract::abi::sdk::HostBuf;
    use busbar_test_kit::test_support::sink;

    struct OwedHeads(VecDeque<Piece<Vec<u8>>>);
    impl Owed<Vec<u8>> for OwedHeads {
        fn wire_into(&mut self, _: &mut HostBuf<'_, u8>) {}
        fn wire_pending(&self) -> bool {
            false
        }
        fn pieces(&mut self) -> &mut VecDeque<Piece<Vec<u8>>> {
            &mut self.0
        }
        fn next_deadline(&self) -> Option<u64> {
            None
        }
        fn ended(&self) -> bool {
            false
        }
        fn rest(bytes: &mut Vec<u8>, at: usize) {
            bytes.drain(..at);
        }
    }
    let mut owed = OwedHeads(VecDeque::from([
        Piece {
            status: Some(103),
            head: Some(HeadWords::reason(b"Hint".to_vec())),
            ..Piece::fields(7, b"x-hint: yes\r\n".to_vec())
        },
        Piece {
            status: Some(200),
            head: Some(HeadWords::reason(b"OK".to_vec())),
            ..Piece::fields(7, b"long-name: v\r\n".to_vec())
        },
    ]));
    let mut buffers = Buffers::new(1, 24, 4);
    let mut yielded = Yielded::default();
    for call in 0..2 {
        let out = sink::fill(
            &mut owed,
            &mut buffers.wire,
            &mut buffers.frame,
            &mut buffers.pieces,
            &mut buffers.heads,
            |code| u8::try_from(code / 100).unwrap_or(0),
            |_| 0,
        );

        for piece in &mut buffers.pieces[..out.yielded.pieces_len as usize] {
            if piece.code == 103 {
                piece.flags |= PIECE_INTERIM;
            }
        }
        assert_eq!(out.yielded.pieces_len, 1);
        assert_eq!(out.yielded.heads_len, 1);
        assert_eq!(buffers.take(&out, &mut yielded).unwrap(), call == 1);
        if call == 0 {
            assert!(yielded.heads.is_empty());
            assert!(yielded.pieces.is_empty());
            assert_eq!(yielded.interim.len(), 1);
            assert_eq!(
                yielded.interim[0].reason.as_deref(),
                Some(b"Hint".as_slice())
            );
        }
    }
    assert!(owed.0.is_empty());
    assert_eq!(yielded.interim.len(), 1);
    assert_eq!(yielded.pieces.len(), 1);
    assert_eq!(yielded.pieces[0].status_code, Some(200));
    assert_eq!(yielded.pieces[0].bytes, b"long-name: v\r\n");
    assert_eq!(yielded.pieces[0].reason.as_deref(), Some(b"OK".as_slice()));
    assert_eq!(yielded.heads.len(), 1);
    assert_eq!(yielded.heads[0].reason.as_deref(), Some(b"OK".as_slice()));
}

#[test]
fn a_full_sink_is_re_called_until_every_byte_is_out() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) =
        Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    f.bufs = Buffers::new(7, 5, 1);
    let sent: Vec<u8> = (0..200).collect();
    let y = f.emit(1, &sent, true, false).unwrap();
    assert_eq!(y.wire, sent);
    let y = f.ingest(&sent, true).unwrap();
    let got: Vec<u8> = y.pieces.iter().flat_map(|p| p.bytes.clone()).collect();
    assert_eq!(got, sent);
    assert!(y.pieces.last().unwrap().end_of_frame);
    assert!(y.ended);
    assert!(door.count("ingest") > 1, "re-called while it owed more");
}

/// WS-DIAL: a dialled framing's `begin` is handed the dial's opening head fields
#[test]
fn a_dial_hands_its_opening_head_fields_to_begin() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let opening = vec![
        ("authorization".to_string(), b"Bearer k".to_vec()),
        ("x-mode".to_string(), b"realtime".to_vec()),
    ];
    let _ = Framing::begin_with(
        door.clone(),
        SIDE_DIAL,
        "t",
        &Established::plain_for_test(),
        &opening,
    )
    .unwrap();
    let _ = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    let begun = door.begun_fields.lock().unwrap();
    assert_eq!(
        *begun,
        vec![
            vec![
                (b"authorization".to_vec(), b"Bearer k".to_vec()),
                (b"x-mode".to_vec(), b"realtime".to_vec()),
            ],
            Vec::new(),
        ]
    );
}

/// A piece the framer states as text (`PIECE_TEXT`) is read up as text; one it does not is binary.
#[test]
fn a_text_piece_is_read_as_text() {
    for text in [true, false] {
        let door = Arc::new(TestDoor::new(
            "msg",
            &["msg"],
            &[],
            Knobs {
                text,
                ..Knobs::default()
            },
        ));
        let (mut f, _) =
            Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
        let y = f.ingest(b"{}", false).unwrap();
        assert_eq!(y.pieces.len(), 1);
        assert_eq!(y.pieces[0].text, text, "stated text={text}");
    }
}

#[test]
fn a_refusals_neutral_status_reaches_the_framer_on_every_re_call() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) =
        Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    f.bufs = Buffers::new(7, 5, 1);
    let sent: Vec<u8> = (0..200).collect();
    let y = f.refuse(Some(1), &sent, 401, false).unwrap();
    assert_eq!(y.wire, sent);
    let statuses = door.refused_statuses.lock().unwrap().clone();
    assert!(statuses.len() > 1, "re-called while it owed more");
    assert!(statuses.iter().all(|s| *s == 401), "{statuses:?}");
}

#[test]
fn a_stated_deadline_is_carried() {
    let door = Arc::new(TestDoor::new(
        "bytes",
        &["bytes"],
        &[],
        Knobs {
            silence: Some(std::time::Duration::from_secs(1)),
            ..Knobs::default()
        },
    ));
    let (_, y) = Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    let at = y.deadline_ns.expect("a deadline");
    assert!(at > now_ns());
}

#[test]
fn locate_and_encode_answer() {
    let door = TestDoor::new(
        "sec",
        &["sec"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            ..Knobs::default()
        },
    );
    let l = locate(&door, "127.0.0.1:443").unwrap();
    assert_eq!(l.authority, "127.0.0.1:443");
    assert_eq!(l.name.as_deref(), Some("localhost"));
    assert!(l.secure);
    assert_eq!(encode(&door, &[], b"body").unwrap(), b"body");
}

/// RED: a framer that offers protocols for a secured target is located: the host gives its offer a
#[test]
fn a_framer_offering_protocols_for_a_secured_target_is_located() {
    let door = TestDoor::new(
        "sec",
        &["sec"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            offer: Some(b"\x02h2\x08http/1.1"),
            ..Knobs::default()
        },
    );
    let l = locate(&door, "127.0.0.1:443").expect("located");
    assert_eq!(l.authority, "127.0.0.1:443");
    assert!(l.secure);
}

/// RED: an ACCEPTED framing's head slots come out typed (method, target, an absent authority),
#[test]
fn an_accepted_framing_yields_its_request_head_typed() {
    let knobs = Knobs {
        head: true,
        ..Knobs::default()
    };
    let door = Arc::new(TestDoor::new("bytes", &["bytes"], &[], knobs));
    let (_, y) = Framing::begin(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &Established::plain_for_test(),
    )
    .unwrap();
    assert_eq!(
        y.heads,
        [Head {
            stream: 1,
            method: Some(b"GET".to_vec()),
            target: Some(b"/v1".to_vec()),
            ..Head::default()
        }]
    );
    let dialled = Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test());
    assert!(
        dialled.is_err(),
        "a dialled framing carries no request slots"
    );
}

/// RED: the host reassembles a stream's field block and never takes PIECE_CONTINUED on the framer's
#[test]
fn a_continued_field_piece_is_judged_by_the_host_not_the_framer() {
    let mut l = FieldLines::default();
    assert_eq!(l.piece(1, false, false, b"x: y\r\n"), Ok(()));
    assert!(
        l.piece(1, true, true, b":path: /admin\r\n").is_err(),
        "smuggle"
    );
    let mut l = FieldLines::default();
    assert!(l.piece(1, true, true, b"rest\r\n").is_err(), "orphan");
    let mut l = FieldLines::default();
    assert_eq!(l.piece(1, false, false, b"x-lo"), Ok(()));
    assert!(
        l.piece(1, true, true, b"ng: v\r\n").is_err(),
        "inside a name"
    );
    let mut l = FieldLines::default();
    assert!(
        l.piece(1, false, true, b":path: /\r\n").is_err(),
        "pseudo-field"
    );
    assert!(
        l.piece(2, false, true, b"x: 1\r").is_err(),
        "ends inside a line"
    );
}

/// A long value split across pieces reassembles byte-identically, and the stream's next block
#[test]
fn a_long_value_split_across_pieces_reassembles_byte_identically() {
    let block = b"x-long: abcdefghij\r\nx-b: 2\r\n";
    let mut l = FieldLines::default();
    let parts: [(&[u8], bool, bool); 4] = [
        (&block[..10], false, false),
        (&block[10..18], true, false),
        (&block[18..19], true, false),
        (&block[19..], true, true),
    ];
    let mut joined = Vec::new();
    for (bytes, continued, end) in parts {
        assert_eq!(l.piece(7, continued, end, bytes), Ok(()));
        joined.extend_from_slice(bytes);
    }
    assert_eq!(joined, block);
    assert_eq!(
        l.piece(7, false, true, b""),
        Ok(()),
        "an empty block after it"
    );
}

/// RED: a payload piece inside a stream's open field block is refused; a failed stream drops its
#[test]
fn a_payload_piece_inside_an_open_block_is_refused_and_a_failure_drops_the_block() {
    let fields = |continued, end| FieldPiece::Fields { continued, end };
    let mut l = FieldLines::default();
    assert_eq!(l.take(3, fields(false, false), b"x: y\r\n"), Ok(()));
    assert!(
        l.take(3, FieldPiece::Payload, b"body").is_err(),
        "payload inside"
    );
    assert_eq!(
        l.take(4, FieldPiece::Payload, b"body"),
        Ok(()),
        "another stream"
    );
    assert_eq!(l.take(3, fields(false, false), b"x-lo"), Ok(()));
    assert_eq!(l.take(3, FieldPiece::Failed, b"reset"), Ok(()));
    assert!(l.open.is_empty(), "the failed stream's block is gone");
    assert_eq!(l.take(3, fields(false, true), b"a: b\r\n"), Ok(()));
    assert_eq!(l.take(3, FieldPiece::Payload, b"body"), Ok(()));
}

/// A framer that keeps answering that it owes more (`YIELD_MORE`) and writes nothing FAULTs its
#[test]
fn a_framer_that_owes_more_forever_and_writes_nothing_faults() {
    use std::sync::mpsc;
    use std::time::Duration;

    let door = Arc::new(TestDoor::new(
        "spin",
        &["spin"],
        &[],
        Knobs {
            spin: true,
            ..Knobs::default()
        },
    ));
    let (answer, answered) = mpsc::channel();
    std::thread::spawn(move || {
        let begun = Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test())
            .map(|_| ())
            .map_err(|r| r.outcome);
        let _ = answer.send(begun);
    });
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(5)),
        Ok(Err(busbar_contract::abi::mechanism::call::Outcome::Fault)),
        "the framing faults within its bound"
    );
}

use crate::support::{AuthHost, AuthTicket, PendingDoor};
use busbar_contract::abi::mechanism::ticket::Ticket;

/// Stream, byte length, flags, end-of-frame and resume observed at the actual emit crossing.
type EmitObservation = (u64, usize, u32, u32, bool);

struct TrailerDoor {
    inner: PendingDoor,
    seen: std::sync::Mutex<Vec<EmitObservation>>,
}

impl FramerDoor for TrailerDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        self.inner.framing_side()
    }
    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        resume: bool,
        call: crate::carrier::Carry<'_>,
    ) -> Crossed {
        self.inner.carry(side, resume, call)
    }
    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        if let Call::Emit(i, _) = &call {
            self.seen
                .lock()
                .unwrap()
                .push((i.stream, i.len, i.flags, i.end_of_frame, resume));
            if i.len == 0 && !resume {
                return self.inner.inner.cross(call);
            }
        }
        self.inner.cross_on(side, resume, call)
    }
}

#[test]
fn final_fields_keep_their_kind_and_custody_across_pending_and_drain() {
    use busbar_contract::abi::transport::EMIT_TRAILERS;

    let door = Arc::new(TrailerDoor {
        inner: PendingDoor::new(TestDoor::identity("bytes"), 1),
        seen: Default::default(),
    });
    let (mut framing, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    framing.bufs = Buffers::new(7, 5, 1);
    framing.bufs.side = SIDE_ACCEPT;
    let fields = b"final-status: 7\r\n";
    assert!(framing.emit_trailers(1, fields).unwrap().wire.is_empty());
    assert!(framing.holds(1));
    assert!(framing.emit(1, b"late", true, false).is_err());
    assert_eq!(framing.emit(3, b"ok", true, false).unwrap().wire, b"ok");
    assert!(framing.poll_parked(&mut noop_cx()).is_pending());
    door.inner.host.complete(9);
    let std::task::Poll::Ready(Ok(done)) = framing.poll_parked(&mut noop_cx()) else {
        panic!("the original trailer op resumes and drains");
    };
    assert_eq!(done.wire, fields);
    assert!(!framing.holds(1));
    let seen = door.seen.lock().unwrap();
    let same: Vec<_> = seen.iter().filter(|v| v.0 == 1).collect();
    assert_eq!(*same[0], (1, fields.len(), EMIT_TRAILERS, 1, false));
    assert!(
        same.len() > 2,
        "the small wire sink requires empty drain recalls"
    );
    assert!(same[1..].iter().all(|v| v.1 == 0 && v.2 == 0 && v.3 == 0));
}

/// A framer whose dial `begin` calls the auth service (handle seq 0) on its framing's ticket: it
struct AuthDoor {
    facts: DoorFacts,
    host: Arc<AuthHost>,
    begins: std::sync::atomic::AtomicUsize,
    resumes: std::sync::atomic::AtomicUsize,
}

impl FramerDoor for AuthDoor {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let outcome = match call {
            Call::Begin(..) => busbar_contract::abi::mechanism::call::Outcome::Refused,
            _ => busbar_contract::abi::mechanism::call::Outcome::Ready,
        };
        Crossed {
            outcome,
            error: None,
        }
    }

    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: 7,
                generation: 1,
            },
            host: Arc::clone(&self.host),
        }))
    }

    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        use busbar_contract::abi::mechanism::call::Outcome;
        use std::sync::atomic::Ordering;
        match call {
            Call::Begin(_, o) => {
                self.begins.fetch_add(1, Ordering::SeqCst);
                if resume {
                    self.resumes.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.host.new_op(side.ticket());
                }
                match self.host.call(side.ticket(), 0) {
                    None => Crossed {
                        outcome: Outcome::Pending,
                        error: None,
                    },
                    Some(_) => {
                        o.framing = 42;
                        Crossed {
                            outcome: Outcome::Ready,
                            error: None,
                        }
                    }
                }
            }
            other => self.cross(other),
        }
    }
}

/// A task waker that records it was woken.
#[derive(Default)]
struct Woken(std::sync::atomic::AtomicBool);

impl std::task::Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A ticketed begin whose auth pends resumes on the wake with one auth call.
#[test]
fn a_ticketed_begin_whose_auth_pends_resumes_on_the_wake_with_one_auth_call() {
    use std::sync::atomic::Ordering;
    use std::task::{Context, Poll, Waker};
    let door = Arc::new(AuthDoor {
        facts: DoorFacts {
            name: "framer".into(),
            claims: vec!["t"],
            role: busbar_contract::abi::transport::ROLE_FRAMER,
            composes_over: Vec::new(),
            ported: false,
            status_rows: Vec::new(),
            duplex: Vec::new(),
            datagram: false,
        },
        host: Arc::new(AuthHost::default()),
        begins: Default::default(),
        resumes: Default::default(),
    });
    let (mut f, y) = Framing::begin_ticketed(
        door.clone(),
        SIDE_DIAL,
        "t",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    assert!(f.parked(), "the begin waits on its auth call");
    assert_eq!(y, Yielded::default(), "a parked op yields nothing");
    assert!(
        f.ingest(b"x", false).is_err(),
        "no other op crosses a parked framing"
    );
    let woken = Arc::new(Woken::default());
    let waker = Waker::from(Arc::clone(&woken));
    let mut cx = Context::from_waker(&waker);
    assert!(
        f.poll_parked(&mut cx).is_pending(),
        "the auth is still not ready"
    );
    assert!(!woken.0.load(Ordering::SeqCst));
    door.host.complete(9);
    assert!(
        woken.0.load(Ordering::SeqCst),
        "the auth's answer wakes the ticket"
    );
    match f.poll_parked(&mut cx) {
        Poll::Ready(Ok(_)) => {}
        other => panic!("the resumed begin completes: {other:?}"),
    }
    assert!(!f.parked());
    assert_eq!(f.token, 42, "the framing the completed begin named");
    assert_eq!(
        door.host.real_calls.load(Ordering::SeqCst),
        1,
        "exactly one auth call across the not-ready"
    );
    assert_eq!(door.begins.load(Ordering::SeqCst), 3);
    assert_eq!(
        door.resumes.load(Ordering::SeqCst),
        2,
        "each re-drive is a resume"
    );
}

/// A noop task context.
fn noop_cx() -> std::task::Context<'static> {
    std::task::Context::from_waker(std::task::Waker::noop())
}

/// One stream pending auth parks only that stream and resumes with one auth call.
#[test]
fn one_stream_pending_auth_parks_only_that_stream_and_resumes_with_one_auth_call() {
    let door = Arc::new(PendingDoor::new(TestDoor::identity("bytes"), 1));
    let (mut f, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_DIAL,
        "t",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    let y = f.emit_opening(1, b"first ", true, false, Some(0)).unwrap();
    assert_eq!(
        y,
        Yielded::default(),
        "the first stream's head waits on its auth"
    );
    assert!(f.parked() && f.holds(1) && !f.holds(3) && !f.begin_parked());
    assert!(
        f.emit(1, b"more", true, false).is_err(),
        "its stream is held"
    );
    let y = f.emit_opening(3, b"second", true, false, Some(0)).unwrap();
    assert_eq!(
        y.wire, b"second",
        "the second stream's request goes out now"
    );
    let y = f.ingest(b"answer", false).unwrap();
    assert_eq!(
        y.pieces
            .iter()
            .flat_map(|p| p.bytes.clone())
            .collect::<Vec<_>>(),
        b"answer",
        "the far end's answer comes in while the first stream waits"
    );
    assert!(
        f.poll_parked(&mut noop_cx()).is_pending(),
        "the auth is not ready"
    );
    door.host.complete(9);
    match f.poll_parked(&mut noop_cx()) {
        std::task::Poll::Ready(Ok(y)) => assert_eq!(y.wire, b"first ", "the first goes out"),
        other => panic!("the resumed emit completes: {other:?}"),
    }
    assert!(!f.parked() && !f.holds(1));
    assert_eq!(
        door.host.calls(),
        1,
        "exactly one auth call across the not-ready"
    );
    let on = door.on.lock().unwrap().clone();
    let first: Vec<_> = on
        .iter()
        .filter(|(op, _, _)| *op == "emit")
        .map(|(_, t, resume)| (*t, *resume))
        .collect();
    assert_eq!(
        first.len(),
        4,
        "the first emit, the second, two resumes: {on:?}"
    );
    let (parked_on, _) = first[0];
    assert_ne!(
        parked_on, first[1].0,
        "the second stream crossed on another ticket"
    );
    assert!(
        first[2..]
            .iter()
            .all(|&(t, resume)| t == parked_on && resume),
        "each re-drive is a resume on the parked op's own ticket"
    );
    assert_eq!(
        door.emitted.lock().unwrap().as_slice(),
        &[(1, 0, 1), (3, 0, 1)],
        "each head emit states its opening body's length, known"
    );
}

/// A MULTIPLEXING ACCEPTING FRAMER double: each byte an `ingest` carries names the stream a
struct MuxDoor {
    facts: DoorFacts,
    yield_writable: bool,
    host: Arc<AuthHost>,
    next: std::sync::atomic::AtomicU32,
    held: std::sync::Mutex<HashMap<Ticket, Vec<u8>>>,
    /// The bytes every resumed ingest carried.
    resumed: std::sync::Mutex<Vec<usize>>,
}

impl MuxDoor {
    fn new() -> Self {
        Self {
            yield_writable: false,
            facts: DoorFacts {
                name: "mux".into(),
                claims: vec!["mux"],
                role: busbar_contract::abi::transport::ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: Vec::new(),
                datagram: false,
            },
            host: Arc::new(AuthHost::default()),
            next: std::sync::atomic::AtomicU32::new(1),
            held: std::sync::Mutex::new(HashMap::new()),
            resumed: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl FramerDoor for MuxDoor {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Begin(_, o) = call {
            o.framing = 5;
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }

    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                generation: 1,
            },
            host: Arc::clone(&self.host),
        }))
    }

    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        let (i, o) = match call {
            Call::Ingest(i, o) => (i, o),
            other => return self.cross(other),
        };
        let t = side.ticket();
        let pending = Crossed {
            outcome: Outcome::Pending,
            error: None,
        };
        let ready = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        if resume {
            self.resumed.lock().unwrap().push(i.len);
            if self.host.call(t, 0).is_none() {
                return pending;
            }
            let held = self.held.lock().unwrap().remove(&t).unwrap_or_default();
            if self.yield_writable {
                assert_eq!(held, b"1");
                crate::support::writable_on_lane(&i.sink, o, 1);
            } else {
                crate::support::pieces_on_lanes(&i.sink, o, &held);
            }
            return ready;
        }
        self.host.new_op(t);
        let bytes = crate::support::lent(i.bytes, i.len);
        if bytes.contains(&b'1') && self.host.call(t, 0).is_none() {
            self.held.lock().unwrap().insert(t, bytes);
            return pending;
        }
        crate::support::pieces_on_lanes(&i.sink, o, &bytes);
        ready
    }
}

/// A pending ingest holds only its stream and the next stream head is handed up first.
#[test]
fn a_pending_ingest_holds_only_its_stream_and_the_next_stream_head_is_handed_up_first() {
    let door = Arc::new(MuxDoor::new());
    let (mut f, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    let y = f.ingest(b"1", false).unwrap();
    assert!(
        y.pieces.is_empty() && f.parked(),
        "the first stream's auth pends"
    );
    assert!(!f.begin_parked(), "the framing itself is not held");
    let y = f.ingest(b"3", false).unwrap();
    assert_eq!(
        y.pieces.iter().map(|p| p.stream).collect::<Vec<_>>(),
        [3_u64],
        "the second stream's head is handed up while the first waits"
    );
    assert!(f.timer().is_ok(), "the framing's own ops keep crossing");
    assert!(f.poll_parked(&mut noop_cx()).is_pending());
    door.host.complete(1);
    match f.poll_parked(&mut noop_cx()) {
        std::task::Poll::Ready(Ok(y)) => assert_eq!(
            y.pieces.iter().map(|p| p.stream).collect::<Vec<_>>(),
            [1_u64],
            "the first stream's head, once its auth answered"
        ),
        other => panic!("the resumed ingest completes: {other:?}"),
    }
    assert!(!f.parked());
    assert_eq!(
        door.host.calls(),
        1,
        "exactly one auth call across the not-ready"
    );
    assert!(
        door.resumed.lock().unwrap().iter().all(|&n| n == 0),
        "a resumed ingest carries no new bytes"
    );
}

/// THE OPENING BODY'S LENGTH (`EmitIn::body_len`): stated on a dialled framing's head emit when
#[test]
fn a_dialled_head_emit_states_its_body_length_and_nothing_else_does() {
    let door = Arc::new(PendingDoor::new(TestDoor::identity("bytes"), 99));
    let (mut f, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_DIAL,
        "t",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    f.emit_opening(1, b"head", true, false, Some(4096)).unwrap();
    f.emit(1, b"body", true, false).unwrap();
    f.emit_opening(3, b"head", true, false, None).unwrap();
    let (mut accepted, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    accepted
        .emit_opening(1, b"answer", true, false, Some(10))
        .unwrap();
    assert_eq!(
        door.emitted.lock().unwrap().as_slice(),
        &[(1, 4096, 1), (1, 0, 0), (3, 0, 0), (1, 0, 0)],
        "known on the dialled head; streamed, plain and accepting emits state none"
    );
}

/// A binding with auth points is refused without a ticket.
#[test]
fn a_binding_with_auth_points_is_refused_ticket_less() {
    use busbar_contract::abi::host::service::AuthRef;
    use busbar_contract::abi::transport::POINT_HEAD;
    let dial = AuthBinding {
        points: POINT_HEAD,
        auth: AuthRef { id: 3, mac: 4 },
        line_points: 0,
    };
    let lines = AuthBinding {
        line_points: POINT_HEAD,
        ..AuthBinding::NONE
    };
    let refused = |r: Result<(Framing, Yielded), Refused>| match r {
        Err(e) => {
            assert_eq!(e.outcome, Outcome::Refused);
            assert_eq!(e.error, TICKET_LESS_AUTH, "the refusal names the rule");
        }
        Ok(_) => panic!("an auth-calling binding was begun ticket-less"),
    };
    let door = Arc::new(TestDoor::identity("bytes"));
    let est = Established::plain_for_test();
    refused(Framing::begin_ticketless(
        door.clone(),
        SIDE_DIAL,
        "t",
        &est,
        &[],
        &dial,
    ));
    refused(Framing::begin_ticketless(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &est,
        &[],
        &lines,
    ));

    refused(Framing::begin_bound(
        door.clone(),
        SIDE_DIAL,
        "t",
        &est,
        &[],
        &dial,
    ));
    assert_eq!(door.count("begin"), 0, "nothing crossed");
    match crate::framed_stream::FramedStream::open_bound(
        door.clone(),
        "bytes",
        "/s",
        &[],
        &lines,
        busbar_contract::abi::host::service::SCHEME_PLAIN,
    ) {
        Err(e) => assert_eq!(e.error, TICKET_LESS_AUTH),
        Ok(_) => panic!("a stream with auth lines was framed ticket-less"),
    }
    assert_eq!(door.count("begin"), 0, "nothing crossed");
    assert!(
        Framing::begin_ticketless(door.clone(), SIDE_DIAL, "t", &est, &[], &AuthBinding::NONE)
            .is_ok(),
        "a binding with no auth is framed ticket-less as before"
    );

    let ticketed = Arc::new(PendingDoor::new(TestDoor::identity("bytes"), 99));
    let (f, _) = Framing::begin_bound(ticketed.clone(), SIDE_DIAL, "t", &est, &[], &dial).unwrap();
    assert!(!f.parked());
    assert_eq!(
        ticketed.begun.lock().unwrap().as_slice(),
        &[(POINT_HEAD, AuthRef { id: 3, mac: 4 })]
    );
}

/// An encode that answers YIELD_MORE faults without sending truncated bytes.
#[test]
fn an_encode_answered_yield_more_faults_and_is_never_sent_truncated() {
    let door = TestDoor::new(
        "spin",
        &["spin"],
        &[],
        Knobs {
            spin: true,
            ..Knobs::default()
        },
    );
    let refused = encode(&door, &[], b"body").expect_err("a YIELD_MORE encode is refused");
    assert_eq!(
        refused.outcome,
        busbar_contract::abi::mechanism::call::Outcome::Fault
    );
    assert_eq!(
        encode(&TestDoor::identity("bytes"), &[], b"body").ok(),
        Some(b"body".to_vec()),
        "a whole answer is the message"
    );
}

/// An INTERIM head (a `1xx` the framer flags interim) is never the answer's head: the final head
#[test]
fn an_interim_head_is_never_handed_up_as_the_final_head() {
    let door = Arc::new(TestDoor::new(
        "messages",
        &["messages"],
        &[],
        Knobs {
            messages: Some(1),
            ..Knobs::default()
        },
    ));
    let (mut f, _) = Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    let y = f.ingest(b"ihx", false).unwrap();
    let heads: Vec<Option<u32>> = y
        .pieces
        .iter()
        .filter(|p| p.fields)
        .map(|p| p.status_code)
        .collect();
    assert_eq!(
        heads,
        vec![Some(200)],
        "only the final head is the head: {y:?}"
    );
    assert_eq!(y.pieces.len(), 2, "the head, then the message");
    let interim: Vec<Option<u32>> = y.interim.iter().map(|p| p.status_code).collect();
    assert_eq!(
        interim,
        vec![Some(103)],
        "the interim head is kept apart, not lost"
    );
}

/// A `PIECE_WRITABLE` piece is the framer telling the host a stream may be emitted on again, never
#[test]
fn a_writable_piece_is_never_handed_up_as_a_frame() {
    let door = Arc::new(TestDoor::new(
        "messages",
        &["messages"],
        &[],
        Knobs {
            messages: Some(1),
            ..Knobs::default()
        },
    ));
    let (mut f, _) = Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    let y = f.ingest(b"w", false).unwrap();
    assert!(y.pieces.is_empty(), "a writable piece is no frame: {y:?}");
    let y = f.ingest(b"xwz", false).unwrap();
    let got: Vec<Vec<u8>> = y.pieces.iter().map(|p| p.bytes.clone()).collect();
    assert_eq!(got, vec![b"x".to_vec(), b"z".to_vec()]);
}

/// A locate size answer past the host's bound is a fault never an allocation.
#[test]
fn a_locate_size_answer_past_the_hosts_bound_is_a_fault_never_an_allocation() {
    let needed = busbar_contract::abi::mechanism::check::MAX_BYTES;
    let door = TestDoor::new(
        "big",
        &["big"],
        &[],
        Knobs {
            authority_needed: Some(needed),
            ..Knobs::default()
        },
    );
    let answer = locate(&door, "127.0.0.1:443");
    let caps = door.locate_caps.lock().unwrap().clone();
    assert_eq!(
        caps.len(),
        1,
        "asked once, never again with the room the transport named: {caps:?}"
    );
    let refused = answer.expect_err("a size past the host's bound is refused");
    assert_eq!(
        refused.outcome,
        busbar_contract::abi::mechanism::call::Outcome::Fault,
        "{refused}"
    );
    assert!(refused.error.contains("locate"), "{refused}");
}

/// GREEN twin: a short `locate` within the host's bound is asked again with the room it named,
#[test]
fn a_short_locate_within_the_hosts_bound_is_asked_again_with_room() {
    let door = TestDoor::new(
        "roomy",
        &["roomy"],
        &[],
        Knobs {
            authority_needed: Some(300),
            ..Knobs::default()
        },
    );
    let l = locate(&door, "127.0.0.1:443").expect("located on the second ask");
    assert_eq!(l.authority, "127.0.0.1:443");
    let caps = door.locate_caps.lock().unwrap().clone();
    assert_eq!(caps.len(), 2, "{caps:?}");
    assert!(
        caps[1] >= 300,
        "the second ask has the room named: {caps:?}"
    );
}

struct LocatedCounts {
    inner: TestDoor,
    authority_written: u64,
    name_written: u64,
    has_name: bool,
}

impl FramerDoor for LocatedCounts {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Locate(_, out) => {
                out.authority_written = self.authority_written;
                out.name_written = self.name_written;
                out.has_name = u32::from(self.has_name);
                Crossed {
                    outcome: Outcome::Ready,
                    error: None,
                }
            }
            other => self.inner.cross(other),
        }
    }
}

#[test]
fn a_ready_locate_cannot_claim_text_outside_the_hosts_buffers() {
    for count in [257, u64::MAX] {
        for name in [false, true] {
            let door = LocatedCounts {
                inner: TestDoor::identity("bytes"),
                authority_written: if name { 0 } else { count },
                name_written: if name { count } else { 0 },
                has_name: name,
            };
            let fault = locate(&door, "127.0.0.1:443").expect_err("invalid written count");
            assert_eq!(fault.outcome, Outcome::Fault);
            assert!(fault
                .error
                .contains(if name { "name" } else { "authority" }));
            assert!(
                accept_offer(&door).is_err(),
                "accepting locate validates the same answer"
            );
        }
    }
    for count in [0, 256] {
        for has_name in [false, true] {
            let door = LocatedCounts {
                inner: TestDoor::identity("bytes"),
                authority_written: count,
                name_written: if has_name { count } else { 0 },
                has_name,
            };
            let located = locate(&door, "127.0.0.1:443").unwrap();
            assert_eq!(located.authority.len(), usize::try_from(count).unwrap());
            assert_eq!(
                located.name.as_ref().map(String::len),
                has_name.then_some(count as usize)
            );
            assert!(accept_offer(&door).unwrap().is_empty());
        }
    }
}

#[test]
fn an_adopted_framing_keeps_pending_emits_on_their_own_tickets() {
    let door = Arc::new(PendingDoor::new(TestDoor::identity("bytes"), 1));
    let (mut framing, _) = Framing::adopt(
        door.clone(),
        SIDE_ACCEPT,
        b"",
        &Established::plain_for_test(),
    )
    .expect("the upgrade is adopted");
    let first = framing
        .emit(1, b"first", true, false)
        .expect("the emit parks");
    assert!(
        first.wire.is_empty(),
        "the pending message is not emitted before its host answers"
    );
    assert!(
        framing.parked() && framing.holds(1),
        "an adopted framing retains its pending stream"
    );
    assert!(framing.poll_parked(&mut noop_cx()).is_pending());
    assert_eq!(
        framing.emit(3, b"second", true, false).unwrap().wire,
        b"second"
    );
    door.host.complete(9);
    let std::task::Poll::Ready(Ok(done)) = framing.poll_parked(&mut noop_cx()) else {
        panic!("the adopted framing resumes after the host answers");
    };
    assert_eq!(done.wire, b"first");
    assert!(!framing.parked());
    assert_eq!(
        door.host.calls(),
        1,
        "the host service runs once across resume"
    );
    let calls = door.on.lock().unwrap();
    let emits: Vec<_> = calls.iter().filter(|(op, _, _)| *op == "emit").collect();
    assert!(emits.len() >= 3);
    let held = emits[0].1;
    assert!(!emits[0].2);
    assert!(emits
        .iter()
        .filter(|(_, _, resume)| *resume)
        .all(|(_, ticket, _)| *ticket == held));
}

#[test]
fn a_pending_adoption_resumes_on_its_ticket_without_replaying_leftover_bytes() {
    let mut door = PendingDoor::new(TestDoor::identity("bytes"), 99);
    door.pend_adopt = true;
    let door = Arc::new(door);
    let (mut framing, first) = Framing::adopt(
        door.clone(),
        SIDE_ACCEPT,
        b"leftover",
        &Established::plain_for_test(),
    )
    .expect("the adoption parks");
    assert_eq!(first, Yielded::default());
    assert!(framing.begin_parked() && framing.holds(1) && framing.holds(3));
    assert!(framing.emit(3, b"too soon", true, false).is_err());
    assert!(framing.poll_parked(&mut noop_cx()).is_pending());
    door.host.complete(9);
    let std::task::Poll::Ready(Ok(done)) = framing.poll_parked(&mut noop_cx()) else {
        panic!("adoption resumes after its host answers");
    };
    assert_eq!(
        done.pieces
            .iter()
            .flat_map(|p| p.bytes.iter().copied())
            .collect::<Vec<_>>(),
        b"leftover"
    );
    assert!(!framing.begin_parked() && !framing.parked());
    assert_ne!(framing.token(), 0);
    assert_eq!(
        door.inner.count("adopt"),
        1,
        "the underlying adoption runs once"
    );
    assert_eq!(door.host.calls(), 1);
    let calls = door.on.lock().unwrap();
    let adopts: Vec<_> = calls.iter().filter(|(op, _, _)| *op == "adopt").collect();
    assert!(adopts.len() >= 3);
    let ticket = adopts[0].1;
    assert!(!adopts[0].2);
    assert!(adopts[1..]
        .iter()
        .all(|(_, t, resume)| *t == ticket && *resume));
}

#[test]
fn a_resumed_emit_preserves_its_stream_full_answer() {
    let door = Arc::new(PendingDoor::new(
        TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                full_at: Some(1),
                ..Knobs::default()
            },
        ),
        1,
    ));
    let (mut framing, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    assert_eq!(
        framing.emit(1, b"held", true, false).unwrap(),
        Yielded::default()
    );
    assert!(framing.holds(1));
    assert!(framing.poll_parked(&mut noop_cx()).is_pending());
    door.host.complete(1);
    let yielded = match framing.poll_parked(&mut noop_cx()) {
        std::task::Poll::Ready(Ok(y)) => y,
        other => panic!("the parked emit must complete: {other:?}"),
    };
    assert_eq!(yielded.wire, b"held", "the original bytes are emitted once");
    assert_eq!(
        yielded.flow,
        [super::StreamFlow::Full(1)],
        "the resumed stream must remain blocked at its high-water mark"
    );
    assert!(!framing.parked());
    assert_eq!(door.host.calls(), 1);
}

#[test]
fn a_resumed_ingest_preserves_its_stream_writable_signal() {
    let mut door = MuxDoor::new();
    door.yield_writable = true;
    let door = Arc::new(door);
    let (mut framing, _) = Framing::begin_ticketed(
        door.clone(),
        SIDE_ACCEPT,
        "",
        &Established::plain_for_test(),
        &[],
    )
    .unwrap();
    assert_eq!(framing.ingest(b"1", false).unwrap(), Yielded::default());
    assert!(framing.poll_parked(&mut noop_cx()).is_pending());
    door.host.complete(1);
    let yielded = match framing.poll_parked(&mut noop_cx()) {
        std::task::Poll::Ready(Ok(y)) => y,
        other => panic!("the parked ingest must complete: {other:?}"),
    };
    assert_eq!(
        yielded.flow,
        [super::StreamFlow::Writable(1)],
        "a resumed readiness signal must reach the caller"
    );
    assert!(
        yielded.pieces.is_empty(),
        "readiness must never become a payload frame"
    );
    assert!(!framing.parked());
    assert_eq!(door.host.calls(), 1);
}

fn reasoned_head_buffers(rows: &[(u64, u16, bool, &[u8])]) -> (Buffers, FramerOut) {
    let mut buffers = Buffers::default();
    buffers.frame.clear();
    buffers.pieces.clear();
    buffers.heads.clear();
    for &(stream, code, interim, reason) in rows {
        let offset = buffers.frame.len() as u64;
        buffers.frame.extend_from_slice(reason);
        buffers.heads.push(HeadSlots {
            stream,
            reason: FrameSpan {
                offset,
                len: reason.len() as u64,
            },
            ..HeadSlots::default()
        });
        let offset = buffers.frame.len() as u64;
        let fields = b"x-sensitive-marker: retained\r\n";
        buffers.frame.extend_from_slice(fields);
        buffers.pieces.push(FramePiece {
            stream,
            offset,
            len: fields.len() as u64,
            code: u32::from(code),
            flags: PIECE_FIELDS
                | PIECE_HAS_CODE
                | PIECE_END_OF_FRAME
                | if interim { PIECE_INTERIM } else { 0 },
            ..EMPTY_PIECE
        });
    }
    let mut out: FramerOut = blank_out();
    out.yielded.frame_len = buffers.frame.len() as u64;
    out.yielded.pieces_len = buffers.pieces.len() as u32;
    out.yielded.heads_len = buffers.heads.len() as u32;
    (buffers, out)
}

#[test]
fn informational_reasons_stay_on_their_pieces_and_never_become_terminal_heads() {
    for terminal in [101, 200] {
        let (mut buffers, out) = reasoned_head_buffers(&[
            (7, 100, true, b"Continue"),
            (8, 103, true, b"Other hints"),
            (7, 103, true, b"Early hints"),
            (8, 200, false, b"Other ready"),
            (7, terminal, false, b"Final response"),
        ]);
        let mut yielded = Yielded::default();
        assert!(buffers.take(&out, &mut yielded).unwrap());
        assert_eq!(
            yielded
                .heads
                .iter()
                .map(|h| (h.stream, h.reason.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (8, Some(b"Other ready".as_slice())),
                (7, Some(b"Final response".as_slice()))
            ]
        );
        assert_eq!(
            yielded
                .interim
                .iter()
                .map(|p| (p.stream, p.status_code, p.reason.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (7, Some(100), Some(b"Continue".as_slice())),
                (8, Some(103), Some(b"Other hints".as_slice())),
                (7, Some(103), Some(b"Early hints".as_slice()))
            ]
        );
        assert_eq!(
            yielded
                .pieces
                .iter()
                .map(|p| (p.stream, p.status_code, p.reason.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (8, Some(200), Some(b"Other ready".as_slice())),
                (
                    7,
                    Some(u32::from(terminal)),
                    Some(b"Final response".as_slice())
                )
            ]
        );
        assert!(yielded
            .interim
            .iter()
            .chain(&yielded.pieces)
            .all(|p| p.bytes == b"x-sensitive-marker: retained\r\n"));
    }
}

#[test]
fn informational_only_answer_does_not_publish_a_terminal_head_before_the_next_yield() {
    let (mut buffers, out) = reasoned_head_buffers(&[(7, 103, true, b"Early hints")]);
    let mut yielded = Yielded::default();
    assert!(buffers.take(&out, &mut yielded).unwrap());
    assert!(yielded.heads.is_empty());
    assert!(yielded.pieces.is_empty());
    assert_eq!(
        yielded.interim[0].reason.as_deref(),
        Some(b"Early hints".as_slice())
    );
    let (mut buffers, out) = reasoned_head_buffers(&[(7, 101, false, b"Switching Protocols")]);
    assert!(buffers.take(&out, &mut yielded).unwrap());
    assert_eq!(yielded.heads.len(), 1);
    assert_eq!(yielded.pieces[0].status_code, Some(101));
    assert_eq!(
        yielded.pieces[0].reason.as_deref(),
        Some(b"Switching Protocols".as_slice())
    );
    assert_eq!(
        yielded.interim[0].reason.as_deref(),
        Some(b"Early hints".as_slice())
    );
}

#[test]
fn split_informational_fields_keep_their_stream_state_and_original_reason_across_yields() {
    let (mut buffers, mut out) = reasoned_head_buffers(&[(7, 103, true, b"Early hints")]);
    let start = buffers.pieces[0].offset as usize;
    buffers.frame.truncate(start);
    buffers.frame.extend_from_slice(b"x-sensitive-marker: ");
    buffers.pieces[0].len = (buffers.frame.len() - start) as u64;
    buffers.pieces[0].flags &= !PIECE_END_OF_FRAME;
    out.yielded.frame_len = buffers.frame.len() as u64;
    out.yielded.flags = YIELD_MORE;
    let mut yielded = Yielded::default();
    assert!(!buffers.take(&out, &mut yielded).unwrap());
    assert!(yielded.heads.is_empty());
    buffers.frame = b"retained\r\n".to_vec();
    buffers.pieces = vec![FramePiece {
        stream: 7,
        offset: 0,
        len: buffers.frame.len() as u64,
        code: 103,
        flags: PIECE_FIELDS | PIECE_HAS_CODE | PIECE_INTERIM | PIECE_CONTINUED | PIECE_END_OF_FRAME,
        ..EMPTY_PIECE
    }];
    buffers.heads.clear();
    out.yielded.frame_len = buffers.frame.len() as u64;
    out.yielded.heads_len = 0;
    assert!(!buffers.take(&out, &mut yielded).unwrap());
    assert_eq!(
        yielded.interim[0].reason.as_deref(),
        Some(b"Early hints".as_slice())
    );
    assert_eq!(yielded.interim[1].reason, None);
    assert_eq!(
        yielded
            .interim
            .iter()
            .flat_map(|p| p.bytes.iter().copied())
            .collect::<Vec<_>>(),
        b"x-sensitive-marker: retained\r\n"
    );
    let (mut terminal, terminal_out) =
        reasoned_head_buffers(&[(7, 101, false, b"Switching Protocols")]);
    buffers.frame = std::mem::take(&mut terminal.frame);
    buffers.pieces = std::mem::take(&mut terminal.pieces);
    buffers.heads = std::mem::take(&mut terminal.heads);
    assert!(buffers.take(&terminal_out, &mut yielded).unwrap());
    assert_eq!(yielded.heads.len(), 1);
    assert_eq!(yielded.pieces[0].status_code, Some(101));
    assert_eq!(
        yielded.pieces[0].reason.as_deref(),
        Some(b"Switching Protocols".as_slice())
    );
}
