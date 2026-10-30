// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host side of a framer: a full sink is re-called with no new bytes until every byte is out,
//! once and in order; a deadline and the end are carried; `locate` and `encode` answer.

use std::sync::Arc;

use busbar_contract::abi::transport::{SIDE_ACCEPT, SIDE_DIAL};

use super::*;
use crate::support::{Knobs, TestDoor};

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
/// (`BeginIn::fields`), in order; a framing begun without any hands none.
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
/// buffer (a framer answering short for want of one never located an https target).
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
/// never as field lines; the same request slots on a DIALLED framing are the other side's, and
/// refused.
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
/// word. A line ended with CR LF then a "continued" `:path` is a smuggled pseudo-field, refused; a
/// continued piece with nothing before it is refused; a continuation inside a name is refused.
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
/// starts clean.
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
/// open block, so its state does not outlive it (and the same stream id may start clean).
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
/// framing after a bounded number of re-calls. Re-called with no bound, it spun the host worker
/// forever.
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

/// A framer whose dial `begin` calls the auth service (handle seq 0) on its framing's ticket: it
/// answers PENDING while the auth is not ready, and READY (framing token 42) once the call answers.
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
        // Ticket-less, the auth service is refused, so a begin cannot complete; the close answers.
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

/// RED (a framer pends only on a ticketed auth call): a TICKETED `begin` whose auth call answers
/// not-ready PARKS, resumes on the ticket's wake with the same op on the same ticket, and
/// completes; the auth runs EXACTLY ONCE across the not-ready (each re-issue reads the stored
/// result; a re-issue as a new op would have run it again).
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

/// RED (A PENDING ANSWER PARKS ONLY ITS OWN STREAM, emit): two streams on one dialled framing.
/// The first stream's head emit calls the auth, which pends: the emit parks on ITS OWN ticket and
/// holds that stream alone. The second stream's request goes out and its answer comes in while
/// the first waits; then the first resumes on its ticket, carrying no new bytes, and goes out with
/// exactly one auth call.
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
/// request head arrives on (`'1'`, `'3'`), yielded as one piece on that stream. A head on stream
/// `1` calls the auth (handle seq `0`) on the op's ticket: while the auth is not ready the framer
/// holds what it took and answers PENDING; its resume, carrying no bytes, yields what it held once
/// the auth answers.
struct MuxDoor {
    facts: DoorFacts,
    host: Arc<AuthHost>,
    next: std::sync::atomic::AtomicU32,
    held: std::sync::Mutex<HashMap<Ticket, Vec<u8>>>,
    /// The bytes every resumed ingest carried.
    resumed: std::sync::Mutex<Vec<usize>>,
}

impl MuxDoor {
    fn new() -> Self {
        Self {
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
            crate::support::pieces_on_lanes(&i.sink, o, &held);
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

/// RED (A PENDING ANSWER PARKS ONLY ITS OWN STREAM, ingest): on one accepted connection the first
/// stream's head arrives and its auth pends: that ingest parks on its own ticket. The second
/// stream's head arrives next and is read, ingested on another ticket and handed up before the
/// first resumes; then the first resumes (carrying no bytes: the framer took them) and its head is
/// handed up, with exactly one auth call.
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
/// known; never on a plain emit, and never on an accepting framing.
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

/// RED (NO TICKET-LESS PATH FOR AN AUTH-CALLING FRAMER): a framing whose binding has auth points is
/// never begun ticket-less, whichever way it is asked for, and nothing crosses; on tickets, a dial
/// hands the binding to `begin` (`BeginIn::points`, `BeginIn::auth`).
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
    // An entry that gives no ticket is ticket-less too.
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
    // On tickets the dial's binding reaches the framer's begin.
    let ticketed = Arc::new(PendingDoor::new(TestDoor::identity("bytes"), 99));
    let (f, _) = Framing::begin_bound(ticketed.clone(), SIDE_DIAL, "t", &est, &[], &dial).unwrap();
    assert!(!f.parked());
    assert_eq!(
        ticketed.begun.lock().unwrap().as_slice(),
        &[(POINT_HEAD, AuthRef { id: 3, mac: 4 })]
    );
}

/// RED (Q128 arch u22 LOW 9; `busbar_contract::abi::transport`: "A framer that fills a buffer
/// answers READY with `YIELD_MORE` and the host calls the same op again"): `encode` renders a
/// whole message, statelessly, into one buffer sized for it, so it has no re-call to continue
/// from. A framer answering it `YIELD_MORE` owes bytes the host cannot ask for, and the encode
/// FAULTs. Taken as whole, the partial wire was sent as the message.
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
/// that follows it is the one field block handed up as the head.
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
}

/// A `PIECE_WRITABLE` piece is the framer telling the host a stream may be emitted on again, never
/// a frame: it is never handed up as a piece (relayed, it reached a reader as an empty body piece,
/// ahead of the head on a dialled stream). The messages around it are handed up as they came.
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

/// RED (a transport's size answer): `locate`'s short answer names the buffer sizes it needs, and
/// the contract admits up to 4 GiB each. The host bounds what it gives a locate answer and refuses
/// a larger ask as the transport's FAULT: it never allocates what the transport named past that
/// bound, and never asks again.
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
/// and located.
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
