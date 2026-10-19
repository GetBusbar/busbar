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
    let (mut f, _) = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
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

/// WS-DIAL (ARCHITECT Q-L5B-WS-DIAL 2026-10-03): a dialled framing's `begin` is handed the dial's
/// opening head fields (`BeginIn::fields`), in order; a framing begun without any hands none.
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
        &Established::default(),
        &opening,
    )
    .unwrap();
    let _ = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
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

/// RED (C19-TAIL U5): a piece the framer states as text (`PIECE_TEXT`) is read up as text; one it
/// does not is binary.
#[test]
fn a_text_piece_is_read_as_text() {
    for text in [true, false] {
        let door = Arc::new(TestDoor::new(
            "ws",
            &["ws"],
            &[],
            Knobs {
                text,
                ..Knobs::default()
            },
        ));
        let (mut f, _) = Framing::begin(door, SIDE_DIAL, "t", &Established::default()).unwrap();
        let y = f.ingest(b"{}", false).unwrap();
        assert_eq!(y.pieces.len(), 1);
        assert_eq!(y.pieces[0].text, text, "stated text={text}");
    }
}

#[test]
fn a_refusals_neutral_status_reaches_the_framer_on_every_re_call() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
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
    let (_, y) = Framing::begin(door, SIDE_DIAL, "t", &Established::default()).unwrap();
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
    let (_, y) = Framing::begin(door.clone(), SIDE_ACCEPT, "", &Established::default()).unwrap();
    assert_eq!(
        y.heads,
        [Head {
            stream: 1,
            method: Some(b"GET".to_vec()),
            target: Some(b"/v1".to_vec()),
            ..Head::default()
        }]
    );
    let dialled = Framing::begin(door, SIDE_DIAL, "t", &Established::default());
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

/// RED (Law 0: a plugin is isolated to its ABI, and holds no host worker): a framer that keeps
/// answering that it owes more (`YIELD_MORE`) and writes nothing FAULTs its framing after a bounded
/// number of re-calls. Re-called with no bound, it spun the host worker forever.
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
        let begun = Framing::begin(door, SIDE_DIAL, "t", &Established::default())
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

/// THE HOST'S AUTH SERVICE, doubled as the mechanism keeps it: a call runs ONCE per handle
/// `(ticket, seq)` and stores its result; a not-ready call answers NOT_READY and its completion
/// wakes the ticket; a re-issued handle reads the stored result; a NEW op on the ticket forgets the
/// ticket's results (its handles count from 0 again), so only a resume reads them.
#[derive(Default)]
struct AuthHost {
    /// `None` = running, `Some` = the stored answer.
    stored: std::sync::Mutex<std::collections::HashMap<(Ticket, u32), Option<u64>>>,
    /// How many times the auth itself ran.
    real_calls: std::sync::atomic::AtomicUsize,
    /// The waker the ticket's holder registered.
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

use busbar_contract::abi::mechanism::ticket::Ticket;

impl AuthHost {
    fn new_op(&self, t: Ticket) {
        self.stored.lock().unwrap().retain(|(k, _), _| *k != t);
    }

    /// `auth.call` on `(t, seq)`: `Some` = READY with the stored answer, `None` = NOT_READY.
    fn call(&self, t: Ticket, seq: u32) -> Option<u64> {
        let mut m = self.stored.lock().unwrap();
        if let Some(r) = m.get(&(t, seq)) {
            return *r;
        }
        self.real_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        m.insert((t, seq), None);
        None
    }

    /// The auth answers: every running call stores `answer`, and the ticket's wake fires.
    fn complete(&self, answer: u64) {
        for v in self.stored.lock().unwrap().values_mut() {
            v.get_or_insert(answer);
        }
        if let Some(w) = self.waker.lock().unwrap().take() {
            w.wake();
        }
    }
}

/// The framing's ticket, its registered waker held by the auth double.
struct AuthTicket {
    ticket: Ticket,
    host: Arc<AuthHost>,
}

impl crate::carrier::Side for AuthTicket {
    fn ticket(&self) -> Ticket {
        self.ticket
    }

    fn register(&self, waker: &std::task::Waker) {
        *self.host.waker.lock().unwrap() = Some(waker.clone());
    }
}

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
        &Established::default(),
        &[],
        None,
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
