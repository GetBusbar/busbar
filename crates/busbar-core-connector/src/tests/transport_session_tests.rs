// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 session task's core arms (IF §8.7, §11.3, §12.22, §13; C-TRANSPORT-BACKPRESSURE and
//! C-TRANSPORT-CLOSE core arms, C-TRANSPORT-REFUSE connector arm, C-ALPN connector arm): the answer grammar
//! charged to C1, the held bit and its stall reset, E_REFUSE, E_CLOSE once and never after CLOSE/EOF/a lost
//! socket/quarantine, and ALPN by role. The framer's answers are scripted; each framer's own arm runs in its
//! repository against its image.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::records::Records;
use busbar_ports::transport::TransportEvent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;

use super::*;
use crate::framed_stream::STREAM_STALL_DEFAULT_MS;
use busbar_plugin_abi::transport::{
    CR_DRAIN, CR_NORMAL, CR_TIMEOUT, E_BODY, E_CLOSE, E_END, E_HEAD, E_REFUSE, E_REFUSE_HEAD_SENT,
    E_RESET, RESET_STALLED,
};

/// One call the scripted framer saw, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seen {
    Ingest(Vec<u8>),
    Emit {
        stream: u64,
        piece: u32,
        arg: u32,
        bytes: Vec<u8>,
    },
    Timer,
}

/// One answer record the scripted framer writes, owned.
#[derive(Debug, Clone)]
pub(crate) enum Out {
    Write(&'static [u8]),
    Echo(Vec<u8>),
    Close(bool),
    Head(u64),
    Opened(u64),
    Full(u64),
    Writable(u64),
    SendTo(u32),
}

type Respond = Box<dyn FnMut(&Seen) -> Vec<Out> + Send>;

/// A framer whose answers a test writes: every call is recorded, every charge kept.
pub(crate) struct Script {
    pub(crate) quarantined: bool,
    respond: Respond,
    seen: Arc<Mutex<Vec<Seen>>>,
    charges: Arc<Mutex<Vec<FaultReason>>>,
    dropped: Arc<AtomicU64>,
}

impl Drop for Script {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

impl Script {
    pub(crate) fn answer(
        &mut self,
        call: Call<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        let seen = match call {
            Call::Ingest(bytes) => Seen::Ingest(Vec::from(bytes)),
            Call::Emit {
                stream,
                piece,
                arg,
                bytes,
            } => Seen::Emit {
                stream,
                piece,
                arg,
                bytes: Vec::from(bytes),
            },
            Call::Timer => Seen::Timer,
        };
        let outs = (self.respond)(&seen);
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(seen);
        for out in &outs {
            match out {
                Out::Write(bytes) => sink(TransportOut::Write(bytes)),
                Out::Echo(bytes) => sink(TransportOut::Write(bytes)),
                Out::Close(abort) => sink(TransportOut::Close { abort: *abort }),
                Out::Head(stream) => sink(TransportOut::StreamHead {
                    stream: *stream,
                    end_stream: false,
                    head: Records::new(&[]),
                }),
                Out::Opened(stream) => sink(TransportOut::StreamOpened(*stream)),
                Out::Full(stream) => sink(TransportOut::StreamFull(*stream)),
                Out::Writable(stream) => sink(TransportOut::StreamWritable(*stream)),
                Out::SendTo(path) => sink(TransportOut::SendTo {
                    path: *path,
                    secured: false,
                    bytes: b"dg",
                }),
            }
        }
        Ok(())
    }

    pub(crate) fn charged(&self, reason: FaultReason) {
        self.charges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(reason);
    }
}

struct Scripted {
    conn: TransportConn,
    seen: Arc<Mutex<Vec<Seen>>>,
    charges: Arc<Mutex<Vec<FaultReason>>>,
    dropped: Arc<AtomicU64>,
}

fn scripted(respond: Respond, stall_ms: Option<u32>, quarantined: bool) -> Scripted {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let charges = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicU64::new(0));
    let script = Script {
        quarantined,
        respond,
        seen: Arc::clone(&seen),
        charges: Arc::clone(&charges),
        dropped: Arc::clone(&dropped),
    };
    Scripted {
        conn: TransportConn::scripted(script, stall_ms, Instant::now()),
        seen,
        charges,
        dropped,
    }
}

fn seen(log: &Arc<Mutex<Vec<Seen>>>) -> Vec<Seen> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn closes(log: &Arc<Mutex<Vec<Seen>>>) -> usize {
    seen(log)
        .iter()
        .filter(|s| matches!(s, Seen::Emit { piece: E_CLOSE, .. }))
        .count()
}

fn emit(stream: u64, piece: u32) -> Called {
    Called::Emit { stream, piece }
}

fn answer(
    answers: &mut Answers,
    called: Called,
    outs: Vec<TransportOut<'_>>,
) -> Result<Actions, FaultReason> {
    answers.start(called, Instant::now());
    for out in outs {
        answers.take(out);
    }
    answers.finish()
}

// Compare test observations explicitly; production payload owners deliberately have no equality API.
impl PartialEq for Act {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Write(a), Self::Write(b)) => a.as_slice() == b.as_slice(),
            (Self::Close { abort: a }, Self::Close { abort: b }) => a == b,
            (Self::Wake(a), Self::Wake(b))
            | (Self::End(a), Self::End(b))
            | (Self::Opened(a), Self::Opened(b))
            | (Self::Full(a), Self::Full(b))
            | (Self::Writable(a), Self::Writable(b)) => a == b,
            (
                Self::Upgrade {
                    protocol: a,
                    leftover: x,
                },
                Self::Upgrade {
                    protocol: b,
                    leftover: y,
                },
            ) => a == b && x.as_slice() == y.as_slice(),
            (
                Self::Head {
                    stream: a,
                    end_stream: x,
                    head: p,
                },
                Self::Head {
                    stream: b,
                    end_stream: y,
                    head: q,
                },
            ) => a == b && x == y && p.as_slice() == q.as_slice(),
            (
                Self::Body {
                    stream: a,
                    flags: x,
                    bytes: p,
                },
                Self::Body {
                    stream: b,
                    flags: y,
                    bytes: q,
                },
            ) => a == b && x == y && p.as_slice() == q.as_slice(),
            (Self::Reset { stream: a, code: x }, Self::Reset { stream: b, code: y }) => {
                a == b && x == y
            }
            (
                Self::Trailers {
                    stream: a,
                    pairs: x,
                },
                Self::Trailers {
                    stream: b,
                    pairs: y,
                },
            ) => a == b && x.as_slice() == y.as_slice(),
            (Self::Pause, Self::Pause) | (Self::Resume, Self::Resume) => true,
            _ => false,
        }
    }
}

impl PartialEq for Inbound {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Head {
                    stream: a,
                    end_stream: x,
                    head: p,
                },
                Self::Head {
                    stream: b,
                    end_stream: y,
                    head: q,
                },
            ) => a == b && x == y && p.as_slice() == q.as_slice(),
            (
                Self::Body {
                    stream: a,
                    flags: x,
                    bytes: p,
                },
                Self::Body {
                    stream: b,
                    flags: y,
                    bytes: q,
                },
            ) => a == b && x == y && p.as_slice() == q.as_slice(),
            (Self::Reset { stream: a, code: x }, Self::Reset { stream: b, code: y }) => {
                a == b && x == y
            }
            (
                Self::Trailers {
                    stream: a,
                    pairs: x,
                },
                Self::Trailers {
                    stream: b,
                    pairs: y,
                },
            ) => a == b && x.as_slice() == y.as_slice(),
            (Self::End(a), Self::End(b)) | (Self::Stalled(a), Self::Stalled(b)) => a == b,
            _ => false,
        }
    }
}

fn send_to() -> TransportOut<'static> {
    TransportOut::SendTo {
        path: 1,
        secured: false,
        bytes: b"dg",
    }
}

#[test]
fn native_callback_payloads_are_redacted_and_wiped_on_release() {
    const SECRET: &[u8] = b"native-request-credential-72819";
    let before = busbar_contract::secure::wipe_counts().1;
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        Called::Ingest,
        vec![
            TransportOut::Write(SECRET),
            TransportOut::StreamHead {
                stream: 1,
                end_stream: false,
                head: Records::new(SECRET),
            },
            TransportOut::StreamBody {
                stream: 1,
                flags: 0,
                bytes: SECRET,
            },
            TransportOut::StreamTrailers {
                stream: 1,
                pairs: Records::new(SECRET),
            },
        ],
    )
    .expect("callback ownership");
    let shown = format!("{acts:?}");
    assert!(
        !shown.contains(&format!("{SECRET:?}")),
        "native payload Debug leaked bytes"
    );
    drop(acts);
    assert_eq!(
        busbar_contract::secure::wipe_counts().1 - before,
        4,
        "all four callback buffers wipe"
    );
}

#[test]
fn malformed_native_output_wipes_already_copied_payloads() {
    let before = busbar_contract::secure::wipe_counts().1;
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(
            &mut answers,
            Called::Ingest,
            vec![
                TransportOut::Write(b"credential"),
                TransportOut::StreamFull(1)
            ]
        ),
        Err(GRAMMAR),
    );
    assert_eq!(
        busbar_contract::secure::wipe_counts().1 - before,
        1,
        "discarded partial output wipes"
    );
}

#[test]
fn dropping_a_queued_native_piece_wipes_its_body() {
    let before = busbar_contract::secure::wipe_counts().1;
    let queued = piece(E_BODY, b"queued-response-credential");
    let shown = format!("{queued:?}");
    assert!(!shown.contains(&format!("{:?}", b"queued-response-credential".as_slice())));
    drop(queued);
    assert_eq!(busbar_contract::secure::wipe_counts().1 - before, 1);
}

#[test]
fn upgrade_leftover_stays_in_wiping_custody() {
    let before = busbar_contract::secure::wipe_counts().1;
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        emit(1, E_HEAD),
        vec![
            TransportOut::Upgrade {
                protocol: "test-protocol",
            },
            TransportOut::Leftover(b"first-private-message"),
        ],
    )
    .expect("upgrade output");
    let [Act::Upgrade { protocol, leftover }] = acts.as_slice() else {
        panic!("upgrade and leftover stay together");
    };
    assert_eq!(protocol.as_ref(), "test-protocol");
    assert_eq!(leftover.as_slice(), b"first-private-message");
    drop(acts);
    assert_eq!(busbar_contract::secure::wipe_counts().1 - before, 1);
}

struct PendingRead;

impl AsyncRead for PendingRead {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        out.put_slice(b"uncommitted-read");
        Poll::Pending
    }
}

#[tokio::test]
async fn pending_native_read_wipes_the_abandoned_loan() {
    use futures::FutureExt;
    let mut bytes = SecureVec::new();
    assert!(read_secure(&mut PendingRead, &mut bytes)
        .now_or_never()
        .is_none());
    assert!(bytes.is_empty());
    assert!(bytes.allocation().iter().all(|byte| *byte == 0));
}

struct PartialWriteThenPending(bool);

impl AsyncWrite for PartialWriteThenPending {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.0 {
            Poll::Pending
        } else {
            self.0 = true;
            Poll::Ready(Ok(bytes.len().min(3)))
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn partial_native_write_wipes_only_the_accepted_prefix() {
    use futures::FutureExt;
    let mut bytes = Payload::from(b"abcdef".as_slice());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    assert!(
        write_bounded(&mut PartialWriteThenPending(false), &mut bytes, deadline)
            .now_or_never()
            .is_none()
    );
    assert_eq!(bytes.as_slice(), b"def");
    assert!(bytes.allocation()[..bytes.live_range().start]
        .iter()
        .all(|byte| *byte == 0));
}

// ---- the answer grammar charged to C1 (§11.3) ----

#[test]
fn stream_full_holds_the_emits_own_stream() {
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        emit(3, E_BODY),
        vec![TransportOut::Write(b"x"), TransportOut::StreamFull(3)],
    )
    .expect("STREAM_FULL for the emit's own stream");
    assert_eq!(acts, vec![Act::Write(b"x".as_slice().into()), Act::Full(3)]);
    assert!(answers.is_held(3));
    assert!(!answers.is_held(5));
}

#[test]
fn stream_full_for_another_stream_is_a_grammar_breach() {
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(
            &mut answers,
            emit(3, E_BODY),
            vec![TransportOut::StreamFull(5)]
        ),
        Err(GRAMMAR)
    );
    assert!(!answers.is_held(3) && !answers.is_held(5));
}

#[test]
fn stream_full_outside_an_emit_answer_is_a_grammar_breach() {
    for called in [Called::Begin, Called::Ingest, Called::Timer, Called::Close] {
        let mut answers = Answers::new(None, Instant::now());
        assert_eq!(
            answer(&mut answers, called, vec![TransportOut::StreamFull(1)]),
            Err(GRAMMAR),
            "{called:?}"
        );
    }
}

#[test]
fn stream_writable_only_answers_ingest_or_timer() {
    for called in [Called::Begin, emit(1, E_BODY), Called::Close] {
        let mut answers = Answers::new(None, Instant::now());
        assert_eq!(
            answer(&mut answers, called, vec![TransportOut::StreamWritable(1)]),
            Err(GRAMMAR),
            "{called:?}"
        );
    }
}

#[test]
fn stream_writable_releases_a_held_stream_and_is_ignored_for_one_not_held() {
    let mut answers = Answers::new(None, Instant::now());
    answer(
        &mut answers,
        emit(3, E_BODY),
        vec![TransportOut::StreamFull(3)],
    )
    .expect("held");
    let acts = answer(
        &mut answers,
        Called::Timer,
        vec![
            TransportOut::StreamWritable(3),
            TransportOut::StreamWritable(9),
        ],
    )
    .expect("writable");
    assert_eq!(acts, vec![Act::Writable(3)]);
    assert!(!answers.is_held(3));
    assert_eq!(answers.next_stall(), None);
}

#[test]
fn a_client_opening_answers_stream_opened_and_may_hold_the_stream_it_opened() {
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        emit(0, E_HEAD),
        vec![TransportOut::StreamOpened(7), TransportOut::StreamFull(7)],
    )
    .expect("opened and full");
    assert_eq!(acts, vec![Act::Opened(7), Act::Full(7)]);
    assert!(answers.is_held(7));

    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(
            &mut answers,
            emit(0, E_HEAD),
            vec![TransportOut::Write(b"GET")]
        ),
        Err(GRAMMAR),
        "an opening with no STREAM_OPENED"
    );
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(
            &mut answers,
            emit(0, E_HEAD),
            vec![TransportOut::StreamOpened(7), TransportOut::StreamFull(8)],
        ),
        Err(GRAMMAR),
        "STREAM_FULL for a stream the opening did not open"
    );
}

#[test]
fn an_e_close_answer_is_writes_then_at_most_one_close() {
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        Called::Close,
        vec![
            TransportOut::Write(b"bye"),
            TransportOut::Close { abort: false },
        ],
    )
    .expect("WRITE* CLOSE?");
    assert_eq!(
        acts,
        vec![
            Act::Write(b"bye".as_slice().into()),
            Act::Close { abort: false }
        ]
    );
    let bad: Vec<Vec<TransportOut<'static>>> = vec![
        vec![
            TransportOut::Close { abort: false },
            TransportOut::Write(b"late"),
        ],
        vec![
            TransportOut::Close { abort: false },
            TransportOut::Close { abort: true },
        ],
        vec![TransportOut::StreamEnd(1)],
        vec![TransportOut::Pause],
        vec![send_to()],
    ];
    for outs in bad {
        let mut answers = Answers::new(None, Instant::now());
        assert_eq!(answer(&mut answers, Called::Close, outs), Err(GRAMMAR));
    }
}

#[test]
fn datagram_answers_have_no_place_in_a_byte_stream_session() {
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(&mut answers, Called::Ingest, vec![send_to()]),
        Err(GRAMMAR)
    );
}

#[test]
fn the_stall_deadline_is_armed_once_at_the_first_stream_full() {
    let t0 = Instant::now();
    let mut answers = Answers::new(None, t0);
    answers.start(emit(4, E_BODY), t0);
    answers.take(TransportOut::StreamFull(4));
    answers.finish().expect("held");
    answers.start(emit(4, E_RESET), t0 + Duration::from_secs(1));
    answers.finish().expect("reset");
    assert!(
        !answers.is_held(4),
        "a reset ends the stream and releases it"
    );

    answers.start(emit(3, E_BODY), t0);
    answers.take(TransportOut::StreamFull(3));
    answers.finish().expect("held");
    // Released by a WRITABLE, then held again later: a fresh hold arms a fresh deadline. Until then, a repeated
    // STREAM_FULL on a stream still held never pushes its deadline out.
    let later = t0 + Duration::from_secs(30);
    answers.start(emit(5, E_BODY), t0);
    answers.take(TransportOut::StreamFull(5));
    answers.finish().expect("held");
    answers.start(emit(5, E_RESET), later);
    answers.finish().expect("reset 5");
    let first = answers.next_stall();
    assert_eq!(
        first,
        Some(t0 + Duration::from_millis(u64::from(STREAM_STALL_DEFAULT_MS))),
        "stream 3's deadline, armed at its first STREAM_FULL"
    );
    let mut again = Answers::new(None, t0);
    again.start(emit(3, E_BODY), t0);
    again.take(TransportOut::StreamFull(3));
    again.finish().expect("held");
    again.start(emit(3, E_BODY), later);
    again.take(TransportOut::StreamFull(3));
    again.finish().expect("still held");
    assert_eq!(
        again.next_stall(),
        first,
        "a repeated hold keeps the deadline"
    );
}

// ---- the session: held streams, stall, refuse, close ----

#[test]
fn a_held_stream_takes_no_emit_but_a_reset_or_a_refusal() {
    let mut s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Emit { piece: E_BODY, .. } => vec![Out::Full(3)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let now = Instant::now();
    s.conn.emit(3, E_BODY, 0, b"a", now).expect("first body");
    assert!(s.conn.is_held(3));
    assert_eq!(
        s.conn.emit(3, E_BODY, 0, b"b", now),
        Err(Ended::Misuse("an emit on a held stream"))
    );
    assert_eq!(
        s.conn.emit(3, E_END, 0, b"", now),
        Err(Ended::Misuse("an emit on a held stream"))
    );
    assert_eq!(
        seen(&s.seen).len(),
        1,
        "nothing reached the framer while held"
    );
    s.conn
        .emit(3, E_RESET, 8, b"", now)
        .expect("a reset still goes");
    assert!(!s.conn.is_held(3), "and ends the stream");
}

#[test]
fn a_stalled_stream_is_reset_with_reset_stalled_and_its_siblings_untouched() {
    let mut s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Emit {
                stream: 3,
                piece: E_BODY,
                ..
            } => vec![Out::Full(3)],
            _ => Vec::new(),
        }),
        Some(1_000),
        false,
    );
    let t0 = Instant::now();
    s.conn.emit(3, E_BODY, 0, b"a", t0).expect("held");
    s.conn.emit(5, E_BODY, 0, b"b", t0).expect("sibling flows");
    let (stalled, _) = s
        .conn
        .stall(t0 + Duration::from_millis(999))
        .expect("not yet");
    assert!(stalled.is_empty());
    let (stalled, _) = s
        .conn
        .stall(t0 + Duration::from_millis(1_000))
        .expect("due");
    assert_eq!(stalled, vec![3]);
    assert_eq!(
        seen(&s.seen).last(),
        Some(&Seen::Emit {
            stream: 3,
            piece: E_RESET,
            arg: RESET_STALLED,
            bytes: Vec::new(),
        })
    );
    assert!(!s.conn.is_held(3));
    s.conn
        .emit(5, E_END, 0, b"", t0)
        .expect("the sibling still flows");
    assert!(s.conn.is_live(), "the conn stays up");
}

#[test]
fn core_refuses_a_stream_with_e_refuse_status_and_the_head_sent_flag() {
    let mut s = scripted(Box::new(|_: &Seen| Vec::new()), None, false);
    let now = Instant::now();
    s.conn
        .refuse(5, 429, true, "budget", now)
        .expect("refused after the head");
    s.conn
        .refuse(7, 503, false, "no plane", now)
        .expect("refused before the head");
    assert_eq!(
        seen(&s.seen),
        vec![
            Seen::Emit {
                stream: 5,
                piece: E_REFUSE,
                arg: 429 | E_REFUSE_HEAD_SENT,
                bytes: b"budget".to_vec(),
            },
            Seen::Emit {
                stream: 7,
                piece: E_REFUSE,
                arg: 503,
                bytes: b"no plane".to_vec(),
            },
        ]
    );
    for status in [200, 399, 600] {
        assert_eq!(
            s.conn.refuse(9, status, false, "x", now),
            Err(Ended::Misuse("a refusal status outside 400..=599"))
        );
    }
    assert_eq!(seen(&s.seen).len(), 2);
}

#[test]
fn e_close_is_sent_exactly_once_by_core() {
    let mut s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Emit { piece: E_CLOSE, .. } => vec![Out::Write(b"bye"), Out::Close(false)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let now = Instant::now();
    let acts = s.conn.close(CR_DRAIN, now).expect("sent").expect("live");
    assert_eq!(
        acts,
        vec![
            Act::Write(b"bye".as_slice().into()),
            Act::Close { abort: false }
        ]
    );
    assert_eq!(
        seen(&s.seen),
        vec![Seen::Emit {
            stream: 0,
            piece: E_CLOSE,
            arg: CR_DRAIN,
            bytes: Vec::new(),
        }]
    );
    assert_eq!(s.conn.close(CR_DRAIN, now), Ok(None), "never twice");
    assert!(!s.conn.is_live());
    assert_eq!(closes(&s.seen), 1);
}

#[test]
fn no_e_close_after_close_eof_a_lost_socket_or_quarantine() {
    let now = Instant::now();

    let mut framer_closed = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Ingest(_) => vec![Out::Close(false)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    framer_closed
        .conn
        .ingest(b"x", now)
        .expect("closed by the framer");
    assert_eq!(framer_closed.conn.close(CR_NORMAL, now), Ok(None));
    assert_eq!(closes(&framer_closed.seen), 0);

    let mut eof = scripted(Box::new(|_: &Seen| Vec::new()), None, false);
    eof.conn.ingest(&[], now).expect("EOF");
    assert_eq!(eof.conn.close(CR_NORMAL, now), Ok(None));
    assert_eq!(closes(&eof.seen), 0);

    let mut lost = scripted(Box::new(|_: &Seen| Vec::new()), None, false);
    lost.conn.mark_lost();
    assert_eq!(lost.conn.close(CR_TIMEOUT, now), Ok(None));
    assert_eq!(closes(&lost.seen), 0);

    let mut quarantined = scripted(Box::new(|_: &Seen| Vec::new()), None, true);
    assert_eq!(quarantined.conn.close(CR_DRAIN, now), Ok(None));
    assert_eq!(closes(&quarantined.seen), 0);
}

#[test]
fn a_terminal_session_never_calls_the_framer_again() {
    let now = Instant::now();
    for lost in [false, true] {
        let mut s = scripted(Box::new(|_| vec![Out::Close(false)]), None, false);
        if lost {
            s.conn.mark_lost();
        } else {
            s.conn.ingest(b"close", now).expect("framer close");
        }
        let before = seen(&s.seen);
        assert!(!s.conn.is_live());
        assert!(matches!(s.conn.timer(now), Err(Ended::Misuse(_))));
        assert!(matches!(s.conn.ingest(b"late", now), Err(Ended::Misuse(_))));
        assert!(matches!(
            s.conn.emit(1, E_BODY, 0, b"late", now),
            Err(Ended::Misuse(_))
        ));
        assert_eq!(seen(&s.seen), before);
    }
}

#[test]
fn core_close_retains_the_handle_until_the_output_owner_is_dropped() {
    let mut s = scripted(Box::new(|_| vec![Out::Write(b"goodbye")]), None, false);
    let now = Instant::now();
    let output = s.conn.close(CR_DRAIN, now).expect("close").expect("output");
    assert!(!s.conn.is_live());
    assert_eq!(
        s.dropped.load(Ordering::Relaxed),
        0,
        "close output still owns session custody"
    );
    assert!(matches!(s.conn.timer(now), Err(Ended::Misuse(_))));
    assert_eq!(s.conn.close(CR_DRAIN, now), Ok(None));
    assert_eq!(
        s.dropped.load(Ordering::Relaxed),
        0,
        "repeat close cannot cancel pending output"
    );
    assert_eq!(output, [Act::Write(b"goodbye".as_slice().into())]);
    drop(s.conn);
    assert_eq!(s.dropped.load(Ordering::Relaxed), 1);
}

struct FlushFailure;

impl AsyncRead for FlushFailure {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for FlushFailure {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_framer_close_flush_failure_is_not_clean_completion() {
    let s = scripted(Box::new(|_| Vec::new()), None, false);
    let r = rig();
    let outcome = drive(
        s.conn,
        vec![
            Act::Write(b"goodbye".as_slice().into()),
            Act::Close { abort: false },
        ],
        FlushFailure,
        r.wiring,
    )
    .await;
    assert!(matches!(outcome, Outcome::Lost(ref e) if e.kind() == std::io::ErrorKind::BrokenPipe));
    assert_eq!(s.dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_core_close_flush_failure_is_not_clean_completion() {
    let s = scripted(Box::new(|_| vec![Out::Write(b"goodbye")]), None, false);
    let r = rig();
    r.close.send(CR_DRAIN).expect("drain");
    let outcome = drive(s.conn, Vec::new(), FlushFailure, r.wiring).await;
    assert!(matches!(outcome, Outcome::Lost(ref e) if e.kind() == std::io::ErrorKind::BrokenPipe));
    assert_eq!(s.dropped.load(Ordering::Relaxed), 1);
}

#[test]
fn a_breach_charges_the_instance_and_ends_the_session() {
    let mut s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Ingest(_) => vec![Out::Full(1)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let now = Instant::now();
    assert_eq!(s.conn.ingest(b"x", now), Err(Ended::Fault(GRAMMAR)));
    assert_eq!(
        s.charges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
        vec![GRAMMAR]
    );
    assert!(!s.conn.is_live());
    assert_eq!(
        s.conn.timer(now),
        Err(Ended::Misuse("a call after the session was over"))
    );
}

#[test]
fn a_datagram_answer_in_a_byte_stream_session_charges_the_instance() {
    let mut s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Ingest(_) => vec![Out::SendTo(1)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    assert_eq!(
        s.conn.ingest(b"x", Instant::now()),
        Err(Ended::Fault(GRAMMAR))
    );
    assert_eq!(
        s.charges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        1
    );
}

#[test]
fn e_close_never_goes_through_emit() {
    let mut s = scripted(Box::new(|_: &Seen| Vec::new()), None, false);
    assert_eq!(
        s.conn.emit(0, E_CLOSE, CR_DRAIN, b"", Instant::now()),
        Err(Ended::Misuse("E_CLOSE goes through TransportConn::close"))
    );
    assert!(seen(&s.seen).is_empty());
}

// ---- ALPN by role (§8.7 `offer`, §13 round 9) ----

/// A port whose only answers are its offers.
struct Offers {
    server: Vec<Box<str>>,
    client: Vec<Box<str>>,
}

fn not_called() -> PortError {
    PortError::Call(CallError::NotDeclared)
}

impl TransportPort for Offers {
    fn listener_slots(&self) -> &[Box<str>] {
        &[]
    }
    fn alpn(&self, role: u32) -> &[Box<str>] {
        match role {
            wire::ROLE_SERVER => &self.server,
            wire::ROLE_CLIENT => &self.client,
            _ => &[],
        }
    }
    fn defaults(&self, _: u32) -> &[(Box<str>, Box<str>)] {
        &[]
    }
    fn protocols(&self) -> &[Box<str>] {
        &[]
    }
    fn facts(&self) -> u64 {
        wire::FB_SERVER | wire::FB_CLIENT
    }
    fn begin(
        &self,
        _: &ConnIn<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError> {
        Err(not_called())
    }
    fn ingest(
        &self,
        _: &mut TransportSession,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(not_called())
    }
    fn emit(
        &self,
        _: &mut TransportSession,
        _: u64,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(not_called())
    }
    fn timer(
        &self,
        _: &mut TransportSession,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(not_called())
    }
    fn datagram(
        &self,
        _: &mut TransportSession,
        _: u32,
        _: bool,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(not_called())
    }
    fn event(
        &self,
        _: &mut TransportSession,
        _: TransportEvent<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(not_called())
    }
}

#[test]
fn the_listener_offers_the_server_list_and_the_dial_the_client_list() {
    let port = Offers {
        server: vec![Box::from("h2"), Box::from("http/1.1")],
        client: vec![Box::from("http/1.1")],
    };
    assert_eq!(
        server_alpn(&port),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(client_alpn(&port), vec![b"http/1.1".to_vec()]);
    let silent = Offers {
        server: Vec::new(),
        client: vec![Box::from("h2")],
    };
    assert!(
        server_alpn(&silent).is_empty(),
        "an undeclared side offers nothing"
    );
    assert_eq!(client_alpn(&silent), vec![b"h2".to_vec()]);
}

// ---- the session task over a connection ----

async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
    conn: TransportConn,
    first: Vec<Act>,
    io: S,
    wiring: Wiring,
) -> Outcome<S> {
    let mut answer = Actions::new(&conn.answers.source).expect("test answer owner");
    for act in first {
        answer.push(act).expect("test action capacity");
    }
    super::drive(conn, answer, io, wiring).await
}

#[test]
fn storage_refusal_discards_complete_callback_without_charging_the_plugin() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let account = ProcessAdmission::with_limits(1, 16, 4);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut scripted = scripted(Box::new(|_| vec![Out::Write(b"private")]), None, false);
    scripted.conn.answers =
        Answers::with_source(None, Instant::now(), source).expect("empty owner");
    assert!(matches!(
        scripted.conn.ingest(b"input", Instant::now()),
        Err(Ended::Capacity)
    ));
    assert!(
        scripted.charges.lock().unwrap().is_empty(),
        "host allocation refusal is not plugin fault"
    );
    assert_eq!(account.used(), (0, 0), "no retained answer prefix escaped");
}

struct Rig {
    feeds: mpsc::Sender<Feed>,
    inbound: mpsc::Receiver<Inbound>,
    close: oneshot::Sender<u32>,
    counters: Arc<SessionCounters>,
    wiring: Wiring,
}

#[test]
fn attributed_output_is_retained_without_becoming_unattributed_write() {
    use busbar_contract::response_delivery::{CompletionRequirement, WireClass};
    let mut answers = Answers::new(None, Instant::now());
    answers.start(Called::Timer, Instant::now());
    answers.take(TransportOut::WirePart {
        stream: 3,
        class: WireClass::Payload,
        bytes: b"body",
    });
    answers.take(TransportOut::WireEnd {
        stream: 3,
        requirement: CompletionRequirement::Flush,
    });
    answers.take(TransportOut::ResponseQuiescent(3));
    let acts = answers.finish().expect("attributed native answer");
    assert!(
        matches!(&acts[0], Act::WirePart { stream: 3, class: WireClass::Payload, bytes } if bytes.as_slice() == b"body")
    );
    assert!(matches!(
        &acts[1],
        Act::WireEnd {
            stream: 3,
            requirement: CompletionRequirement::Flush
        }
    ));
    assert!(matches!(&acts[2], Act::Quiescent(3)));
}

fn rig() -> Rig {
    let (feeds, feed_rx) = mpsc::channel(8);
    let (inbound_tx, inbound) = mpsc::channel(8);
    let (close, close_rx) = oneshot::channel();
    let counters = Arc::new(SessionCounters::default());
    let wiring = Wiring {
        feeds: feed_rx,
        inbound: inbound_tx,
        close: close_rx,
        write_timeout: Duration::from_secs(5),
        drain_grace: Duration::from_secs(5),
        counters: Arc::clone(&counters),
    };
    Rig {
        feeds,
        inbound,
        close,
        counters,
        wiring,
    }
}

fn piece(piece: u32, bytes: &[u8]) -> Piece {
    Piece {
        piece,
        arg: 0,
        bytes: bytes.into(),
    }
}

async fn read_exactly<R: AsyncRead + Unpin>(r: &mut R, want: &[u8]) {
    let mut got = vec![0u8; want.len()];
    tokio::time::timeout(Duration::from_secs(10), r.read_exact(&mut got))
        .await
        .expect("bytes in time")
        .expect("read");
    assert_eq!(got, want);
}

fn head(stream: u64) -> Inbound {
    Inbound::Head {
        stream,
        end_stream: false,
        head: b"".as_slice().into(),
    }
}

/// The two streams the scripted framer opens on `open`.
fn two_streams(call: &Seen) -> Option<Vec<Out>> {
    match call {
        Seen::Ingest(bytes) if bytes == b"open" => Some(vec![Out::Head(1), Out::Head(3)]),
        _ => None,
    }
}

#[tokio::test]
async fn a_full_stream_is_not_pulled_while_its_sibling_completes() {
    let s = scripted(
        Box::new(|call: &Seen| {
            if let Some(outs) = two_streams(call) {
                return outs;
            }
            match call {
                Seen::Ingest(bytes) if bytes == b"room" => vec![Out::Writable(1)],
                Seen::Emit {
                    stream: 1,
                    piece: E_BODY,
                    bytes,
                    ..
                } => vec![Out::Echo(bytes.clone()), Out::Full(1)],
                Seen::Emit {
                    stream: 3,
                    piece: E_BODY,
                    bytes,
                    ..
                } => vec![Out::Echo(bytes.clone())],
                Seen::Emit {
                    stream: 3,
                    piece: E_END,
                    ..
                } => vec![Out::Write(b"|3")],
                _ => Vec::new(),
            }
        }),
        None,
        false,
    );
    let Rig {
        feeds,
        mut inbound,
        close,
        counters: _,
        wiring,
    } = rig();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let body = async move {
        let (mut rd, mut wr) = tokio::io::split(client);
        wr.write_all(b"open").await.expect("write");
        assert_eq!(inbound.recv().await, Some(head(1)));
        assert_eq!(inbound.recv().await, Some(head(3)));
        let (tx1, rx1) = mpsc::channel(1);
        let (tx3, rx3) = mpsc::channel(1);
        for (stream, pieces) in [(1, rx1), (3, rx3)] {
            feeds
                .send(Feed {
                    stream,
                    pieces,
                    opened: None,
                })
                .await
                .expect("attach");
        }
        tx1.send(piece(E_BODY, b"a")).await.expect("a");
        read_exactly(&mut rd, b"a").await;
        // Stream 1 is held: its next piece waits in the channel and is not pulled.
        tx1.send(piece(E_BODY, b"b")).await.expect("b queued");
        tx3.send(piece(E_BODY, b"c")).await.expect("c");
        read_exactly(&mut rd, b"c").await;
        tx3.send(piece(E_END, b"")).await.expect("end 3");
        read_exactly(&mut rd, b"|3").await;
        assert!(
            matches!(
                tx1.try_send(piece(E_BODY, b"x")),
                Err(TrySendError::Full(_))
            ),
            "the held stream's feed was pulled"
        );
        // Room on the wire: STREAM_WRITABLE releases it and its waiting piece goes.
        wr.write_all(b"room").await.expect("write");
        read_exactly(&mut rd, b"b").await;
        close.send(CR_NORMAL).expect("close");
        (rd, wr, feeds, tx1)
    };
    let (outcome, _keep) = tokio::join!(drive(s.conn, Vec::new(), server, wiring), body);
    assert!(
        matches!(outcome, Outcome::CoreClosed(CR_NORMAL)),
        "{outcome:?}"
    );
    let bodies_on_1 = seen(&s.seen)
        .iter()
        .filter(|c| {
            matches!(
                c,
                Seen::Emit {
                    stream: 1,
                    piece: E_BODY,
                    ..
                }
            )
        })
        .count();
    assert_eq!(bodies_on_1, 2, "a and b, never x");
}

#[tokio::test]
async fn a_stalled_stream_is_reset_and_the_conn_stays_up() {
    let s = scripted(
        Box::new(|call: &Seen| {
            if let Some(outs) = two_streams(call) {
                return outs;
            }
            match call {
                Seen::Emit {
                    stream: 1,
                    piece: E_BODY,
                    bytes,
                    ..
                } => vec![Out::Echo(bytes.clone()), Out::Full(1)],
                Seen::Emit {
                    stream: 1,
                    piece: E_RESET,
                    ..
                } => vec![Out::Write(b"rst")],
                Seen::Emit {
                    stream: 3,
                    piece: E_BODY,
                    bytes,
                    ..
                } => vec![Out::Echo(bytes.clone())],
                _ => Vec::new(),
            }
        }),
        Some(1_000),
        false,
    );
    let Rig {
        feeds,
        mut inbound,
        close,
        counters,
        wiring,
    } = rig();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let body = async move {
        let (mut rd, mut wr) = tokio::io::split(client);
        wr.write_all(b"open").await.expect("write");
        assert_eq!(inbound.recv().await, Some(head(1)));
        assert_eq!(inbound.recv().await, Some(head(3)));
        let (tx1, rx1) = mpsc::channel(1);
        let (tx3, rx3) = mpsc::channel(1);
        for (stream, pieces) in [(1, rx1), (3, rx3)] {
            feeds
                .send(Feed {
                    stream,
                    pieces,
                    opened: None,
                })
                .await
                .expect("attach");
        }
        tx1.send(piece(E_BODY, b"a")).await.expect("a");
        read_exactly(&mut rd, b"a").await;
        let stalled = tokio::time::timeout(Duration::from_secs(10), inbound.recv())
            .await
            .expect("the stall deadline passed");
        assert_eq!(stalled, Some(Inbound::Stalled(1)));
        read_exactly(&mut rd, b"rst").await;
        assert!(tx1.is_closed(), "the stalled stream's feed is ended");
        tx3.send(piece(E_BODY, b"c")).await.expect("c");
        read_exactly(&mut rd, b"c").await;
        close.send(CR_NORMAL).expect("close");
        (rd, wr, feeds, tx3)
    };
    let (outcome, _keep) = tokio::join!(drive(s.conn, Vec::new(), server, wiring), body);
    assert!(
        matches!(outcome, Outcome::CoreClosed(CR_NORMAL)),
        "{outcome:?}"
    );
    assert_eq!(counters.stalled.load(Ordering::Relaxed), 1);
    assert!(seen(&s.seen).contains(&Seen::Emit {
        stream: 1,
        piece: E_RESET,
        arg: RESET_STALLED,
        bytes: Vec::new(),
    }));
}

#[tokio::test]
async fn core_close_writes_the_goodbye_before_the_connection_closes() {
    let s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Emit {
                piece: E_CLOSE,
                arg: CR_DRAIN,
                ..
            } => vec![Out::Write(b"bye"), Out::Close(false)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let Rig {
        feeds,
        inbound,
        close,
        counters,
        wiring,
    } = rig();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let body = async move {
        close.send(CR_DRAIN).expect("close");
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
            .await
            .expect("closed in time")
            .expect("read");
        assert_eq!(got, b"bye", "the goodbye, then the close");
        (feeds, inbound)
    };
    let (outcome, _keep) = tokio::join!(drive(s.conn, Vec::new(), server, wiring), body);
    assert!(
        matches!(outcome, Outcome::CoreClosed(CR_DRAIN)),
        "{outcome:?}"
    );
    assert_eq!(closes(&s.seen), 1);
    assert_eq!(counters.close_skipped.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn the_framer_s_close_ends_the_session_with_no_e_close() {
    let s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Ingest(bytes) if bytes == b"bye" => vec![Out::Write(b"last"), Out::Close(false)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let Rig {
        feeds,
        inbound,
        close,
        counters: _,
        wiring,
    } = rig();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let body = async move {
        client.write_all(b"bye").await.expect("write");
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
            .await
            .expect("closed in time")
            .expect("read");
        assert_eq!(got, b"last");
        (feeds, inbound, close)
    };
    let (outcome, _keep) = tokio::join!(drive(s.conn, Vec::new(), server, wiring), body);
    assert!(matches!(outcome, Outcome::Closed), "{outcome:?}");
    assert_eq!(closes(&s.seen), 0);
}

#[tokio::test]
async fn peer_eof_with_nothing_left_ends_the_session_with_no_e_close() {
    let s = scripted(Box::new(|_: &Seen| Vec::new()), None, false);
    let Rig {
        feeds,
        inbound,
        close,
        counters,
        wiring,
    } = rig();
    let (client, server) = tokio::io::duplex(64 * 1024);
    drop(client);
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        drive(s.conn, Vec::new(), server, wiring),
    )
    .await
    .expect("ended in time");
    assert!(matches!(outcome, Outcome::PeerClosed), "{outcome:?}");
    assert_eq!(seen(&s.seen), vec![Seen::Ingest(Vec::new())]);
    assert_eq!(counters.close_skipped.load(Ordering::Relaxed), 0);
    drop((feeds, inbound, close));
}

#[tokio::test]
async fn a_client_opening_learns_its_stream_and_its_later_pieces_go_on_it() {
    let s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Emit {
                stream: 0,
                piece: E_HEAD,
                ..
            } => vec![Out::Write(b"GET"), Out::Opened(5)],
            Seen::Emit {
                stream: 5,
                piece: E_END,
                ..
            } => vec![Out::Write(b"|end")],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let Rig {
        feeds,
        inbound,
        close,
        counters: _,
        wiring,
    } = rig();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let body = async move {
        let (mut rd, wr) = tokio::io::split(client);
        let (tx, rx) = mpsc::channel(1);
        let (opened_tx, opened_rx) = oneshot::channel();
        feeds
            .send(Feed {
                stream: 0,
                pieces: rx,
                opened: Some(opened_tx),
            })
            .await
            .expect("attach");
        tx.send(piece(E_HEAD, b"head")).await.expect("head");
        read_exactly(&mut rd, b"GET").await;
        assert_eq!(opened_rx.await, Ok(5));
        tx.send(piece(E_END, b"")).await.expect("end");
        read_exactly(&mut rd, b"|end").await;
        close.send(CR_NORMAL).expect("close");
        (rd, wr, feeds, inbound)
    };
    let (outcome, _keep) = tokio::join!(drive(s.conn, Vec::new(), server, wiring), body);
    assert!(
        matches!(outcome, Outcome::CoreClosed(CR_NORMAL)),
        "{outcome:?}"
    );
    assert!(seen(&s.seen).contains(&Seen::Emit {
        stream: 5,
        piece: E_END,
        arg: 0,
        bytes: Vec::new(),
    }));
}
