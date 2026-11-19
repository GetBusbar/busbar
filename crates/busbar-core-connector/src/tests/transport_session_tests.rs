// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 session task's core arms (IF §8.7, §11.3, §12.22, §13; C-TRANSPORT-BACKPRESSURE and
//! C-TRANSPORT-CLOSE core arms, C-TRANSPORT-REFUSE connector arm, C-ALPN connector arm): the answer grammar
//! charged to C1, the held bit and its stall reset, E_REFUSE, E_CLOSE once and never after CLOSE/EOF/a lost
//! socket/quarantine, and ALPN by role. The framer's answers are scripted; each framer's own arm runs in its
//! repository against its image.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_plugin_abi::records::Records;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;

use super::*;
use crate::framed_stream::STREAM_STALL_DEFAULT_MS;
use crate::outbound::records::{END_FAILED, END_FLUSH, WIRE_CONTROL};
use busbar_plugin_abi::transport::{
    CR_DRAIN, CR_NORMAL, E_BODY, E_CLOSE, E_END, E_HEAD, E_REFUSE, E_REFUSE_HEAD_SENT, E_RESET,
    RESET_STALLED,
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
    /// Bytes of the connection itself: stream 0, control.
    Write(&'static [u8]),
    /// Body bytes of a stream: payload.
    Part(u64, &'static [u8]),
    /// A stream's head, framing or end marker: control.
    Control(u64, &'static [u8]),
    /// The stream's output ended whole (END_FLUSH).
    WireEnd(u64),
    /// The transport failed the stream's output (END_FAILED).
    Failed(u64),
    /// The body bytes the engine just emitted on this stream, written as its payload.
    Echo(u64, Vec<u8>),
    Close(bool),
    Head(u64),
    Opened(u64),
    /// Inbound body bytes of a stream, handed up to the engine (STREAM_BODY).
    Body(u64, &'static [u8]),
    Full(u64),
    Writable(u64),
    SendTo(u32),
}

type Respond = Box<dyn FnMut(&Seen) -> Vec<Out> + Send>;

/// A framer whose answers a test writes: every call is recorded, every charge kept.
pub(crate) struct Script {
    pub(crate) quarantined: bool,
    respond: Respond,
    /// A framer that answers from borrowed statics and records nothing (the cost runs): the script
    /// then allocates nothing itself, so what is counted is the session's own.
    lean: Option<fn(Call<'_>, &mut dyn FnMut(TransportOut<'_>))>,
    seen: Arc<Mutex<Vec<Seen>>>,
    charges: Arc<Mutex<Vec<FaultReason>>>,
    /// Every credit the engine gave, in order: (stream, bytes) of each `emit(E_CONSUMED)`. Recorded
    /// before the framer answers the call, so a framer that models its far end's window reads it.
    credits: Arc<Mutex<Vec<(u64, u64)>>>,
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
        if let Some(lean) = self.lean {
            lean(call, sink);
            return Ok(());
        }
        if let Call::Emit {
            stream,
            piece: busbar_plugin_abi::transport::E_CONSUMED,
            credit,
            ..
        } = call
        {
            self.credits
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((stream, credit));
        }
        let seen = match call {
            Call::Ingest(bytes) => Seen::Ingest(Vec::from(bytes)),
            Call::Emit {
                stream,
                piece,
                arg,
                bytes,
                ..
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
                Out::Write(bytes) => sink(control(bytes)),
                Out::Part(stream, bytes) => sink(TransportOut::WirePart {
                    stream: *stream,
                    payload: true,
                    bytes,
                }),
                Out::Control(stream, bytes) => sink(TransportOut::WirePart {
                    stream: *stream,
                    payload: false,
                    bytes,
                }),
                Out::WireEnd(stream) => sink(TransportOut::WireEnd {
                    stream: *stream,
                    how: END_FLUSH,
                    arg: 0,
                }),
                Out::Failed(stream) => sink(TransportOut::WireEnd {
                    stream: *stream,
                    how: END_FAILED,
                    arg: 0,
                }),
                Out::Echo(stream, bytes) => sink(TransportOut::WirePart {
                    stream: *stream,
                    payload: true,
                    bytes,
                }),
                Out::Close(abort) => sink(TransportOut::Close { abort: *abort }),
                Out::Head(stream) => sink(TransportOut::StreamHead {
                    stream: *stream,
                    end_stream: false,
                    head: Records::new(&[]),
                }),
                Out::Opened(stream) => sink(TransportOut::StreamOpened(*stream)),
                Out::Body(stream, bytes) => sink(TransportOut::StreamBody {
                    stream: *stream,
                    flags: 0,
                    bytes,
                }),
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

#[tokio::test]
async fn rejected_upgrade_retires_original_tcp_writer_before_failed_receipt() {
    use busbar_contract::response_delivery::{DeliveryTerminal, ResponseKey, ResponseStop};
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let source = ProcessAdmission::new(1).connection_storage(AdmissionClass::Data);
    let mut ledger = DeliveryLedger::default();
    let handles = ledger
        .admit(ResponseKey {
            node: 1,
            incarnation: 1,
            unit: None,
            connection_generation: 1,
            stream: 1,
        })
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let io = crate::raw_progress::tcp(socket);
    let progress = io.progress();
    let script = scripted(Box::new(|_| Vec::new()), None, false);
    let outcome = Outcome::Upgraded(Box::new(Upgrade {
        delivery: Delivery::new(ledger, progress),
        conn: script.conn,
        io,
        protocol: Name::copy(&source, "websocket").unwrap(),
        leftover: Payload::copy(&source, &[]).unwrap(),
        feed: None,
    }));
    assert!(handles.watch.snapshot().terminal.is_none());
    outcome.retire();
    assert_eq!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::CarrierRetired))
    );
    assert!(!handles.watch.snapshot().first_payload_written);
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(script.dropped.load(Ordering::Relaxed), 1);
}

/// The log a scripted framer records the engine's credits in.
type Credits = Arc<Mutex<Vec<(u64, u64)>>>;

fn scripted(respond: Respond, stall_ms: Option<u32>, quarantined: bool) -> Scripted {
    scripted_stating(
        respond,
        stall_ms,
        quarantined,
        records::Session::stated(true, 1 << 20, 4 << 20),
        Credits::default(),
    )
}

/// As `scripted`, with the session `begin` states and the log the engine's credits are recorded in
/// (the framer's own answers may read it).
fn scripted_stating(
    respond: Respond,
    stall_ms: Option<u32>,
    quarantined: bool,
    session: records::Session,
    credits: Credits,
) -> Scripted {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let charges = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicU64::new(0));
    let script = Script {
        quarantined,
        respond,
        lean: None,
        seen: Arc::clone(&seen),
        charges: Arc::clone(&charges),
        credits,
        dropped: Arc::clone(&dropped),
    };
    Scripted {
        conn: TransportConn::scripted_stating(script, stall_ms, Instant::now(), session),
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
        answers.take(&out);
    }
    answers.finish()?;
    // The session keeps its array and output buffer; the test takes this answer's whole owner (its
    // spans with the buffer they index) and leaves the session a fresh one.
    let fresh = Actions::new(&answers.source).expect("test answer owner");
    Ok(std::mem::replace(&mut answers.acts, fresh))
}

/// A test's view of an answer: the socket bytes read out of the session's buffer, any other act as is.
#[derive(Debug, PartialEq)]
enum Shown<'a> {
    Part(u64, u32, &'a [u8]),
    Act(&'a Act),
}

fn shown(acts: &Actions) -> Vec<Shown<'_>> {
    acts.iter()
        .map(|act| match act {
            Act::WirePart {
                stream,
                class,
                bytes,
            } => Shown::Part(*stream, *class, acts.bytes(*bytes)),
            act => Shown::Act(act),
        })
        .collect()
}

impl PartialEq for Actions {
    fn eq(&self, other: &Self) -> bool {
        shown(self) == shown(other)
    }
}

// Compare test observations explicitly; production payload owners deliberately have no equality API.
// Socket bytes are compared through `shown` (a span alone means nothing without its buffer).
impl PartialEq for Act {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
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
            (
                Self::Reset {
                    stream: a,
                    code: x,
                    flags: p,
                },
                Self::Reset {
                    stream: b,
                    code: y,
                    flags: q,
                },
            ) => a == b && x == y && p == q,
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
            (Self::Session(a), Self::Session(b)) => a == b,
            (Self::WireSealed(a), Self::WireSealed(b)) => a == b,
            (
                Self::WireEnd {
                    stream: a,
                    how: x,
                    arg: p,
                },
                Self::WireEnd {
                    stream: b,
                    how: y,
                    arg: q,
                },
            ) => a == b && x == y && p == q,
            (Self::Busy, Self::Busy) | (Self::NoNewStreams, Self::NoNewStreams) => true,
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

/// Bytes of the connection itself: a part on stream 0, control (what a plain write was).
fn control(bytes: &[u8]) -> TransportOut<'_> {
    TransportOut::WirePart {
        stream: 0,
        payload: false,
        bytes,
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
            control(SECRET),
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
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(
            &mut answers,
            Called::Ingest,
            vec![control(b"credential"), TransportOut::StreamFull(1)]
        ),
        Err(GRAMMAR),
    );
    // The WRITE was copied into the session's output buffer; the refused answer wiped it there.
    let kept = answers
        .acts
        .out
        .allocation()
        .expect("the buffer the WRITE was copied into");
    assert!(
        kept.iter().all(|byte| *byte == 0),
        "discarded partial output wipes"
    );
    assert!(answers.acts.is_empty());
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
    // Since 403829b816 the leftover starts as an empty funded payload that the first Leftover
    // replaces with an exactly funded buffer: the retired buffer is wiped, then the leftover itself.
    assert_eq!(busbar_contract::secure::wipe_counts().1 - before, 1);
    drop(acts);
    assert_eq!(busbar_contract::secure::wipe_counts().1 - before, 2);
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

struct PartialWriteThenPending(bool);

impl AsyncRead for PartialWriteThenPending {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

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
async fn a_partial_write_takes_only_what_the_socket_took_from_the_run() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use futures::FutureExt;
    let source = ProcessAdmission::new(1).connection_storage(AdmissionClass::Data);
    let carrier = crate::raw_progress::test_carrier(PartialWriteThenPending(false));
    let progress = carrier.progress();
    let mut io = DeliveryIo::new(carrier, Delivery::new(DeliveryLedger::default(), progress));
    let mut acts = Actions::new(&source).expect("owner");
    acts.part(0, WIRE_CONTROL, b"abcdef").expect("output");
    let answered = io.answered(&acts).expect("a part on stream 0");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    assert!(io
        .write_out(&answered, &acts, deadline)
        .now_or_never()
        .is_none());
    // The ledger counted the three bytes the socket took, as the write returned, and not one more;
    // the rest is still in the session's own buffer, in order, until the session wipes it.
    assert_eq!((io.ledger().written, io.ledger().queued), (3, 6));
    assert_eq!(acts.bytes(span_of(&acts, 0)), b"abcdef");
    // A run that was not all given places nothing after it.
    assert_eq!(io.answered(&acts).err(), Some(Fault::Queue));
}

/// The span of the `index`th WIRE_PART of `acts`.
fn span_of(acts: &Actions, index: usize) -> Span {
    acts.iter()
        .filter_map(|act| match act {
            Act::WirePart { bytes, .. } => Some(*bytes),
            _ => None,
        })
        .nth(index)
        .expect("a WIRE_PART")
}

// ---- the answer grammar charged to C1 (§11.3) ----

#[test]
fn stream_full_holds_the_emits_own_stream() {
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        emit(3, E_BODY),
        vec![control(b"x"), TransportOut::StreamFull(3)],
    )
    .expect("STREAM_FULL for the emit's own stream");
    assert_eq!(
        shown(&acts),
        vec![
            Shown::Part(0, WIRE_CONTROL, b"x"),
            Shown::Act(&Act::Full(3))
        ]
    );
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
    assert_eq!(*acts, vec![Act::Writable(3)]);
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
    assert_eq!(*acts, vec![Act::Opened(7), Act::Full(7)]);
    assert!(answers.is_held(7));

    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        answer(&mut answers, emit(0, E_HEAD), vec![control(b"GET")]),
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
        vec![control(b"bye"), TransportOut::Close { abort: false }],
    )
    .expect("WRITE* CLOSE?");
    assert_eq!(
        shown(&acts),
        vec![
            Shown::Part(0, WIRE_CONTROL, b"bye"),
            Shown::Act(&Act::Close { abort: false })
        ]
    );
    let bad: Vec<Vec<TransportOut<'static>>> = vec![
        vec![TransportOut::Close { abort: false }, control(b"late")],
        vec![
            TransportOut::Close { abort: false },
            TransportOut::Close { abort: true },
        ],
        vec![TransportOut::StreamEnd(1)],
        vec![TransportOut::StreamBusy],
        vec![TransportOut::Session {
            multiplex: false,
            stream_window: 0,
            conn_window: 0,
        }],
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
    answers.take(&TransportOut::StreamFull(4));
    answers.finish().expect("held");
    answers.start(emit(4, E_RESET), t0 + Duration::from_secs(1));
    answers.finish().expect("reset");
    assert!(
        !answers.is_held(4),
        "a reset ends the stream and releases it"
    );

    answers.start(emit(3, E_BODY), t0);
    answers.take(&TransportOut::StreamFull(3));
    answers.finish().expect("held");
    // Released by a WRITABLE, then held again later: a fresh hold arms a fresh deadline. Until then, a repeated
    // STREAM_FULL on a stream still held never pushes its deadline out.
    let later = t0 + Duration::from_secs(30);
    answers.start(emit(5, E_BODY), t0);
    answers.take(&TransportOut::StreamFull(5));
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
    again.take(&TransportOut::StreamFull(3));
    again.finish().expect("held");
    again.start(emit(3, E_BODY), later);
    again.take(&TransportOut::StreamFull(3));
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
        shown(acts),
        vec![
            Shown::Part(0, WIRE_CONTROL, b"bye"),
            Shown::Act(&Act::Close { abort: false })
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
    assert_eq!(lost.conn.close(CR_NORMAL, now), Ok(None));
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
    // The close's output is the session's own array now: it cannot outlive the session's custody.
    let pending = s
        .conn
        .close(CR_DRAIN, now)
        .expect("close")
        .expect("output")
        .len();
    assert_eq!(pending, 1);
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
    assert_eq!(
        shown(s.conn.actions()),
        [Shown::Part(0, WIRE_CONTROL, b"goodbye")],
        "the pending output is still there"
    );
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
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    let r = rig();
    s.conn
        .actions()
        .part(0, WIRE_CONTROL, b"goodbye")
        .expect("first write");
    let outcome = drive(
        s.conn,
        vec![Act::Close { abort: false }],
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

// ---- the session task over a connection ----

async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
    conn: TransportConn,
    first: Vec<Act>,
    io: S,
    wiring: Wiring,
) -> Outcome<crate::raw_progress::RawCarrier<S>> {
    let mut conn = conn;
    for act in first {
        conn.actions().push(act).expect("test action capacity");
    }
    let io = crate::raw_progress::test_carrier(io);
    let progress = io.progress();
    super::drive(conn, io, progress, wiring).await
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
fn a_transport_2_answer_is_kept_as_the_drivers_items_in_order() {
    use crate::outbound::records::{
        Out as Item, StreamReset, WireSealed, RESET_NOT_PROCESSED, WIRE_PAYLOAD,
    };
    let mut answers = Answers::new(None, Instant::now());
    answers.start(Called::Timer, Instant::now());
    answers.take(&TransportOut::WirePart {
        stream: 3,
        payload: true,
        bytes: b"body",
    });
    answers.take(&TransportOut::WireSealed {
        stream: 3,
        slot: 0,
        offset: 4,
        len: 20,
    });
    answers.take(&TransportOut::WireEnd {
        stream: 3,
        how: END_FLUSH,
        arg: 0,
    });
    answers.take(&TransportOut::NoNewStreams);
    answers.take(&TransportOut::StreamReset {
        stream: 5,
        code: 7,
        not_processed: true,
    });
    answers.finish().expect("a transport 2.0 answer");
    let acts = &answers.acts;
    assert!(
        matches!(&acts[0], Act::WirePart { stream: 3, class: WIRE_PAYLOAD, bytes } if acts.bytes(*bytes) == b"body")
    );
    assert_eq!(acts[1], Act::WireSealed(WireSealed::stated(3, 0, 4, 20)));
    assert_eq!(
        acts[2],
        Act::WireEnd {
            stream: 3,
            how: END_FLUSH,
            arg: 0
        }
    );
    assert_eq!(acts[3], Act::NoNewStreams);
    assert_eq!(
        acts[4],
        Act::Reset {
            stream: 5,
            code: 7,
            flags: RESET_NOT_PROCESSED
        }
    );
    // What the delivery driver reads of them, one for one.
    let driven: Vec<Item> = acts
        .iter()
        .filter_map(|act| Some(act.driven()?.0))
        .collect();
    assert_eq!(driven.len(), 5);
    assert!(matches!(driven[0], Item::Part { len: 4, .. }));
    assert!(matches!(driven[1], Item::Sealed(_)));
    assert!(matches!(driven[2], Item::End(_)));
    assert_eq!(driven[3], Item::NoNewStreams);
    assert_eq!(
        driven[4],
        Item::Reset(StreamReset::stated(5, 7, true)),
        "the far end's guarantee reaches the redial decision"
    );
}

#[test]
fn session_is_begins_statement_once_and_nobody_elses() {
    let stated = |answers: &mut Answers, called: Called, count: usize| {
        answers.start(called, Instant::now());
        for _ in 0..count {
            answers.take(&TransportOut::Session {
                multiplex: true,
                stream_window: 1 << 16,
                conn_window: 1 << 18,
            });
        }
        answers.finish()
    };
    let mut answers = Answers::new(None, Instant::now());
    stated(&mut answers, Called::Begin, 1).expect("begin states the session");
    assert_eq!(
        answers.acts.as_slice(),
        [Act::Session(crate::outbound::records::Session::stated(
            true,
            1 << 16,
            1 << 18
        ))]
    );
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(
        stated(&mut answers, Called::Begin, 0),
        Err(GRAMMAR),
        "a begin that states no session"
    );
    let mut answers = Answers::new(None, Instant::now());
    assert_eq!(stated(&mut answers, Called::Begin, 2), Err(GRAMMAR));
    for called in [
        Called::Ingest,
        Called::Timer,
        emit(1, E_BODY),
        Called::Close,
    ] {
        let mut answers = Answers::new(None, Instant::now());
        answers.stated = true;
        assert_eq!(stated(&mut answers, called, 1), Err(GRAMMAR), "{called:?}");
    }
}

#[test]
fn stream_busy_answers_a_head_on_stream_zero_and_nothing_else() {
    let mut answers = Answers::new(None, Instant::now());
    let acts = answer(
        &mut answers,
        emit(0, E_HEAD),
        vec![TransportOut::StreamBusy],
    )
    .expect("the head was not taken: not a fault");
    assert_eq!(*acts, vec![Act::Busy]);
    let bad: Vec<(Called, Vec<TransportOut<'static>>)> = vec![
        (emit(3, E_BODY), vec![TransportOut::StreamBusy]),
        (Called::Ingest, vec![TransportOut::StreamBusy]),
        (
            emit(0, E_HEAD),
            vec![TransportOut::StreamBusy, TransportOut::StreamBusy],
        ),
        (
            emit(0, E_HEAD),
            vec![TransportOut::StreamOpened(7), TransportOut::StreamBusy],
        ),
        (
            emit(0, E_HEAD),
            vec![TransportOut::StreamBusy, TransportOut::StreamOpened(7)],
        ),
        (
            emit(0, E_HEAD),
            vec![TransportOut::StreamBusy, TransportOut::StreamFull(7)],
        ),
    ];
    for (called, outs) in bad {
        let mut answers = Answers::new(None, Instant::now());
        assert_eq!(
            answer(&mut answers, called, outs),
            Err(GRAMMAR),
            "{called:?}"
        );
    }
}

#[test]
fn one_piece_is_the_ports_set_of_one_with_its_bytes_in_its_own_entry() {
    use busbar_plugin_abi::transport::{E_CONSUMED, E_TRAILERS};
    let head = parts_of(E_HEAD, b"h");
    assert!(head.head == Some(&b"h"[..]) && head.body.is_none() && head.end.is_none());
    let body = parts_of(E_BODY, b"b");
    assert!(body.body == Some(&b"b"[..]) && body.head.is_none());
    let trailers = parts_of(E_TRAILERS, b"t");
    assert!(trailers.trailers == Some(&b"t"[..]) && trailers.body.is_none());
    let end = parts_of(E_END, b"");
    assert!(
        end.end == Some(&[][..]) && end.head.is_none() && end.body.is_none(),
        "the end's entry is present and empty"
    );
    for piece in [E_RESET, E_CLOSE, E_CONSUMED] {
        let parts = parts_of(piece, b"");
        assert!(
            parts.head.is_none()
                && parts.body.is_none()
                && parts.trailers.is_none()
                && parts.end.is_none()
                && parts.refuse.is_none(),
            "piece {piece} carries no entry"
        );
    }
    // E_REFUSE's one entry is core's own text.
    let refuse = parts_of(E_REFUSE, b"t");
    assert!(
        refuse.refuse == Some(&b"t"[..]) && refuse.head.is_none() && refuse.end.is_none(),
        "the refusal carries its text"
    );
}

#[test]
fn credit_is_its_own_call_and_an_emit_is_exactly_one_piece() {
    use busbar_plugin_abi::transport::E_CONSUMED;
    let mut s = scripted(Box::new(|_: &Seen| Vec::new()), None, false);
    let now = Instant::now();
    assert!(matches!(
        s.conn.emit(1, E_CONSUMED, 0, b"", now),
        Err(Ended::Misuse(_))
    ));
    assert!(matches!(
        s.conn.emit(1, E_HEAD | E_END, 0, b"", now),
        Err(Ended::Misuse(_))
    ));
    assert!(matches!(
        s.conn.emit(1, E_END, 0, b"x", now),
        Err(Ended::Misuse(_))
    ));
    assert!(matches!(s.conn.consumed(1, 0, now), Err(Ended::Misuse(_))));
    assert!(seen(&s.seen).is_empty(), "nothing was called");
    s.conn.consumed(1, 4096, now).expect("credit");
    assert_eq!(
        seen(&s.seen),
        vec![Seen::Emit {
            stream: 1,
            piece: E_CONSUMED,
            arg: 0,
            bytes: Vec::new()
        }]
    );
}

fn rig() -> Rig {
    let (_register, registrations) = mpsc::channel(8);
    let (feeds, feed_rx) = mpsc::channel(8);
    let (inbound_tx, inbound) = mpsc::channel(8);
    let (close, close_rx) = oneshot::channel();
    let counters = Arc::new(SessionCounters::default());
    let wiring = Wiring {
        delivery: DeliveryLedger::default(),
        registrations,
        feeds: feed_rx,
        inbound: inbound_tx,
        close: close_rx,
        write_timeout: Duration::from_secs(5),
        drain_grace: Duration::from_secs(5),
        counters: Arc::clone(&counters),
        read_holders: None,
    };
    Rig {
        feeds,
        inbound,
        close,
        counters,
        wiring,
    }
}

/// A framer that serves one answer per stream: a head on "open", then the engine's pieces framed
/// as the one output model says (a head is control, the body is payload, the end is its mark).
fn serving(call: &Seen) -> Vec<Out> {
    match call {
        Seen::Ingest(bytes) if bytes == b"open" => vec![Out::Head(1)],
        Seen::Emit {
            stream,
            piece: E_HEAD,
            ..
        } => vec![Out::Control(*stream, b"H")],
        Seen::Emit {
            stream,
            piece: E_BODY,
            bytes,
            ..
        } => vec![Out::Echo(*stream, bytes.clone())],
        Seen::Emit {
            stream,
            piece: E_END,
            ..
        } => vec![Out::Control(*stream, b"E"), Out::WireEnd(*stream)],
        Seen::Emit {
            stream,
            piece: E_RESET,
            ..
        } => vec![Out::Failed(*stream)],
        _ => Vec::new(),
    }
}

fn response_key(stream: u64) -> ResponseKey {
    ResponseKey {
        node: 1,
        incarnation: 1,
        unit: None,
        connection_generation: 1,
        stream,
    }
}

#[tokio::test]
async fn an_abandoned_registration_stops_its_answer_and_holds_nothing() {
    let s = scripted(Box::new(serving), None, false);
    let mut r = rig();
    let (registration, registrations) = mpsc::channel(1);
    r.wiring.registrations = registrations;
    let (mut peer, server) = tokio::io::duplex(64);
    let mut inbound = r.inbound;
    let feeds = r.feeds;
    let body = async move {
        peer.write_all(b"open").await.unwrap();
        assert_eq!(inbound.recv().await, Some(head(1)));
        // The receipt's waiter is gone before the receipt is made.
        let (admitted, acknowledged) = oneshot::channel();
        drop(acknowledged);
        registration
            .send(RegisterResponse {
                key: response_key(1),
                admitted,
            })
            .await
            .unwrap();
        drop(registration);
        drop(feeds);
        drop(peer);
        inbound
    };
    let (outcome, _inbound) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(Box::pin(drive(s.conn, Vec::new(), server, r.wiring)), body)
    })
    .await
    .expect("an answer nobody will feed must not keep the connection");
    assert!(
        matches!(
            outcome,
            Outcome::PeerClosed | Outcome::CoreClosed(CR_NORMAL)
        ),
        "{outcome:?}"
    );
    assert_eq!(
        seen(&s.seen)
            .iter()
            .filter(|call| matches!(call, Seen::Emit { piece: E_RESET, .. }))
            .count(),
        1,
        "the answer is stopped once, like any other"
    );
}

#[tokio::test]
async fn a_registration_for_a_stream_the_transport_never_announced_is_refused() {
    let s = scripted(Box::new(serving), None, false);
    let mut r = rig();
    let (registration, registrations) = mpsc::channel(1);
    r.wiring.registrations = registrations;
    let (peer, server) = tokio::io::duplex(64);
    let feeds = r.feeds;
    let body = async move {
        let (admitted, acknowledged) = oneshot::channel();
        registration
            .send(RegisterResponse {
                key: response_key(9),
                admitted,
            })
            .await
            .unwrap();
        let refused = acknowledged.await.unwrap().err();
        drop(feeds);
        drop(peer);
        refused
    };
    let (_outcome, refused) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(Box::pin(drive(s.conn, Vec::new(), server, r.wiring)), body)
    })
    .await
    .expect("refused at once");
    assert_eq!(refused, Some(ResponseStop::Integrity));
    assert!(
        !seen(&s.seen)
            .iter()
            .any(|call| matches!(call, Seen::Emit { .. })),
        "nothing is emitted for it"
    );
}

#[tokio::test]
async fn an_answer_is_whole_when_its_end_mark_is_out_and_the_engine_holds_the_last_piece() {
    use busbar_contract::response_delivery::DeliveryTerminal;
    let s = scripted(Box::new(serving), None, false);
    let mut r = rig();
    let (registration, registrations) = mpsc::channel(1);
    r.wiring.registrations = registrations;
    let (mut peer, server) = tokio::io::duplex(64);
    let mut inbound = r.inbound;
    let feeds = r.feeds;
    let close = r.close;
    let body = async move {
        peer.write_all(b"open").await.unwrap();
        assert_eq!(inbound.recv().await, Some(head(1)));
        let key = response_key(1);
        let (admitted, acknowledged) = oneshot::channel();
        registration
            .send(RegisterResponse { key, admitted })
            .await
            .unwrap();
        let handles = acknowledged.await.unwrap().unwrap();
        let (pieces, receiver) = mpsc::channel(1);
        feeds
            .send(Feed {
                stream: 1,
                pieces: receiver,
                opened: None,
            })
            .await
            .unwrap();
        pieces.send(piece(E_HEAD, b"head")).await.unwrap();
        pieces.send(piece(E_BODY, b"input")).await.unwrap();
        read_exactly(&mut peer, b"Hinput").await;
        // THE HOLD IS THE ENGINE'S: the owner has not given the end. Nothing the transport is
        // called with releases anything, and the answer is not whole however long it waits.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(handles.watch.snapshot().terminal, None);
        assert_eq!(handles.watch.record(), None);
        // The record is in: the owner gives the piece that completes the answer.
        handles.release.freeze(key, 1).unwrap();
        handles.release.publish(key, 1).unwrap();
        pieces.send(piece(E_END, b"")).await.unwrap();
        handles.input.producer_ended();
        read_exactly(&mut peer, b"E").await;
        let snapshot = handles.watch.terminal().await;
        assert_eq!(snapshot.terminal, Some(DeliveryTerminal::Complete));
        assert!(snapshot.first_payload_written);
        let record = handles.watch.record().expect("the delivery record");
        assert_eq!(
            (record.state, record.reason, record.body_bytes),
            ("whole", None, 5)
        );
        close.send(CR_NORMAL).unwrap();
        (peer, inbound, feeds, pieces)
    };
    let (outcome, _kept) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(Box::pin(drive(s.conn, Vec::new(), server, r.wiring)), body)
    })
    .await
    .expect("an answer makes progress with no release call");
    assert!(
        matches!(outcome, Outcome::CoreClosed(CR_NORMAL)),
        "{outcome:?}"
    );
    let calls = seen(&s.seen);
    assert!(
        calls.iter().all(|call| match call {
            Seen::Emit { piece, .. } => [E_HEAD, E_BODY, E_END, E_CLOSE].contains(piece),
            _ => true,
        }),
        "the transport is never called about delivery: {calls:?}"
    );
}

#[tokio::test]
async fn a_breach_of_the_output_model_writes_nothing_charges_the_instance_and_fails_every_open_answer(
) {
    // The transport claims an end the engine did not ask for (L5), with bytes before it.
    let s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Ingest(bytes) if bytes == b"open" => vec![Out::Head(1), Out::Head(3)],
            Seen::Emit {
                stream: 1,
                piece: E_BODY,
                ..
            } => vec![Out::Part(1, b"leak"), Out::WireEnd(1)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let mut r = rig();
    let (registration, registrations) = mpsc::channel(2);
    r.wiring.registrations = registrations;
    let (mut peer, server) = tokio::io::duplex(64);
    let mut inbound = r.inbound;
    let feeds = r.feeds;
    let body = async move {
        peer.write_all(b"open").await.unwrap();
        assert_eq!(inbound.recv().await, Some(head(1)));
        assert_eq!(inbound.recv().await, Some(head(3)));
        let mut owners = Vec::new();
        for stream in [1, 3] {
            let (admitted, acknowledged) = oneshot::channel();
            registration
                .send(RegisterResponse {
                    key: response_key(stream),
                    admitted,
                })
                .await
                .unwrap();
            owners.push(acknowledged.await.unwrap().unwrap());
        }
        let (pieces, receiver) = mpsc::channel(1);
        feeds
            .send(Feed {
                stream: 1,
                pieces: receiver,
                opened: None,
            })
            .await
            .unwrap();
        pieces.send(piece(E_BODY, b"body")).await.unwrap();
        let mut written = Vec::new();
        peer.read_to_end(&mut written).await.unwrap();
        let records: Vec<_> = owners
            .iter()
            .map(|owner| owner.watch.record().expect("frozen with the session"))
            .collect();
        (written, records, inbound, feeds, pieces)
    };
    let (outcome, (written, records, ..)) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(Box::pin(drive(s.conn, Vec::new(), server, r.wiring)), body)
    })
    .await
    .expect("a fault ends the session at once");
    assert!(
        matches!(outcome, Outcome::Ended(Ended::Fault(ref reason)) if *reason == GRAMMAR),
        "{outcome:?}"
    );
    assert!(written.is_empty(), "nothing of that answer is written");
    assert_eq!(
        s.charges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
        vec![GRAMMAR]
    );
    for record in records {
        assert_eq!(
            (record.state, record.reason),
            ("none", Some("transport_fault")),
            "every answer still open on the connection"
        );
    }
}

#[tokio::test]
async fn a_stream_the_engine_reset_that_the_transport_never_ends_closes_the_connection() {
    // The transport takes E_RESET and says nothing: after the write timeout the engine closes the
    // connection, which is the one way left to make the answer's verdict final.
    let s = scripted(
        Box::new(|call: &Seen| match call {
            Seen::Ingest(bytes) if bytes == b"open" => vec![Out::Head(1)],
            _ => Vec::new(),
        }),
        None,
        false,
    );
    let mut r = rig();
    r.wiring.write_timeout = Duration::from_millis(50);
    let (registration, registrations) = mpsc::channel(1);
    r.wiring.registrations = registrations;
    let (mut peer, server) = tokio::io::duplex(64);
    let mut inbound = r.inbound;
    let feeds = r.feeds;
    let body = async move {
        peer.write_all(b"open").await.unwrap();
        assert_eq!(inbound.recv().await, Some(head(1)));
        let (admitted, acknowledged) = oneshot::channel();
        registration
            .send(RegisterResponse {
                key: response_key(1),
                admitted,
            })
            .await
            .unwrap();
        let handles = acknowledged.await.unwrap().unwrap();
        handles.cancel.cancel(ResponseStop::Deadline);
        let snapshot = handles.watch.terminal().await;
        (
            snapshot,
            handles.watch.record(),
            peer,
            inbound,
            feeds,
            registration,
        )
    };
    let (outcome, (snapshot, record, ..)) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(Box::pin(drive(s.conn, Vec::new(), server, r.wiring)), body)
    })
    .await
    .expect("bounded by the write timeout");
    assert!(
        matches!(outcome, Outcome::CoreClosed(CR_NORMAL)),
        "{outcome:?}"
    );
    assert_eq!(
        snapshot.terminal,
        Some(busbar_contract::response_delivery::DeliveryTerminal::Failed(ResponseStop::Deadline))
    );
    let record = record.expect("its record");
    assert_eq!((record.state, record.reason), ("none", Some("deadline")));
    let calls = seen(&s.seen);
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, Seen::Emit { piece: E_RESET, .. }))
            .count(),
        1
    );
    assert_eq!(closes(&s.seen), 1);
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
                } => vec![Out::Echo(1, bytes.clone()), Out::Full(1)],
                Seen::Emit {
                    stream: 3,
                    piece: E_BODY,
                    bytes,
                    ..
                } => vec![Out::Echo(3, bytes.clone())],
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
                } => vec![Out::Echo(1, bytes.clone()), Out::Full(1)],
                Seen::Emit {
                    stream: 1,
                    piece: E_RESET,
                    ..
                } => vec![Out::Write(b"rst"), Out::Failed(1)],
                Seen::Emit {
                    stream: 3,
                    piece: E_BODY,
                    bytes,
                    ..
                } => vec![Out::Echo(3, bytes.clone())],
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

// ---- #102: the native listener's output-stall bound ----

/// A peer that stopped reading: reads never arrive, writes never progress.
struct StoppedReader;

impl AsyncRead for StoppedReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for StoppedReader {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

/// A slow-read peer: it accepts one byte per tick, forever, so every write makes progress.
struct Trickle {
    tick: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl Trickle {
    const EVERY: Duration = Duration::from_millis(20);

    fn new() -> Self {
        Self {
            tick: Box::pin(tokio::time::sleep(Self::EVERY)),
        }
    }
}

impl AsyncRead for Trickle {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Trickle {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match std::future::Future::poll(self.tick.as_mut(), cx) {
            Poll::Ready(()) => {
                let next = tokio::time::Instant::now() + Self::EVERY;
                self.tick.as_mut().reset(next);
                Poll::Ready(Ok(1))
            }
            Poll::Pending => Poll::Pending,
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

const STALL_BOUND: Duration = Duration::from_millis(300);
/// Scheduling slack only; the bound itself is asserted from below.
const STALL_SLACK: Duration = Duration::from_secs(3);

fn assert_stall_closed<S>(
    outcome: &Outcome<S>,
    elapsed: Duration,
    bound: Duration,
    dropped: &AtomicU64,
) {
    assert!(
        matches!(outcome, Outcome::Lost(e) if e.kind() == std::io::ErrorKind::TimedOut),
        "a stalled peer loses the connection with TimedOut"
    );
    assert!(elapsed >= bound, "the bound is not cut short: {elapsed:?}");
    assert!(
        elapsed < bound + STALL_SLACK,
        "the output stall is bounded: {elapsed:?}"
    );
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        1,
        "the connection handle, and with it the connection slot, is released"
    );
}

#[tokio::test]
async fn a_peer_that_stops_reading_is_closed_at_the_write_timeout() {
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    let mut r = rig();
    r.wiring.write_timeout = STALL_BOUND;
    s.conn
        .actions()
        .part(0, WIRE_CONTROL, &[0x5a; 4096])
        .expect("first write");
    let started = tokio::time::Instant::now();
    let outcome = drive(s.conn, Vec::new(), StoppedReader, r.wiring).await;
    assert_stall_closed(&outcome, started.elapsed(), STALL_BOUND, &s.dropped);
}

#[tokio::test]
async fn a_slow_reader_cannot_extend_the_write_deadline_with_partial_progress() {
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    let mut r = rig();
    r.wiring.write_timeout = STALL_BOUND;
    s.conn
        .actions()
        .part(0, WIRE_CONTROL, &[0x5a; 4096])
        .expect("first write");
    let started = tokio::time::Instant::now();
    // 4096 bytes at one byte per 20 ms would take over 80 s; every write makes progress, but
    // the deadline is absolute for the whole answer.
    let outcome = drive(s.conn, Vec::new(), Trickle::new(), r.wiring).await;
    assert_stall_closed(&outcome, started.elapsed(), STALL_BOUND, &s.dropped);
}

#[tokio::test]
async fn a_core_drain_close_to_a_stopped_reader_is_bounded_by_the_drain_grace() {
    let s = scripted(Box::new(|_| vec![Out::Write(b"goodbye")]), None, false);
    let mut r = rig();
    r.wiring.drain_grace = STALL_BOUND;
    r.close.send(CR_DRAIN).expect("drain");
    let started = tokio::time::Instant::now();
    let outcome = drive(s.conn, Vec::new(), StoppedReader, r.wiring).await;
    assert_stall_closed(&outcome, started.elapsed(), STALL_BOUND, &s.dropped);
}

// ---- THE EMIT PATH'S COST: core's pieces in, the framer's socket bytes out ----

/// The response head the cost framer writes for E_HEAD (a plausible HTTP/1 status line and headers).
static COST_HEAD: [u8; 128] = [b'h'; 128];

/// The cost framer: E_HEAD answers one WRITE of the head, E_BODY one WRITE of the piece's bytes, as a
/// content-length HTTP/1 framer does. Everything it answers is borrowed, so it allocates nothing.
fn cost_answer(call: Call<'_>, sink: &mut dyn FnMut(TransportOut<'_>)) {
    match call {
        Call::Emit { piece: E_HEAD, .. } => sink(control(&COST_HEAD)),
        Call::Emit {
            piece: E_BODY,
            bytes,
            ..
        } => sink(control(bytes)),
        _ => {}
    }
}

/// A socket that takes every byte at once and counts them.
struct CountingSink(Arc<AtomicU64>);

impl AsyncRead for CountingSink {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for CountingSink {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Poll::Ready(Ok(bytes.len()))
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

/// What one shape of response costs on the emit path, per response, after warm-up.
#[derive(Debug)]
struct EmitCost {
    records: usize,
    allocations_min: u64,
    allocations_max: u64,
    wipes: f64,
    median_ns: u64,
    bytes: u64,
}

/// Drives `rounds` responses (E_HEAD, then `pieces` E_BODY of `body`) through the session's emit path:
/// `TransportConn::emit` (the framer's answer captured) and the task's `apply` (its bytes written),
/// exactly as `drive` does for each piece it pulls from a feed.
fn emit_cost(body: &[u8], pieces: usize, rounds: usize) -> EmitCost {
    use futures::FutureExt;
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    if let Some(Backend::Script(script)) = s.conn.backend.as_mut() {
        script.lean = Some(cost_answer);
    }
    let r = rig();
    let written = Arc::new(AtomicU64::new(0));
    let carrier = crate::raw_progress::test_carrier(CountingSink(Arc::clone(&written)));
    let progress = carrier.progress();
    let mut io = DeliveryIo::new(carrier, Delivery::new(r.wiring.delivery, progress));
    let mut task = Task::new();
    let timeout = Duration::from_secs(5);
    let mut one = |conn: &mut TransportConn, piece: u32, bytes: &[u8]| {
        let now = Instant::now();
        conn.emit(1, piece, 0, bytes, now).expect("emit");
        let mut clock = None;
        let flow = task
            .apply(conn.actions(), &mut io, timeout, &mut clock)
            .now_or_never()
            .expect("an always-ready socket");
        assert!(matches!(flow, Flow::Go));
    };
    let mut response = |conn: &mut TransportConn| {
        one(conn, E_HEAD, &[]);
        for _ in 0..pieces {
            one(conn, E_BODY, body);
        }
    };
    for _ in 0..(rounds / 10).max(10) {
        response(&mut s.conn);
    }
    let mut times = Vec::with_capacity(rounds);
    let mut allocations = Vec::with_capacity(rounds);
    let wipes_before = busbar_contract::secure::wipe_counts().1;
    for _ in 0..rounds {
        let at = std::time::Instant::now();
        let ((), n) = crate::support::allocations_during(|| response(&mut s.conn));
        times.push(u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX));
        allocations.push(n);
    }
    let wipes = busbar_contract::secure::wipe_counts().1 - wipes_before;
    times.sort();
    drop(response);
    EmitCost {
        records: 1 + pieces,
        allocations_min: allocations.iter().copied().min().unwrap_or(0),
        allocations_max: allocations.iter().copied().max().unwrap_or(0),
        wipes: wipes as f64 / rounds as f64,
        median_ns: times[times.len() / 2],
        bytes: written.load(Ordering::Relaxed),
    }
}

/// THE MEASUREMENT (N1): time and heap allocations per response and per answer record on the emit path,
/// for a small response (one head, one 1 KiB body piece) and a streamed one (one head, 50 pieces of 200
/// bytes). `B_SESSION_EMIT_ROUNDS` sets the responses timed (default 200); run it in release with
/// `--nocapture` for the numbers. Same thread, same allocator as every lib test (the counting one).
#[tokio::test]
async fn the_emit_path_cost_per_answer_record() {
    let rounds = std::env::var("B_SESSION_EMIT_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    for (label, body, pieces) in [
        ("small (head + 1 x 1024 B)", [0x42u8; 1024].as_slice(), 1),
        ("streamed (head + 50 x 200 B)", [0x42u8; 200].as_slice(), 50),
    ] {
        let cost = emit_cost(body, pieces, rounds);
        let per_record = cost.median_ns as f64 / cost.records as f64;
        println!(
            "SESSION-EMIT {label}: {} records; median {} ns per response, {per_record:.0} ns per record; \
             allocations per response {}..={} ({:.2} per record); buffer wipes per response {:.2}; \
             {} bytes written",
            cost.records,
            cost.median_ns,
            cost.allocations_min,
            cost.allocations_max,
            cost.allocations_max as f64 / cost.records as f64,
            cost.wipes,
            cost.bytes,
        );
        let expected = (rounds + (rounds / 10).max(10)) as u64
            * (COST_HEAD.len() + body.len() * pieces) as u64;
        assert_eq!(cost.bytes, expected, "every byte reached the socket");
    }
}

// ---- CUSTODY OF THE SESSION'S OUTPUT BUFFER ----

/// A response head carrying a credential, as a framer writes it.
const OUTPUT_SECRET: &[u8] = b"HTTP/1.1 200 OK\r\nset-cookie: session=s3cr3t-0042\r\n\r\n";

/// A session charged to `account`'s Data storage whose first answer writes [`OUTPUT_SECRET`]; with the
/// address and extent of the output block that holds it.
fn custody_session(
    account: &Arc<busbar_kernel::limits::process_admission::ProcessAdmission>,
) -> (Scripted, *const u8, usize) {
    use busbar_kernel::limits::process_admission::AdmissionClass;
    let source = account.connection_storage(AdmissionClass::Data);
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    s.conn.answers = Answers::with_source(None, Instant::now(), source).expect("owner");
    s.conn
        .actions()
        .part(0, WIRE_CONTROL, OUTPUT_SECRET)
        .expect("head");
    let block = s.conn.actions().out.allocation().expect("block");
    let (pointer, len) = (block.as_ptr(), block.len());
    (s, pointer, len)
}

fn custody_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn a_finished_session_frees_its_output_buffer_zeroed_and_returns_its_account_to_the_start() {
    use busbar_kernel::limits::process_admission::ProcessAdmission;
    let account = ProcessAdmission::with_limits(2, 1 << 20, 512);
    let (mut s, pointer, len) = custody_session(&account);
    s.conn
        .actions()
        .push(Act::Close { abort: false })
        .expect("close");
    let r = rig();
    let written = Arc::new(AtomicU64::new(0));
    let sink = CountingSink(Arc::clone(&written));
    let runtime = custody_runtime();
    let (closed, wiped, _) = crate::support::observe_wipe(pointer, len, || {
        let outcome = runtime.block_on(drive(s.conn, Vec::new(), sink, r.wiring));
        matches!(outcome, Outcome::Closed)
    });
    assert!(closed, "the framer's CLOSE ended the session");
    assert_eq!(written.load(Ordering::Relaxed), OUTPUT_SECRET.len() as u64);
    assert_eq!(
        wiped,
        Some(true),
        "the freed block held no byte of the response head"
    );
    assert_eq!(account.used(), (0, 0), "every charge returned");
}

#[test]
fn a_session_dropped_mid_write_frees_its_output_buffer_zeroed_and_returns_its_account() {
    use busbar_kernel::limits::process_admission::ProcessAdmission;
    let account = ProcessAdmission::with_limits(2, 1 << 20, 512);
    let (s, pointer, len) = custody_session(&account);
    let r = rig();
    let runtime = custody_runtime();
    let (cut, wiped, _) = crate::support::observe_wipe(pointer, len, || {
        runtime.block_on(async {
            // The socket takes three bytes, then nothing: the task is dropped while it writes.
            let driven = drive(s.conn, Vec::new(), PartialWriteThenPending(false), r.wiring);
            tokio::time::timeout(Duration::from_millis(50), driven)
                .await
                .is_err()
        })
    });
    assert!(cut, "the session was still writing when it was dropped");
    assert_eq!(
        wiped,
        Some(true),
        "the unwritten head was wiped before the free"
    );
    assert_eq!(account.used(), (0, 0), "every charge returned");
    assert_eq!(s.dropped.load(Ordering::Relaxed), 1);
}

/// A socket that takes three bytes and then fails.
struct BreaksAfterThree(bool);

impl AsyncRead for BreaksAfterThree {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for BreaksAfterThree {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.0 {
            Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
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
async fn a_write_that_fails_mid_record_wipes_the_output_before_the_answer_is_let_go() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let account = ProcessAdmission::with_limits(2, 1 << 20, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let r = rig();
    let carrier = crate::raw_progress::test_carrier(BreaksAfterThree(false));
    let progress = carrier.progress();
    let mut io = DeliveryIo::new(carrier, Delivery::new(r.wiring.delivery, progress));
    let mut task = Task::new();
    let mut acts = Actions::new(&source).expect("owner");
    acts.part(0, WIRE_CONTROL, OUTPUT_SECRET).expect("head");
    acts.part(0, WIRE_CONTROL, b"and the body").expect("body");
    let flow = task
        .apply(&mut acts, &mut io, Duration::from_secs(1), &mut None)
        .await;
    assert!(matches!(flow, Flow::Lost(ref e) if e.kind() == std::io::ErrorKind::BrokenPipe));
    // The session still owns the buffer; it is already all zero, not waiting for the session's drop.
    assert!(acts.is_empty());
    let block = acts.out.allocation().expect("kept for the session");
    assert!(block.iter().all(|byte| *byte == 0));
    // Nor does the connection's queue keep what the socket did not take.
    assert!(io.ledger().unwritten().is_empty());
    drop((acts, io));
    assert_eq!(account.used(), (0, 0), "every charge returned");
}

/// Partial socket writes over several records: one byte at a time, and nothing then everything, put
/// the same bytes on the wire in the same order as a socket that takes each record whole.
#[tokio::test]
async fn partial_socket_writes_resume_the_run_where_the_socket_stopped() {
    /// Takes `step` bytes per write (0 = nothing, then on the next poll everything).
    struct Partial {
        wire: Arc<Mutex<Vec<u8>>>,
        step: usize,
        refused: bool,
    }
    impl AsyncWrite for Partial {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let take = if self.step == 0 {
                if !self.refused {
                    self.refused = true;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.refused = false;
                bytes.len()
            } else {
                bytes.len().min(self.step)
            };
            self.wire
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&bytes[..take]);
            Poll::Ready(Ok(take))
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
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let source = ProcessAdmission::new(1).connection_storage(AdmissionClass::Data);
    let records: [&[u8]; 3] = [b"HTTP/1.1 200 OK\r\n\r\n", b"first piece|", b"second"];
    for step in [1, 0] {
        let mut acts = Actions::new(&source).expect("owner");
        for record in records {
            acts.part(0, WIRE_CONTROL, record).expect("record");
        }
        acts.push(Act::NoNewStreams)
            .expect("a non-byte act between");
        acts.part(0, WIRE_CONTROL, b"|after").expect("record");
        let wire = Arc::new(Mutex::new(Vec::new()));
        let carrier = crate::raw_progress::test_carrier(Partial {
            wire: Arc::clone(&wire),
            step,
            refused: false,
        });
        let progress = carrier.progress();
        let mut io = DeliveryIo::new(
            carrier,
            Delivery::new(DeliveryLedger::default(), Arc::clone(&progress)),
        );
        let flow = Task::new()
            .apply(&mut acts, &mut io, Duration::from_secs(1), &mut None)
            .await;
        assert!(matches!(flow, Flow::Go), "step {step}");
        assert_eq!(
            *wire.lock().unwrap_or_else(PoisonError::into_inner),
            b"HTTP/1.1 200 OK\r\n\r\nfirst piece|second|after",
            "step {step}"
        );
        assert!(io.ledger().unwritten().is_empty(), "step {step}");
        assert_eq!(
            progress.snapshot().written_plaintext,
            43,
            "step {step}: the carrier's own count of what it took"
        );
        let block = acts.out.allocation().expect("block");
        assert!(
            block.iter().all(|byte| *byte == 0),
            "step {step}: the session's copy was wiped when the run was queued"
        );
    }
}

// ---- WHAT AN ACCEPTED CONNECTION MAKES (owner's allocation ruling; v1.5.5 made nothing of its own) ----

/// The delivery ledger root makes for every accepted connection (`root/listener_native.rs`, `open`).
fn accepted_ledger() -> DeliveryLedger {
    DeliveryLedger::default()
}

/// A plain request and the response a framer writes for it.
const HEALTHZ_REQUEST: &[u8] = b"GET /healthz HTTP/1.1\r\nhost: 127.0.0.1:18170\r\n\r\n";
const HEALTHZ_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

/// A framer that answers a request's bytes with the response and CLOSE, from statics.
fn answer_and_close(call: Call<'_>, sink: &mut dyn FnMut(TransportOut<'_>)) {
    if matches!(call, Call::Ingest(bytes) if !bytes.is_empty()) {
        sink(control(HEALTHZ_RESPONSE));
        sink(TransportOut::Close { abort: false });
    }
}

/// A framer that answers nothing.
fn answer_nothing(_: Call<'_>, _: &mut dyn FnMut(TransportOut<'_>)) {}

type Carrier = crate::raw_progress::RawCarrier<tokio::io::DuplexStream>;
type Driven = std::pin::Pin<Box<dyn std::future::Future<Output = Outcome<Carrier>>>>;

/// Everything an accepted connection's session is driven with except core's own state, made before
/// anything is counted or timed (these are the test's, or root's channels): a lean framer whose
/// answers allocate nothing, a socket pair, and the channels root keeps open.
struct AcceptParts {
    conn: TransportConn,
    io: Carrier,
    peer: tokio::io::DuplexStream,
    counters: Arc<SessionCounters>,
    registrations: mpsc::Receiver<RegisterResponse>,
    feeds: mpsc::Receiver<Feed>,
    inbound: mpsc::Sender<Inbound>,
    close: oneshot::Receiver<u32>,
    kept: Kept,
    /// The housekeeping tick's list, as a listener would pass it.
    holders: Arc<ReadHolders>,
}

/// Root's ends of the channels, kept open while the session runs.
struct Kept {
    _register: mpsc::Sender<RegisterResponse>,
    _feeds: mpsc::Sender<Feed>,
    _inputs: mpsc::Receiver<Inbound>,
    _close: oneshot::Sender<u32>,
    peer: tokio::io::DuplexStream,
}

fn accept_parts(lean: fn(Call<'_>, &mut dyn FnMut(TransportOut<'_>))) -> AcceptParts {
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    if let Some(Backend::Script(script)) = s.conn.backend.as_mut() {
        script.lean = Some(lean);
    }
    let (peer, server) = tokio::io::duplex(4096);
    let (register, registrations) = mpsc::channel(1);
    let (feed, feeds) = mpsc::channel(1);
    let (inbound, inputs) = mpsc::channel(1);
    let (close_tx, close) = oneshot::channel();
    let (unused_peer, _) = tokio::io::duplex(1);
    AcceptParts {
        conn: s.conn,
        io: crate::raw_progress::test_carrier(server),
        peer,
        counters: Arc::default(),
        registrations,
        feeds,
        inbound,
        close,
        kept: Kept {
            _register: register,
            _feeds: feed,
            _inputs: inputs,
            _close: close_tx,
            peer: unused_peer,
        },
        holders: Arc::default(),
    }
}

impl AcceptParts {
    /// The session's task over these parts and `delivery`, boxed as a spawn would (the box is the task's
    /// own block, not core's state); root's ends and the peer come back to be kept.
    fn task(self, delivery: DeliveryLedger) -> (Driven, Kept) {
        let progress = self.io.progress();
        let wiring = Wiring {
            delivery,
            registrations: self.registrations,
            feeds: self.feeds,
            inbound: self.inbound,
            close: self.close,
            write_timeout: Duration::from_secs(5),
            drain_grace: Duration::from_secs(5),
            counters: self.counters,
            read_holders: Some(self.holders),
        };
        let driven: Driven = Box::pin(super::drive(self.conn, self.io, progress, wiring));
        let mut kept = self.kept;
        kept.peer = self.peer;
        (driven, kept)
    }
}

/// THE RED-BEFORE-GREEN PROOF (owner's allocation ruling): an accepted connection that has sent nothing
/// has made nothing of core's: the ledger root makes at accept and the session's task, run until it
/// waits for the first byte, ask the heap for no block and no byte (so none is zero-filled). Then input
/// that arrives in a burst makes the read block, which the connection keeps across the housekeeping
/// tick that saw bytes, and lets go (wiped) at the first tick that saw none (the one keep-or-release
/// rule). A request after that is served.
#[test]
fn an_accepted_connection_waiting_for_its_first_byte_has_made_nothing() {
    use futures::FutureExt;
    let runtime = custody_runtime();
    let _entered = runtime.enter();
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    // The first round warms this thread's own runtime state; the second is counted.
    for counted in [false, true] {
        let parts = accept_parts(answer_nothing);
        let holders = Arc::clone(&parts.holders);
        let (ledger, ledger_calls, ledger_bytes) = crate::support::heap_during(accepted_ledger);
        let (mut driven, mut kept) = parts.task(ledger);
        let (parked, calls, bytes) = crate::support::heap_during(|| driven.as_mut().poll(&mut cx));
        assert!(parked.is_pending(), "it waits for the first byte");
        if counted {
            assert_eq!(
                (ledger_calls, ledger_bytes, calls, bytes),
                (0, 0, 0, 0),
                "heap calls and bytes of the accepted ledger, then of the session until it waits"
            );
        }
        // A burst: more than the task's own room (512 bytes), so the read block is made.
        let send = |peer: &mut tokio::io::DuplexStream, bytes: &[u8]| {
            peer.write_all(bytes)
                .now_or_never()
                .expect("room in the pipe")
                .expect("written");
        };
        send(&mut kept.peer, &[b'x'; 600]);
        assert!(driven.as_mut().poll(&mut cx).is_pending());
        assert_eq!(holders.len(), 1, "the connection holds a read block");
        let with_block = crate::support::held_bytes();
        assert_eq!(holders.walk(), 0, "a tick that saw bytes keeps it");
        assert!(driven.as_mut().poll(&mut cx).is_pending());
        assert_eq!(holders.walk(), 1, "a tick that saw none asks for it");
        assert!(driven.as_mut().poll(&mut cx).is_pending());
        if counted {
            assert_eq!(
                with_block - crate::support::held_bytes(),
                READ_CHUNK as isize,
                "the read block is gone"
            );
        }
        assert!(holders.is_empty());
        // Still served: a small request needs no block.
        send(&mut kept.peer, b"GET / HTTP/1.1\r\n\r\n");
        let (served, calls, _) = crate::support::heap_during(|| driven.as_mut().poll(&mut cx));
        assert!(served.is_pending());
        if counted {
            assert_eq!(calls, 0, "a small request after release makes nothing");
        }
        drop((driven, kept));
    }
}

/// The read block: never zero-filled, never reallocated (1 MiB read through it, same block), and
/// every byte reads wrote in it (a reader that writes and then waits included) is zero when it is
/// freed. The task's own room uses the same one-store wipe over the same high-water count.
#[test]
fn a_read_block_never_reallocates_and_is_freed_wiped_over_what_reads_wrote() {
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let mut s = scripted(Box::new(|_| Vec::new()), None, false);
    if let Some(Backend::Script(script)) = s.conn.backend.as_mut() {
        script.lean = Some(answer_nothing);
    }
    let mut room = ReadRoom::new(s.conn.storage().clone(), None);
    let mut clock = None;
    let full = [b'k'; FIRST_READ];
    let mut input: &[u8] = &full;
    let read = room.poll_ingest(&mut input, &mut s.conn, &mut clock, &mut cx);
    assert!(matches!(read, Poll::Ready(Ok(Ingested { eof: false, .. }))));
    assert_eq!(room.first_used, FIRST_READ);
    let block = room
        .block
        .as_mut()
        .expect("a full first read makes the block");
    let (pointer, capacity) = (
        block.bytes.spare_capacity_mut().as_ptr().cast::<u8>(),
        block.bytes.capacity(),
    );
    let big = vec![b'z'; 1 << 20];
    let mut input: &[u8] = &big;
    while !input.is_empty() {
        let read = room.poll_ingest(&mut input, &mut s.conn, &mut clock, &mut cx);
        assert!(matches!(read, Poll::Ready(Ok(Ingested { eof: false, .. }))));
    }
    let block = room.block.as_mut().expect("kept while reads find bytes");
    assert_eq!(
        (
            block.bytes.spare_capacity_mut().as_ptr().cast::<u8>(),
            block.bytes.capacity(),
            block.bytes.len()
        ),
        (pointer, capacity, 0),
        "the same block, never grown, never holding a length"
    );
    assert_eq!(block.used, READ_CHUNK);
    assert!(room
        .poll_ingest(&mut PendingRead, &mut s.conn, &mut clock, &mut cx)
        .is_pending());
    let ((), wiped, _) = crate::support::observe_wipe(pointer, READ_CHUNK, || room.release());
    assert_eq!(wiped, Some(true), "the freed block holds no byte read");
    assert_eq!(room.first_used, 0, "the task's own room was wiped with it");
}

/// THE MEASUREMENT: per accepted connection, core's share (the ledger root makes and the session's
/// task; the framer is a lean script, the transport plugin's own work is not in it): heap calls and
/// bytes, the time to "waiting for the first byte" and its close, the time of open + one request +
/// close, on one thread and on eight, and what 1,000 idle connections hold. `B_ACCEPT_ROUNDS` sets
/// the units timed (default 2,000). Run in release with `--nocapture` for the numbers; it asserts
/// only that every unit did what it says.
#[test]
fn the_accept_path_cost() {
    let rounds: usize = std::env::var("B_ACCEPT_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let one = accept_units(rounds);
    println!(
        "ACCEPT-OPEN 1 thread: median {} ns open, {} ns close; heap per open {} calls, {} bytes; \
         task state {} bytes",
        one.open_ns, one.close_ns, one.open_calls, one.open_bytes, one.task_bytes
    );
    println!(
        "ACCEPT-REQUEST 1 thread: median {} ns open + request + close; heap {} calls, {} bytes",
        one.request_ns, one.request_calls, one.request_bytes
    );
    let eight: Vec<AcceptCost> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| accept_units(rounds)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect()
    });
    let mut opens: Vec<u64> = eight.iter().map(|cost| cost.open_ns).collect();
    let mut requests: Vec<u64> = eight.iter().map(|cost| cost.request_ns).collect();
    opens.sort();
    requests.sort();
    println!(
        "ACCEPT-OPEN 8 threads: per-thread medians {opens:?} ns; ACCEPT-REQUEST 8 threads: {requests:?} ns"
    );
    let held = idle_held(1_000);
    println!(
        "ACCEPT-IDLE 1000 held: core's heap {} bytes per connection; process resident {} KiB in all \
         (the test's sockets and channels included)",
        held.0, held.1
    );
    for size in [64, 2_000] {
        let (most, ns) = keepalive_cost(size, rounds.min(20_000));
        println!(
            "ACCEPT-KEEPALIVE {size}-byte requests, 1 thread: per request after the first, heap calls \
             at most {most}, median {ns} ns"
        );
    }
    for size in [64, 2_000] {
        println!(
            "ACCEPT-IDLE-AFTER {size}-byte request, then two ticks with no bytes: core's heap still held \
             {} bytes per connection",
            held_after_request(size)
        );
    }
    let (keep_ns, release_ns) = walk_cost(10_000);
    println!(
        "TICK-WALK 10000 connections holding a read block: {keep_ns} ns for a walk that keeps all, \
         {release_ns} ns for one that asks all back"
    );
    let (first, rest, per_call, fill) = pool_cost(rounds);
    println!(
        "POOL (plugin interface, frozen): a thread's first crossing {} calls, {} bytes (kept by the \
         thread); each crossing after: {} calls, median {} ns for its two lent buffers; the lease's \
         4 KiB zero-fill alone median {} ns",
        first.0, first.1, rest, per_call, fill
    );
}

/// A request of `size` bytes whose last byte is `\n`.
fn request_of(size: usize) -> Vec<u8> {
    let mut request = vec![b'r'; size];
    if let Some(last) = request.last_mut() {
        *last = b'\n';
    }
    request
}

/// A framer that answers each request with the response once its last byte (`\n`) arrives, however
/// many reads the request took (no CLOSE: kept alive).
fn answer_kept_alive(call: Call<'_>, sink: &mut dyn FnMut(TransportOut<'_>)) {
    if matches!(call, Call::Ingest(bytes) if bytes.last() == Some(&b'\n')) {
        sink(control(HEALTHZ_RESPONSE));
    }
}

/// `rounds` requests of `size` bytes on one kept-alive connection: the most heap calls any request
/// after the first made in core (read, ingest, answer, write, flush, wipe), and the median time.
fn keepalive_cost(size: usize, rounds: usize) -> (u64, u64) {
    use futures::FutureExt;
    use tokio::io::AsyncReadExt as _;
    let runtime = custody_runtime();
    let _entered = runtime.enter();
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let parts = accept_parts(answer_kept_alive);
    let holders = Arc::clone(&parts.holders);
    let (mut driven, mut kept) = parts.task(accepted_ledger());
    let request = request_of(size);
    let mut answer = [0u8; 256];
    let (mut most, mut times) = (0, Vec::with_capacity(rounds));
    for round in 0..=rounds {
        kept.peer
            .write_all(&request)
            .now_or_never()
            .expect("room in the pipe")
            .expect("written");
        let at = std::time::Instant::now();
        let (polled, calls) = crate::support::allocations_during(|| driven.as_mut().poll(&mut cx));
        let took = nanos(at);
        assert!(polled.is_pending(), "kept alive");
        let got = kept
            .peer
            .read(&mut answer)
            .now_or_never()
            .expect("answered")
            .expect("read");
        assert_eq!(&answer[..got], HEALTHZ_RESPONSE);
        if round > 0 {
            most = most.max(calls);
            times.push(took);
        }
        // Traffic keeps arriving between ticks: the tick keeps the block.
        holders.walk();
    }
    drop((driven, kept));
    (most, median(times))
}

/// One connection that carried one request of `size` bytes and then went quiet for two ticks: the
/// heap core still holds for it (the task's own box, a spawn's block, not counted).
fn held_after_request(size: usize) -> isize {
    use futures::FutureExt;
    use tokio::io::AsyncReadExt as _;
    let runtime = custody_runtime();
    let _entered = runtime.enter();
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let mut parts = accept_parts(answer_kept_alive);
    let holders = Arc::clone(&parts.holders);
    parts
        .peer
        .write_all(&request_of(size))
        .now_or_never()
        .expect("room in the pipe")
        .expect("written");
    let mut answer = [0u8; 256];
    let start = crate::support::held_bytes();
    let (mut driven, mut kept) = parts.task(accepted_ledger());
    let task_box = isize::try_from(std::mem::size_of_val(&*driven)).unwrap_or(isize::MAX);
    assert!(driven.as_mut().poll(&mut cx).is_pending());
    let got = kept
        .peer
        .read(&mut answer)
        .now_or_never()
        .expect("answered")
        .expect("read");
    assert_eq!(&answer[..got], HEALTHZ_RESPONSE);
    holders.walk();
    holders.walk();
    assert!(driven.as_mut().poll(&mut cx).is_pending());
    let held = crate::support::held_bytes() - start - task_box;
    drop((driven, kept));
    held
}

/// The housekeeping tick's walk over `count` connections that hold a read block: one walk that
/// keeps them all (each saw bytes), then one that asks them all back (none did).
fn walk_cost(count: usize) -> (u64, u64) {
    let holders = ReadHolders::default();
    let keeps: Vec<Arc<ReadKeep>> = (0..count).map(|_| Arc::default()).collect();
    for keep in &keeps {
        keep.active.store(true, Ordering::Relaxed);
        holders.hold(keep);
    }
    let at = std::time::Instant::now();
    assert_eq!(holders.walk(), 0);
    let keep_ns = nanos(at);
    let at = std::time::Instant::now();
    assert_eq!(holders.walk(), count);
    let release_ns = nanos(at);
    assert!(keeps
        .iter()
        .all(|keep| keep.release.load(Ordering::Relaxed)));
    (keep_ns, release_ns)
}

/// The frozen interface's per-crossing buffers (`busbar-plugin-abi` `host_side::pool::sync_bufs`, what
/// every transport `begin`, `ingest`, `emit` and `close` goes through), on a fresh thread: its first
/// crossing's heap, then per crossing writing a response-sized answer; and the 4 KiB `fill(0)` the
/// lease does on every call (`busbar-ffi` `OutLease::new`), timed alone.
fn pool_cost(rounds: usize) -> ((u64, u64), u64, u64, u64) {
    use busbar_plugin_abi::host_side::pool::sync_bufs;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let cross = || {
                    sync_bufs(1 << 20, |_args, out| {
                        out.put_bytes(HEALTHZ_RESPONSE).expect("room");
                    });
                };
                let ((), calls, bytes) = crate::support::heap_during(cross);
                let mut most = 0;
                let mut times = Vec::with_capacity(rounds);
                for _ in 0..rounds {
                    let at = std::time::Instant::now();
                    let ((), n) = crate::support::allocations_during(cross);
                    times.push(nanos(at));
                    most = most.max(n);
                }
                let mut block = vec![0u8; 4096];
                let mut fills = Vec::with_capacity(rounds);
                for _ in 0..rounds {
                    let at = std::time::Instant::now();
                    block.fill(0);
                    std::hint::black_box(&block);
                    fills.push(nanos(at));
                }
                ((calls, bytes), most, median(times), median(fills))
            })
            .join()
            .expect("pool thread")
    })
}

struct AcceptCost {
    open_ns: u64,
    close_ns: u64,
    open_calls: u64,
    open_bytes: u64,
    task_bytes: usize,
    request_ns: u64,
    request_calls: u64,
    request_bytes: u64,
}

fn median(mut times: Vec<u64>) -> u64 {
    times.sort();
    times.get(times.len() / 2).copied().unwrap_or(0)
}

fn nanos(at: std::time::Instant) -> u64 {
    u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// `rounds` opens (parked at the first byte, then closed by dropping, as a peer that never sends does)
/// and `rounds` open + request + close, on this thread, after a tenth as warm-up.
fn accept_units(rounds: usize) -> AcceptCost {
    use futures::FutureExt;
    let runtime = custody_runtime();
    let _entered = runtime.enter();
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let warm = (rounds / 10).max(10);
    let (mut open, mut close, mut request) = (Vec::new(), Vec::new(), Vec::new());
    let (mut open_heap, mut request_heap) = ((0, 0), (0, 0));
    for round in 0..warm + rounds {
        let parts = accept_parts(answer_nothing);
        let at = std::time::Instant::now();
        let (ledger, calls, bytes) = crate::support::heap_during(accepted_ledger);
        let (mut driven, kept) = parts.task(ledger);
        let (parked, more_calls, more_bytes) =
            crate::support::heap_during(|| driven.as_mut().poll(&mut cx));
        let opened = nanos(at);
        assert!(parked.is_pending());
        let at = std::time::Instant::now();
        drop(driven);
        let closed = nanos(at);
        drop(kept);
        let mut parts = accept_parts(answer_and_close);
        parts
            .peer
            .write_all(HEALTHZ_REQUEST)
            .now_or_never()
            .expect("room in the pipe")
            .expect("written");
        let at = std::time::Instant::now();
        let (ledger, r_calls, r_bytes) = crate::support::heap_during(accepted_ledger);
        let (mut served, kept) = parts.task(ledger);
        let (outcome, r_more_calls, r_more_bytes) =
            crate::support::heap_during(|| served.as_mut().poll(&mut cx));
        drop(served);
        let answered = nanos(at);
        assert!(
            matches!(outcome, Poll::Ready(Outcome::Closed)),
            "{outcome:?}"
        );
        drop(kept);
        if round >= warm {
            open.push(opened);
            close.push(closed);
            request.push(answered);
            open_heap = (calls + more_calls, bytes + more_bytes);
            request_heap = (r_calls + r_more_calls, r_bytes + r_more_bytes);
        }
    }
    let (task, kept) = accept_parts(answer_nothing).task(accepted_ledger());
    let task_bytes = std::mem::size_of_val(&*task);
    drop((task, kept));
    AcceptCost {
        open_ns: median(open),
        close_ns: median(close),
        open_calls: open_heap.0,
        open_bytes: open_heap.1,
        task_bytes,
        request_ns: median(request),
        request_calls: request_heap.0,
        request_bytes: request_heap.1,
    }
}

/// `count` connections opened and left waiting for their first byte: core's heap bytes kept per
/// connection (asked while opening, nothing freed before it waits), and the process's resident
/// growth in KiB over all of them, the test's own parts included.
fn idle_held(count: usize) -> (u64, u64) {
    let runtime = custody_runtime();
    let _entered = runtime.enter();
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let resident = || {
        std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
            .map_or(0, |pages| pages * 4)
    };
    let before = resident();
    let mut held = Vec::with_capacity(count);
    let mut core = 0;
    for _ in 0..count {
        let parts = accept_parts(answer_nothing);
        let (ledger, _, bytes) = crate::support::heap_during(accepted_ledger);
        let (mut driven, kept) = parts.task(ledger);
        let (parked, _, more) = crate::support::heap_during(|| driven.as_mut().poll(&mut cx));
        assert!(parked.is_pending());
        core += bytes + more;
        held.push((driven, kept));
    }
    let grown = resident().saturating_sub(before);
    drop(held);
    (core / count as u64, grown)
}

// ---- credit for a stream the engine has left (one mechanism, both roles) ----

/// One late body piece of the stream the engine left: a quarter of the connection window below.
static LATE: [u8; 64] = [7; 64];

/// A framer over a far end that keeps to the windows the session stated (64 a stream, 256 the
/// connection) and reopens them by the engine's credit and by nothing else, as a multiplexing
/// transport does. Each byte it ingests is one event of the far end: `O` opens streams 1 and 3,
/// `L` is a late 64-byte body piece on stream 1, `V` is five body bytes on stream 3. A piece the
/// far end has no window for is never sent: the framer hands nothing up for it.
fn windowed(credits: Credits) -> Respond {
    let mut window: u64 = 256;
    let mut read = 0;
    Box::new(move |call: &Seen| {
        {
            let credits = credits.lock().unwrap_or_else(PoisonError::into_inner);
            for &(_, count) in &credits[read..] {
                window += count;
            }
            read = credits.len();
        }
        match call {
            Seen::Ingest(bytes) => {
                let mut outs = Vec::new();
                for byte in bytes {
                    match byte {
                        b'O' => outs.extend([Out::Head(1), Out::Head(3)]),
                        b'L' if window >= 64 => {
                            window -= 64;
                            outs.push(Out::Body(1, &LATE));
                        }
                        b'V' if window >= 5 => {
                            window -= 5;
                            outs.push(Out::Body(3, b"alive"));
                        }
                        _ => {}
                    }
                }
                outs
            }
            Seen::Emit {
                stream,
                piece: E_RESET,
                ..
            } => vec![Out::Failed(*stream)],
            _ => Vec::new(),
        }
    })
}

/// ENGINE-OPEN-2 row 2. The engine resets one stream of an accepted connection that multiplexes;
/// the caller's body for it was already on its way and keeps arriving: ten pieces, two and a half
/// times the connection window. Nobody reads them, so the engine owes the credit for every byte at
/// once (`Outcome::left`, as the dial side gives it). Without it the far end's connection window
/// closes after four pieces and the other stream of the connection never receives again.
#[tokio::test]
async fn a_reset_stream_s_late_body_does_not_close_the_window_of_an_accepted_connection() {
    let credits = Credits::default();
    let s = scripted_stating(
        windowed(Arc::clone(&credits)),
        None,
        false,
        records::Session::stated(true, 64, 256),
        Arc::clone(&credits),
    );
    let mut r = rig();
    let (registration, registrations) = mpsc::channel(1);
    r.wiring.registrations = registrations;
    let (mut peer, server) = tokio::io::duplex(64);
    let mut inbound = r.inbound;
    let feeds = r.feeds;
    let body = async move {
        peer.write_all(b"O").await.unwrap();
        assert_eq!(inbound.recv().await, Some(head(1)));
        assert_eq!(inbound.recv().await, Some(head(3)));
        let (admitted, acknowledged) = oneshot::channel();
        registration
            .send(RegisterResponse {
                key: response_key(1),
                admitted,
            })
            .await
            .unwrap();
        let handles = acknowledged.await.unwrap().unwrap();
        // The owner stops its answer: E_RESET, the transport's end mark, the verdict. The engine has
        // left stream 1.
        handles.cancel.cancel(ResponseStop::Cancelled);
        let stopped = handles.watch.terminal().await;
        assert!(stopped.terminal.is_some());
        // More than one connection window of late body for the stream that is gone.
        for piece in 0..10 {
            peer.write_all(b"L").await.unwrap();
            let late = tokio::time::timeout(Duration::from_secs(2), inbound.recv())
                .await
                .unwrap_or_else(|_| panic!("the window closed behind late piece {piece}"));
            assert!(
                matches!(late, Some(Inbound::Body { stream: 1, .. })),
                "{late:?}"
            );
        }
        // The other stream of the connection still receives.
        peer.write_all(b"V").await.unwrap();
        let alive = tokio::time::timeout(Duration::from_secs(2), inbound.recv())
            .await
            .expect("the connection's window is open for its other streams");
        assert_eq!(
            alive,
            Some(Inbound::Body {
                stream: 3,
                flags: 0,
                bytes: b"alive".as_slice().into(),
            })
        );
        drop(registration);
        drop(feeds);
        drop(peer);
        inbound
    };
    let (_outcome, _inbound) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(Box::pin(drive(s.conn, Vec::new(), server, r.wiring)), body)
    })
    .await
    .expect("the session ends when its caller goes");
    let given = credits
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert!(
        given.iter().all(|&(stream, _)| stream == 1),
        "only the left stream is owed credit here: {given:?}"
    );
    // CREDIT IS NEVER GIVEN TWICE: the pieces also went up to core, whose taking them credits
    // nothing more. Every late byte is credited exactly once.
    assert_eq!(
        given.iter().map(|&(_, count)| count).sum::<u64>(),
        10 * 64,
        "{given:?}"
    );
}
