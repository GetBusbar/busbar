// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED SIDE'S DELIVERY RECORD, rule by rule. The transport's answers are written here as the
//! session's own actions (what `Answers::capture` makes of a transport 2.0 answer) and applied through
//! the session task's own `apply`, over a real carrier with a real progress reader: the same driver
//! and state machine the dial is proven with (`outbound::wire`), in the answering role.

use super::*;
use crate::framed_stream::session::{Flow, Payload, Task};
use crate::outbound::delivery::{Breach, State};
use crate::outbound::records::{
    Session, WireSealed, END_FAILED, END_FLUSH, END_NO_BODY, END_SHUTDOWN, WIRE_CONTROL,
    WIRE_PAYLOAD,
};
use crate::response_delivery::{DeliveryRecord, ResponseHandles};
use busbar_contract::response_delivery::{DeliveryTerminal, ResponseKey};
use busbar_contract::storage::StorageSource;
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
use busbar_plugin_abi::transport::{E_BODY, E_END, E_REFUSE};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, DuplexStream};

type Carrier = crate::raw_progress::RawCarrier<DuplexStream>;

const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";

fn key(stream: u64) -> ResponseKey {
    ResponseKey {
        node: 1,
        incarnation: 1,
        unit: None,
        connection_generation: 1,
        stream,
    }
}

/// One accepted connection: its writer over a real carrier, the far end, and the session task.
struct Rig<S = Carrier> {
    source: StorageSource,
    io: DeliveryIo<S>,
    peer: DuplexStream,
    progress: Arc<dyn CarrierProgressReader>,
    task: Task,
}

/// What `begin` states: a session that carries several streams, or one that carries one.
fn stated(multiplex: bool) -> Session {
    if multiplex {
        Session::stated(true, 1 << 20, 4 << 20)
    } else {
        Session::stated(false, 0, 0)
    }
}

fn rig_over<S>(wrap: impl FnOnce(Carrier) -> S, multiplex: bool) -> Rig<S> {
    rig_stating(wrap, stated(multiplex))
}

fn rig_stating<S>(wrap: impl FnOnce(Carrier) -> S, session: Session) -> Rig<S> {
    let source = ProcessAdmission::new(1).connection_storage(AdmissionClass::Data);
    let (stream, peer) = tokio::io::duplex(1 << 16);
    let raw = crate::raw_progress::test_carrier(stream);
    let progress = raw.progress();
    let mut io = DeliveryIo::new(
        wrap(raw),
        Delivery::new(DeliveryLedger::default(), Arc::clone(&progress)),
    );
    // `begin`'s answer states the session.
    let mut begin = Actions::new(&source).unwrap();
    begin.push(Act::Session(session)).unwrap();
    io.answered(&begin).unwrap();
    Rig {
        source,
        io,
        peer,
        progress,
        task: Task::new(),
    }
}

fn rig() -> Rig {
    rig_over(|raw| raw, true)
}

impl<S: AsyncWrite + Unpin> Rig<S> {
    fn acts(&self) -> Actions {
        Actions::new(&self.source).unwrap()
    }

    /// The transport announces `stream` (its STREAM_HEAD, in the answer to an ingest).
    async fn announce(&mut self, stream: u64) {
        let mut acts = self.acts();
        acts.push(Act::Head {
            stream,
            end_stream: true,
            head: Payload::copy(&self.source, &[]).unwrap(),
        })
        .unwrap();
        assert!(matches!(self.apply(acts).await, Flow::Go));
        // Core takes the head.
        self.task.pending.clear();
    }

    /// The caller goes away: its end of the connection is closed.
    fn hang_up(&mut self) {
        self.peer = tokio::io::duplex(1).0;
    }

    /// The request on `stream` is announced and admitted: its owner's handles.
    async fn admitted(&mut self, stream: u64) -> ResponseHandles {
        self.announce(stream).await;
        self.io.ledger().admit_announced(key(stream)).unwrap()
    }

    async fn apply(&mut self, mut acts: Actions) -> Flow {
        self.task
            .apply(&mut acts, &mut self.io, Duration::from_secs(1), &mut None)
            .await
    }

    /// The engine emits `body` on `stream` and the transport frames it: a chunk head (control), the
    /// bytes (payload), the chunk's end (control).
    async fn chunk(&mut self, stream: u64, body: &[u8]) -> Flow {
        self.io.ledger().emitting(stream, E_BODY, body.len() as u64);
        let mut acts = self.acts();
        acts.part(stream, WIRE_CONTROL, b"4\r\n").unwrap();
        acts.part(stream, WIRE_PAYLOAD, body).unwrap();
        acts.part(stream, WIRE_CONTROL, b"\r\n").unwrap();
        self.apply(acts).await
    }

    /// The engine emits E_END on `stream` and the transport writes its end mark.
    async fn end(&mut self, stream: u64) -> Flow {
        self.io.ledger().emitting(stream, E_END, 0);
        let mut acts = self.acts();
        acts.part(stream, WIRE_CONTROL, b"0\r\n\r\n").unwrap();
        acts.push(Act::WireEnd {
            stream,
            how: END_FLUSH,
            arg: 0,
        })
        .unwrap();
        self.apply(acts).await
    }

    async fn head(&mut self, stream: u64) -> Flow {
        let mut acts = self.acts();
        acts.part(stream, WIRE_CONTROL, HEAD).unwrap();
        self.apply(acts).await
    }
}

fn record(state: &'static str, reason: Option<&'static str>, body_bytes: u64) -> DeliveryRecord {
    DeliveryRecord {
        state,
        reason,
        body_bytes,
    }
}

async fn read_some(peer: &mut DuplexStream, want: usize) -> Vec<u8> {
    let mut got = vec![0; want];
    peer.read_exact(&mut got).await.unwrap();
    got
}

// ---- a completed answer --------------------------------------------------------------------

#[tokio::test]
async fn a_completed_answer_is_whole_with_its_body_bytes() {
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.head(1).await, Flow::Go));
    assert!(matches!(rig.chunk(1, b"body").await, Flow::Go));
    assert_eq!(
        handles.watch.record(),
        None,
        "not final before its end mark"
    );
    assert!(handles.watch.snapshot().terminal.is_none());
    assert!(matches!(rig.end(1).await, Flow::Go));
    assert_eq!(handles.watch.record(), Some(record("whole", None, 4)));
    let snapshot = handles.watch.snapshot();
    assert_eq!(snapshot.terminal, Some(DeliveryTerminal::Complete));
    assert!(snapshot.first_payload_written);
    let wire = read_some(&mut rig.peer, HEAD.len() + 3 + 4 + 2 + 5).await;
    assert!(wire.starts_with(HEAD) && wire.ends_with(b"0\r\n\r\n"));
    // The record survives the connection: its owner holds only that small value.
    drop(rig.io);
    assert_eq!(handles.watch.record(), Some(record("whole", None, 4)));
}

#[tokio::test]
async fn an_answer_with_no_body_is_whole_at_its_end_mark() {
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    rig.io.ledger().emitting(1, E_END, 0);
    let mut acts = rig.acts();
    acts.part(1, WIRE_CONTROL, b"HTTP/1.1 204 No Content\r\n\r\n")
        .unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: END_NO_BODY,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert_eq!(handles.watch.record(), Some(record("whole", None, 0)));
    assert!(!handles.watch.snapshot().first_payload_written);
}

// ---- a streamed answer ---------------------------------------------------------------------

#[tokio::test]
async fn a_streamed_answer_is_whole_only_at_its_final_chunk() {
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.head(1).await, Flow::Go));
    for _ in 0..5 {
        assert!(matches!(rig.chunk(1, b"data").await, Flow::Go));
        assert_eq!(
            handles.watch.record(),
            None,
            "a stream in flight has no verdict"
        );
        assert_eq!(rig.io.ledger().state_of(1), State::Part);
    }
    assert!(matches!(rig.end(1).await, Flow::Go));
    assert_eq!(handles.watch.record(), Some(record("whole", None, 20)));
}

// ---- a client that goes away mid-body ------------------------------------------------------

#[tokio::test]
async fn a_client_that_goes_away_mid_body_is_part_caller_gone() {
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.head(1).await, Flow::Go));
    assert!(matches!(rig.chunk(1, b"data").await, Flow::Go));
    rig.hang_up();
    assert!(matches!(rig.chunk(1, b"more").await, Flow::Lost(_)));
    assert!(
        handles.watch.snapshot().terminal.is_none(),
        "a failed write alone is not a verdict: the writer is not gone yet"
    );
    drop(rig.io);
    // Eight body bytes were made; the socket took the first four.
    assert_eq!(
        handles.watch.record(),
        Some(record("part", Some("caller_gone"), 8))
    );
    let snapshot = handles.watch.snapshot();
    assert!(matches!(
        snapshot.terminal,
        Some(DeliveryTerminal::Failed(_))
    ));
    assert!(snapshot.first_payload_written);
}

#[tokio::test]
async fn a_client_gone_before_any_body_byte_is_none() {
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.head(1).await, Flow::Go));
    rig.hang_up();
    assert!(matches!(rig.chunk(1, b"data").await, Flow::Lost(_)));
    drop(rig.io);
    assert_eq!(
        handles.watch.record(),
        Some(record("none", Some("caller_gone"), 4))
    );
    assert!(!handles.watch.snapshot().first_payload_written);
}

/// The connection takes one byte of a write, then fails.
struct OneByteThenBroken<S>(S);

impl<S: AsyncWrite + Unpin> AsyncWrite for OneByteThenBroken<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.get_mut().0).poll_write(cx, &bytes[..1]) {
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn a_failed_write_keeps_the_body_byte_the_carrier_did_take() {
    let mut rig = rig_over(OneByteThenBroken, true);
    let handles = rig.admitted(1).await;
    rig.io.ledger().emitting(1, E_BODY, 4);
    let mut acts = rig.acts();
    acts.part(1, WIRE_PAYLOAD, b"body").unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Lost(_)));
    assert_eq!(
        handles.watch.snapshot().terminal,
        None,
        "error alone has not retired the writer"
    );
    drop(rig.io);
    let mut got = Vec::new();
    rig.peer.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"b");
    // One body byte reached the carrier: `part`, never `none`, never `whole`.
    assert_eq!(
        handles.watch.record(),
        Some(record("part", Some("caller_gone"), 4))
    );
    assert!(handles.watch.snapshot().first_payload_written);
}

// ---- a refused last piece ------------------------------------------------------------------

#[tokio::test]
async fn an_answer_whose_last_piece_is_withheld_and_then_refused_is_never_whole() {
    // The hold is the engine's: the owner withholds E_END while the record is not in. The record is
    // refused, so the end is never given and the owner stops the answer.
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.head(1).await, Flow::Go));
    assert!(matches!(rig.chunk(1, b"data").await, Flow::Go));
    handles.cancel.cancel(ResponseStop::Cancelled);
    let Some(DeliveryControl::Cancel { stream: 1, reason }) = rig.io.ledger().next_control() else {
        panic!("the owner's stop reaches the connection");
    };
    let now = Instant::now();
    assert!(
        rig.io.ledger().stop(1, reason, now),
        "the engine emits E_RESET"
    );
    assert!(!rig.io.ledger().takes_pieces(1));
    assert_eq!(
        rig.io.ledger().next_overdue(Duration::from_secs(5)),
        Some(now + Duration::from_secs(5)),
        "the transport owes the stream's end mark"
    );
    // The transport's answer to E_RESET: the stream failed.
    let mut acts = rig.acts();
    acts.part(1, WIRE_CONTROL, b"\x00\x00\x04\x03\x00").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FAILED,
        arg: 8,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert_eq!(
        handles.watch.record(),
        Some(record("part", Some("cancelled"), 4))
    );
    assert_eq!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::Cancelled))
    );
    assert_eq!(rig.io.ledger().next_overdue(Duration::from_secs(5)), None);
}

#[tokio::test]
async fn a_transport_that_ends_an_answer_the_engine_has_not_ended_is_faulted() {
    // L5, which is what makes the engine's hold a hold: no end without the engine's E_END.
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.chunk(1, b"data").await, Flow::Go));
    let before = rig.progress.snapshot().written_plaintext;
    let mut acts = rig.acts();
    acts.part(1, WIRE_CONTROL, b"0\r\n\r\n").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: 0,
    })
    .unwrap();
    assert!(matches!(
        rig.apply(acts).await,
        Flow::Rejected(Fault::Output(Breach::L5))
    ));
    assert_eq!(
        rig.progress.snapshot().written_plaintext,
        before,
        "nothing of that answer is written"
    );
    rig.io.ledger().faulted();
    assert_eq!(
        handles.watch.record(),
        Some(record("part", Some("transport_fault"), 4))
    );
}

#[tokio::test]
async fn the_engines_own_refusal_of_a_cut_answer_is_not_the_answer_delivered() {
    // The answer's feed went away before its end: the engine ends the stream with its own refusal.
    // The transport completes that refusal; the owner's answer was cut.
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    assert!(matches!(rig.head(1).await, Flow::Go));
    rig.io.ledger().cut(1);
    rig.io.ledger().emitting(1, E_REFUSE, 0);
    let mut acts = rig.acts();
    acts.part(1, WIRE_CONTROL, b"0\r\n\r\n").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: 0,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert_eq!(
        handles.watch.record(),
        Some(record("none", Some("cancelled"), 0))
    );
    assert!(matches!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(_))
    ));
}

// ---- HTTP/2: a stream reset, among others ---------------------------------------------------

#[tokio::test]
async fn a_caller_resetting_one_stream_fails_that_answer_and_no_other() {
    let mut rig = rig();
    let one = rig.admitted(1).await;
    let three = rig.admitted(3).await;
    assert!(matches!(rig.chunk(1, b"data").await, Flow::Go));
    assert!(matches!(rig.chunk(3, b"data").await, Flow::Go));
    // RST_STREAM for 1 arrives: the transport hands the reset up and ends the stream's output.
    let mut acts = rig.acts();
    acts.push(Act::Reset {
        stream: 1,
        code: 8,
        flags: 0,
    })
    .unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FAILED,
        arg: 8,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert_eq!(
        one.watch.record(),
        Some(record("part", Some("caller_gone"), 4))
    );
    assert!(matches!(
        rig.task.pending.pop_front(),
        Some(crate::framed_stream::session::Inbound::Reset { stream: 1, code: 8 })
    ));
    assert_eq!(three.watch.record(), None, "its neighbour is untouched");
    assert!(matches!(rig.chunk(3, b"more").await, Flow::Go));
    assert!(matches!(rig.end(3).await, Flow::Go));
    assert_eq!(three.watch.record(), Some(record("whole", None, 8)));
}

#[tokio::test]
async fn a_stream_reset_before_its_request_is_admitted_is_remembered() {
    let mut rig = rig();
    rig.announce(1).await;
    let mut acts = rig.acts();
    acts.push(Act::Reset {
        stream: 1,
        code: 8,
        flags: 0,
    })
    .unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FAILED,
        arg: 8,
    })
    .unwrap();
    assert!(
        matches!(rig.apply(acts).await, Flow::Go),
        "an end mark before admission is valid"
    );
    // Admission finds the stream already ended.
    let handles = rig.io.ledger().admit_announced(key(1)).unwrap();
    assert_eq!(
        handles.watch.record(),
        Some(record("none", Some("caller_gone"), 0))
    );
    assert!(!rig.io.ledger().takes_pieces(1));
}

#[tokio::test]
async fn an_answer_on_a_stream_the_transport_never_announced_is_refused() {
    let mut rig = rig();
    assert_eq!(
        rig.io.ledger().admit_announced(key(7)).err(),
        Some(ResponseStop::Integrity)
    );
    let _first = rig.admitted(1).await;
    assert_eq!(
        rig.io.ledger().admit_announced(key(1)).err(),
        Some(ResponseStop::Integrity),
        "one owner per answer, and an id is never reused"
    );
}

#[tokio::test]
async fn an_unadmitted_stream_is_let_go_once_it_can_no_longer_be_admitted() {
    let mut rig = rig();
    rig.announce(1).await;
    let mut acts = rig.acts();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FAILED,
        arg: 0,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    // Stream 3 is admitted: ids only rise, so stream 1 never will be; its entry goes.
    let _three = rig.admitted(3).await;
    assert_eq!(
        rig.io.ledger().admit_announced(key(1)).err(),
        Some(ResponseStop::Integrity)
    );
    assert_eq!(
        rig.io.ledger().state_of(1),
        State::None,
        "nothing is held of it"
    );
}

// ---- answers the transport makes by itself -------------------------------------------------

#[tokio::test]
async fn bytes_on_stream_zero_are_written_and_have_no_record() {
    let mut rig = rig();
    let mut acts = rig.acts();
    acts.part(0, WIRE_CONTROL, b"HTTP/1.1 400 Bad Request\r\n\r\n")
        .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert_eq!(
        read_some(&mut rig.peer, 28).await,
        b"HTTP/1.1 400 Bad Request\r\n\r\n"
    );
    assert!(!rig.io.ledger().has_responses());
}

// ---- the rules, on the accepted side: a breach writes nothing of that answer ---------------

async fn breach(build: impl FnOnce(&mut Rig, &mut Actions)) -> (Flow, u64, Option<DeliveryRecord>) {
    let mut rig = rig();
    let handles = rig.admitted(1).await;
    let mut acts = rig.acts();
    build(&mut rig, &mut acts);
    let flow = rig.apply(acts).await;
    let written = rig.progress.snapshot().written_plaintext;
    rig.io.ledger().faulted();
    (flow, written, handles.watch.record())
}

fn assert_faulted(name: &str, got: (Flow, u64, Option<DeliveryRecord>), rule: Breach) {
    let (flow, written, record) = got;
    assert!(
        matches!(flow, Flow::Rejected(Fault::Output(found)) if found == rule),
        "{name}: the answer is refused whole"
    );
    assert_eq!(written, 0, "{name}: nothing of it is written");
    assert_eq!(
        record.and_then(|record| record.reason),
        Some("transport_fault"),
        "{name}"
    );
}

#[tokio::test]
async fn l1_a_part_with_no_bytes_is_a_breach() {
    let got = breach(|_, acts| acts.part(1, WIRE_CONTROL, b"").unwrap()).await;
    assert_faulted("L1 empty", got, Breach::L1);
    let got = breach(|_, acts| acts.part(1, 7, b"x").unwrap()).await;
    assert_faulted("L1 class", got, Breach::L1);
}

#[tokio::test]
async fn l2_a_part_for_a_stream_that_is_not_open_is_a_breach() {
    let got = breach(|_, acts| acts.part(9, WIRE_CONTROL, b"x").unwrap()).await;
    assert_faulted("L2 unknown", got, Breach::L2);
    // A stream is open from its STREAM_HEAD on, not from the start of the answer that carries it.
    let got = breach(|rig, acts| {
        acts.part(5, WIRE_CONTROL, b"early").unwrap();
        acts.push(Act::Head {
            stream: 5,
            end_stream: true,
            head: Payload::copy(&rig.source, &[]).unwrap(),
        })
        .unwrap();
    })
    .await;
    assert_faulted("L2 before its head", got, Breach::L2);
}

#[tokio::test]
async fn l2_a_stream_announced_twice_is_a_breach() {
    let got = breach(|rig, acts| {
        acts.push(Act::Head {
            stream: 1,
            end_stream: true,
            head: Payload::copy(&rig.source, &[]).unwrap(),
        })
        .unwrap();
    })
    .await;
    assert_faulted("L2 twice", got, Breach::L2);
}

#[tokio::test]
async fn l3_payload_on_stream_zero_is_a_breach() {
    let got = breach(|_, acts| acts.part(0, WIRE_PAYLOAD, b"x").unwrap()).await;
    assert_faulted("L3", got, Breach::L3);
}

#[tokio::test]
async fn l4_a_record_after_a_streams_end_mark_is_a_breach() {
    let mut rig = rig();
    let _one = rig.admitted(1).await;
    let three = rig.admitted(3).await;
    assert!(matches!(rig.end(1).await, Flow::Go));
    let before = rig.progress.snapshot().written_plaintext;
    // Stream 1's verdict was read, so its entry is gone: a late part names a stream that is not open.
    let mut acts = rig.acts();
    acts.part(1, WIRE_CONTROL, b"late").unwrap();
    assert!(matches!(
        rig.apply(acts).await,
        Flow::Rejected(Fault::Output(Breach::L2 | Breach::L4))
    ));
    // And a second end mark in the answer that carries the first.
    let mut acts = rig.acts();
    rig.io.ledger().emitting(3, E_END, 0);
    for _ in 0..2 {
        acts.push(Act::WireEnd {
            stream: 3,
            how: END_FLUSH,
            arg: END_NO_BODY,
        })
        .unwrap();
    }
    assert!(matches!(
        rig.apply(acts).await,
        Flow::Rejected(Fault::Output(Breach::L4))
    ));
    assert_eq!(rig.progress.snapshot().written_plaintext, before);
    rig.io.ledger().faulted();
    assert_eq!(
        three.watch.record().and_then(|record| record.reason),
        Some("transport_fault")
    );
}

#[tokio::test]
async fn l6_an_end_whose_payload_is_not_the_body_the_engine_gave_is_a_breach() {
    // Short: the transport claims success with body missing.
    let got = breach(|rig, acts| {
        rig.io.ledger().emitting(1, E_BODY, 8);
        rig.io.ledger().emitting(1, E_END, 0);
        acts.part(1, WIRE_PAYLOAD, b"half").unwrap();
        acts.push(Act::WireEnd {
            stream: 1,
            how: END_FLUSH,
            arg: 0,
        })
        .unwrap();
    })
    .await;
    assert_faulted("L6 short", got, Breach::L6);
    // Another answer's bytes labelled as this one's.
    let got = breach(|rig, acts| {
        rig.io.ledger().emitting(1, E_END, 0);
        acts.part(1, WIRE_PAYLOAD, b"not mine").unwrap();
        acts.push(Act::WireEnd {
            stream: 1,
            how: END_FLUSH,
            arg: 0,
        })
        .unwrap();
    })
    .await;
    assert_faulted("L6 over", got, Breach::L6);
    // END_NO_BODY does not excuse a body that was written.
    let got = breach(|rig, acts| {
        rig.io.ledger().emitting(1, E_BODY, 8);
        rig.io.ledger().emitting(1, E_END, 0);
        acts.part(1, WIRE_PAYLOAD, b"half").unwrap();
        acts.push(Act::WireEnd {
            stream: 1,
            how: END_FLUSH,
            arg: END_NO_BODY,
        })
        .unwrap();
    })
    .await;
    assert_faulted("L6 no-body with a body", got, Breach::L6);
}

#[tokio::test]
async fn l7_nothing_follows_an_end_that_closes() {
    let mut rig = rig();
    let one = rig.admitted(1).await;
    rig.io.ledger().emitting(1, E_BODY, 4);
    rig.io.ledger().emitting(1, E_END, 0);
    let mut acts = rig.acts();
    acts.part(1, WIRE_PAYLOAD, b"body").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_SHUTDOWN,
        arg: 0,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    // The shutdown succeeded: an answer that ends by closing is whole only now.
    assert_eq!(one.watch.record(), Some(record("whole", None, 4)));
    let mut got = Vec::new();
    rig.peer.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"body", "the write side was shut after the last byte");
    let mut acts = rig.acts();
    acts.part(0, WIRE_CONTROL, b"more").unwrap();
    assert!(matches!(
        rig.apply(acts).await,
        Flow::Rejected(Fault::Output(Breach::L7))
    ));
}

#[tokio::test]
async fn l9_an_answer_carries_no_sealed_value() {
    let mut rig = rig();
    let _one = rig.admitted(1).await;
    let mut acts = rig.acts();
    acts.push(Act::WireSealed(WireSealed::stated(1, 0, 0, 16)))
        .unwrap();
    assert!(matches!(
        rig.apply(acts).await,
        Flow::Rejected(Fault::Sealed(_))
    ));
    assert_eq!(rig.progress.snapshot().written_plaintext, 0);
}

// ---- every byte given to the connection is a charged byte (OPEN-3 16, money) ----------------

/// A connection that notes where each byte it took was read from (an address range, never a read).
struct Noting<S> {
    inner: S,
    taken_from: Arc<std::sync::Mutex<Vec<std::ops::Range<usize>>>>,
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Noting<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(took)) = polled {
            let range = bytes[..took].as_ptr_range();
            this.taken_from
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(range.start as usize..range.end as usize);
        }
        polled
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The accepted side's twin of `outbound::wire::wire_check`: the session holds the answer's bytes in
/// its own output buffer, charged to the connection's storage account, and every byte the connection
/// is given is read from that block. The driver keeps no copy of its own (an uncharged one was the
/// money fault), and the answer's record is still read from the socket's progress alone.
#[tokio::test]
async fn every_answer_byte_the_accepted_connection_is_given_is_a_charged_byte() {
    let taken_from = Arc::new(std::sync::Mutex::new(Vec::new()));
    let noted = Arc::clone(&taken_from);
    let mut rig = rig_over(
        move |inner| Noting {
            inner,
            taken_from: noted,
        },
        true,
    );
    let handles = rig.admitted(1).await;
    rig.io.ledger().emitting(1, E_BODY, 4);
    rig.io.ledger().emitting(1, E_END, 0);
    let mut acts = rig.acts();
    acts.part(1, WIRE_CONTROL, HEAD).unwrap();
    acts.part(1, WIRE_PAYLOAD, b"body").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: 0,
    })
    .unwrap();
    let block = acts
        .out
        .allocation()
        .expect("the answer's bytes are in the session's buffer")
        .as_ptr_range();
    let block = block.start as usize..block.end as usize;
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    let taken_from = taken_from
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        !taken_from.is_empty(),
        "the connection was given the answer"
    );
    let mut given = 0;
    for range in &taken_from {
        assert!(
            block.start <= range.start && range.end <= block.end,
            "a byte the connection was given lies outside the session's charged block"
        );
        given += range.len();
    }
    assert_eq!(given, HEAD.len() + 4, "every byte of the answer, once");
    assert_eq!(
        read_some(&mut rig.peer, given).await,
        [HEAD, b"body"].concat()
    );
    assert_eq!(handles.watch.record(), Some(record("whole", None, 4)));
}

// ---- the flush and the close are part of "delivered" ---------------------------------------

/// A connection whose flush (or shutdown) fails after it took every byte.
struct Fails<S> {
    inner: S,
    flush: bool,
    shutdown: bool,
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Fails<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.flush {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn an_answer_whose_flush_failed_is_not_whole_though_every_byte_was_taken() {
    let mut rig = rig_over(
        |inner| Fails {
            inner,
            flush: true,
            shutdown: false,
        },
        true,
    );
    // The announce writes nothing, so nothing is flushed for it.
    let handles = rig.admitted(1).await;
    rig.io.ledger().emitting(1, E_BODY, 4);
    rig.io.ledger().emitting(1, E_END, 0);
    let mut acts = rig.acts();
    acts.part(1, WIRE_PAYLOAD, b"body").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: 0,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Lost(_)));
    assert_eq!(rig.progress.snapshot().written_plaintext, 4);
    drop(rig.io);
    assert_eq!(
        handles.watch.record(),
        Some(record("part", Some("caller_gone"), 4)),
        "accepted bytes without their flush are not a delivered answer"
    );
}

#[tokio::test]
async fn an_answer_that_ends_by_closing_is_not_whole_when_the_close_failed() {
    let mut rig = rig_over(
        |inner| Fails {
            inner,
            flush: false,
            shutdown: true,
        },
        false,
    );
    let handles = rig.admitted(1).await;
    rig.io.ledger().emitting(1, E_BODY, 4);
    rig.io.ledger().emitting(1, E_END, 0);
    let mut acts = rig.acts();
    acts.part(1, WIRE_PAYLOAD, b"body").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_SHUTDOWN,
        arg: 0,
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Lost(_)));
    assert_eq!(handles.watch.record(), None);
    drop(rig.io);
    assert_eq!(
        handles.watch.record(),
        Some(record("part", Some("caller_gone"), 4))
    );
}

/// A reader that is not this connection's: it claims bytes nobody wrote.
struct Liar;

impl CarrierProgressReader for Liar {
    fn snapshot(&self) -> busbar_contract::response_delivery::CarrierProgress {
        busbar_contract::response_delivery::CarrierProgress {
            accepted_plaintext: 1 << 20,
            written_plaintext: 1 << 20,
            complete_records_plaintext: 1 << 20,
            fault: None,
        }
    }
}

#[tokio::test]
async fn a_reading_that_claims_more_than_was_written_delivers_nothing() {
    let source = ProcessAdmission::new(1).connection_storage(AdmissionClass::Data);
    let (stream, _peer) = tokio::io::duplex(1 << 16);
    let mut ledger = DeliveryLedger::default();
    let handles = ledger.admit(key(1)).unwrap();
    let mut io = DeliveryIo::new(stream, Delivery::new(ledger, Arc::new(Liar)));
    let mut begin = Actions::new(&source).unwrap();
    begin
        .push(Act::Session(Session::stated(false, 0, 0)))
        .unwrap();
    io.answered(&begin).unwrap();
    io.ledger().emitting(1, E_END, 0);
    let mut acts = Actions::new(&source).unwrap();
    acts.part(1, WIRE_CONTROL, b"HTTP/1.1 204 No Content\r\n\r\n")
        .unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: END_NO_BODY,
    })
    .unwrap();
    let flow = Task::new()
        .apply(&mut acts, &mut io, Duration::from_secs(1), &mut None)
        .await;
    assert!(matches!(flow, Flow::Lost(_)));
    drop(io);
    assert_eq!(
        handles.watch.record().map(|record| record.state),
        Some("none")
    );
}

// ---- hand-over on upgrade -------------------------------------------------------------------

#[tokio::test]
async fn an_upgraded_requests_answer_becomes_stream_one_of_the_adopting_session() {
    let mut rig = rig_over(|raw| raw, false);
    let handles = rig.admitted(5).await;
    let written_before = {
        assert!(matches!(rig.head(5).await, Flow::Go));
        rig.progress.snapshot().written_plaintext
    };
    let (io, delivery) = rig.io.into_parts();
    assert!(
        handles.watch.snapshot().terminal.is_none(),
        "the hand-over freezes nothing"
    );
    let (mut ledger, reader) = delivery.into_parts();
    ledger.adopt(5);
    let mut io = DeliveryIo::new(io, Delivery::new(ledger, reader));
    // The adopting transport writes the 101 on stream 1 and, at the end, its close.
    let mut acts = Actions::new(&rig.source).unwrap();
    acts.part(1, WIRE_CONTROL, b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        .unwrap();
    assert!(matches!(
        rig.task
            .apply(&mut acts, &mut io, Duration::from_secs(1), &mut None)
            .await,
        Flow::Go
    ));
    assert!(
        rig.progress.snapshot().written_plaintext > written_before,
        "the counters were not reset"
    );
    io.ledger().emitting(1, E_END, 0);
    let mut acts = Actions::new(&rig.source).unwrap();
    acts.part(1, WIRE_CONTROL, b"\x88\x00").unwrap();
    acts.push(Act::WireEnd {
        stream: 1,
        how: END_FLUSH,
        arg: END_NO_BODY,
    })
    .unwrap();
    assert!(matches!(
        rig.task
            .apply(&mut acts, &mut io, Duration::from_secs(1), &mut None)
            .await,
        Flow::Go
    ));
    assert_eq!(
        handles.watch.key().stream,
        5,
        "the owner keeps its identity"
    );
    assert_eq!(handles.watch.record(), Some(record("whole", None, 0)));
}

// ---- inbound body: what the session may make the engine hold --------------------------------

#[tokio::test]
async fn a_session_with_one_stream_is_not_read_while_its_reader_is_behind() {
    let mut rig = rig_over(|raw| raw, false);
    let _one = rig.admitted(1).await;
    assert!(rig.io.ledger().reads_socket());
    let mut acts = rig.acts();
    acts.push(Act::Body {
        stream: 1,
        flags: 0,
        bytes: Payload::copy(&rig.source, b"request body").unwrap(),
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert!(!rig.io.ledger().reads_socket());
    assert_eq!(
        rig.io.ledger().taken(1, 12),
        None,
        "no credit call for one stream"
    );
    assert!(rig.io.ledger().reads_socket());
}

#[tokio::test]
async fn a_multiplexing_session_is_given_credit_as_its_reader_reads() {
    // Small windows, so the test holds little: 64 bytes a stream, 256 the connection.
    let mut rig = rig_stating(|raw| raw, Session::stated(true, 64, 256));
    let _one = rig.admitted(1).await;
    let half = 32usize;
    let mut acts = rig.acts();
    acts.push(Act::Body {
        stream: 1,
        flags: 0,
        bytes: Payload::copy(&rig.source, &vec![0; half]).unwrap(),
    })
    .unwrap();
    assert!(matches!(rig.apply(acts).await, Flow::Go));
    assert!(
        rig.io.ledger().reads_socket(),
        "its neighbours are still read"
    );
    assert_eq!(rig.io.ledger().taken(1, 1), None, "not due yet");
    assert_eq!(
        rig.io.ledger().taken(1, half as u64 - 1),
        Some(half as u64),
        "half the window is owed: CONSUMED"
    );
}
