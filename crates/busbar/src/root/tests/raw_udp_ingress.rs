// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_core_connector::datagram::{DatagramFraming, LegSink, Pairing};
use busbar_core_connector::framer::{FramerDoor, Got};
use busbar_core_connector::publication::Messages;
use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_kernel::plane_driver::CallerEnd;
use busbar_test_kit::root_door_fixtures::raw_udp_ingress::{check, Ingress};
use tokio::net::UdpSocket;

use super::{lock, CallerLeg, ClaimDoor, DatagramCaller};

const CHANNEL: u64 = 1;
const WAIT: Duration = Duration::from_secs(5);

fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

struct Association {
    leg: Arc<CallerLeg>,
    pair: Arc<Pairing>,
    messages: Arc<Messages>,
    framer: Arc<Ingress>,
    id: u64,
}

impl Association {
    fn new(door: &Arc<ClaimDoor>, user: &[u8], stream: u64) -> Self {
        Self::with_limit(door, user, stream, None)
    }

    fn with_limit(door: &Arc<ClaimDoor>, user: &[u8], stream: u64, limit: Option<usize>) -> Self {
        let messages = Messages::new(8);
        let leg = CallerLeg::new(door, Arc::clone(&messages));
        let pair =
            Pairing::with_memory_limit(Arc::clone(&leg) as Arc<dyn LegSink>, door.local(), limit);
        *lock(&leg.pairing) = Some(Arc::clone(&pair));
        let framer = Ingress::new(user, stream);
        let (mut framing, _) = DatagramFraming::accept_minted(
            Arc::clone(&framer) as Arc<dyn FramerDoor>,
            door.local(),
        )
        .expect("begin");
        framing
            .rendezvous(b"offer", Instant::now())
            .expect("valid terms");
        let id = door.join(framing, &leg).expect("join");
        leg.take(
            vec![got(CHANNEL, b"label: events\r\n", true)],
            Instant::now(),
        );
        Self {
            leg,
            pair,
            messages,
            framer,
            id,
        }
    }

    fn caller(&self) -> DatagramCaller {
        let (head, _answer) = tokio::sync::oneshot::channel();
        DatagramCaller {
            leg: Arc::clone(&self.leg),
            from: Arc::clone(&self.messages),
            head: std::sync::Mutex::new(Some(head)),
            stated: std::sync::atomic::AtomicU32::new(0),
            opened: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        self.pair.close();
    }
}

struct Quiet;
impl Wake for Quiet {
    fn wake(self: Arc<Self>) {}
}

struct Parked {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<bool>>,
}

impl Parked {
    fn start(
        door: &Arc<ClaimDoor>,
        association: &Association,
    ) -> (Self, std::sync::mpsc::Receiver<()>) {
        let (entered, inside) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let resume = std::sync::Mutex::new(resume);
        association
            .framer
            .recording()
            .observe(Arc::new(move |bytes| {
                if bytes == b"occupied" {
                    let _ = entered.send(());
                    let _ = resume.lock().unwrap().recv();
                }
            }));
        let door = Arc::clone(door);
        let id = association.id;
        let thread = std::thread::spawn(move || {
            door.emit(id, CHANNEL, b"occupied", true, false, Instant::now())
        });
        (
            Self {
                release: Some(release),
                thread: Some(thread),
            },
            inside,
        )
    }

    fn finish(mut self) -> std::thread::Result<bool> {
        let _ = self.release.take().unwrap().send(());
        self.thread.take().unwrap().join()
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn heard(socket: &UdpSocket, door: &Arc<ClaimDoor>, association: &Association, user: &str) {
    let check = check(user, 1);
    socket.send_to(&check, door.local()).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while !association.framer.received().contains(&check) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authenticated check crossed the real socket and framer");
}

#[tokio::test]
async fn raw_output_credit_readiness_drops_before_acceptance_and_resumes_without_replay() {
    use busbar_core_connector::datagram::Leg;
    use busbar_core_connector::framer::FRAME_CAP;
    use busbar_core_connector::test_support::datagram_output_reservation_bytes;

    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let a = Association::with_limit(
        &door,
        b"creditfrag",
        CHANNEL,
        Some(datagram_output_reservation_bytes() + FRAME_CAP),
    );
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    heard(&source, &door, &a, "creditfrag").await;
    assert!(a.pair.published().await.failure.is_none());

    let custody = a
        .pair
        .reserve_input_for(Leg::Caller, 2 * FRAME_CAP)
        .unwrap();
    let input = vec![b'i'; 2 * FRAME_CAP];
    let used = a.pair.memory_account().used();
    let dropped = b"\x80no-output-credit";
    source.send_to(dropped, door.local()).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while door.assocs.raw_busy_dropped() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unavailable output credit is receive-not-ready before raw acceptance");
    assert_eq!(door.assocs.raw_busy_dropped(), 1);
    assert_eq!(a.framer.received(), vec![check("creditfrag", 1)]);
    assert!(a.messages.try_recv().is_err());
    assert!(!a.pair.closed());
    assert!(a.pair.publication_outcome().failure.is_none());
    assert_eq!(a.pair.memory_account().used(), used);
    drop(input);
    drop(custody);

    let fresh = b"\x80credit-returned";
    source.send_to(fresh, door.local()).await.unwrap();
    let message = tokio::time::timeout(WAIT, a.messages.recv())
        .await
        .expect("new raw input progresses after actual storage retirement")
        .unwrap();
    assert_eq!(message.bytes, fresh);
    assert!(message.end);
    assert!(a.pair.published().await.failure.is_none());
    assert_eq!(
        a.framer.received(),
        vec![check("creditfrag", 1), fresh.to_vec()]
    );
    assert!(a.messages.try_recv().is_err());
    assert_eq!(door.assocs.raw_busy_dropped(), 1);
    assert!(!a.pair.closed());
    door.close();
}

#[tokio::test]
async fn busy_raw_ingress_is_counted_without_blocking_the_shared_socket_or_trusted_writes() {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let a = Association::new(&door, b"busyfrag", CHANNEL);
    let b = Association::new(&door, b"healthyfrag", CHANNEL);
    let source_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    heard(&source_a, &door, &a, "busyfrag").await;
    heard(&source_b, &door, &b, "healthyfrag").await;
    let caller = a.caller();
    let (parked, inside) = Parked::start(&door, &a);
    let entered = inside.recv_timeout(WAIT);
    let wake = Waker::from(Arc::new(Quiet));
    let mut cx = Context::from_waker(&wake);
    let mut cancelled = Box::pin(CallerEnd::write(&caller, b"cancelled"));
    let cancelled_poll = cancelled.as_mut().poll(&mut cx);
    drop(cancelled);
    let mut application = Box::pin(CallerEnd::write(&caller, b"accepted once"));
    let application_poll = application.as_mut().poll(&mut cx);

    let dropped_packets = [
        b"\x80busy-one".as_slice(),
        b"\x80busy-two",
        b"\x80busy-three",
    ];
    let mut sends = Vec::new();
    for bytes in dropped_packets {
        sends.push(source_a.send_to(bytes, door.local()).await);
    }
    let counted = tokio::time::timeout(WAIT, async {
        while door.assocs.raw_busy_dropped() < dropped_packets.len() as u64 {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let unknown = source_b
        .send_to(&check("missingfrag", 2), door.local())
        .await;
    let healthy = b"\x80healthy";
    let healthy_sent = source_b.send_to(healthy, door.local()).await;
    let healthy_received = tokio::time::timeout(WAIT, b.messages.recv()).await;
    let count_while_parked = door.assocs.raw_busy_dropped();
    let a_while_parked = a.framer.received();

    let holder = parked.finish();
    let written = match application_poll {
        std::task::Poll::Ready(written) => Ok(written),
        std::task::Poll::Pending => tokio::time::timeout(WAIT, application).await,
    };
    let after = b"\x80after-release";
    source_a.send_to(after, door.local()).await.unwrap();
    let after_received = tokio::time::timeout(WAIT, a.messages.recv()).await;
    let received_a = a.framer.received();
    let received_b = b.framer.received();
    let emitted = a.framer.recording().emitted();
    door.close();

    assert!(entered.is_ok() && holder.unwrap());
    assert!(cancelled_poll.is_pending() && application_poll.is_pending());
    assert!(sends.into_iter().all(|send| send.is_ok()));
    assert!(counted.is_ok() && unknown.is_ok() && healthy_sent.is_ok());
    assert_eq!(count_while_parked, dropped_packets.len() as u64);
    assert_eq!(healthy_received.unwrap().unwrap().bytes, healthy);
    assert_eq!(a_while_parked, vec![check("busyfrag", 1)]);
    assert!(
        written.unwrap(),
        "busy does not mean ClientGone for application writes"
    );
    assert_eq!(
        emitted,
        vec![b"occupied".to_vec(), b"accepted once".to_vec()]
    );
    assert_eq!(after_received.unwrap().unwrap().bytes, after);
    assert_eq!(
        received_a,
        vec![check("busyfrag", 1), after.to_vec()],
        "busy raw packets are never replayed"
    );
    assert_eq!(received_b, vec![check("healthyfrag", 1), healthy.to_vec()]);
    assert_eq!(door.assocs.raw_busy_dropped(), dropped_packets.len() as u64);
}

#[tokio::test]
async fn closing_a_busy_association_cancels_waiters_and_does_not_reuse_its_old_path() {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let a = Association::new(&door, b"reusedfrag", CHANNEL);
    let marker = Association::new(&door, b"closingmarker", CHANNEL);
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    heard(&source, &door, &a, "reusedfrag").await;
    let caller = a.caller();
    let (parked, inside) = Parked::start(&door, &a);
    let entered = inside.recv_timeout(WAIT);
    let wake = Waker::from(Arc::new(Quiet));
    let mut cx = Context::from_waker(&wake);
    let mut pending = Box::pin(CallerEnd::write(&caller, b"closed waiter"));
    let before = pending.as_mut().poll(&mut cx);
    a.pair.close();

    let late = source.send_to(&check("reusedfrag", 3), door.local()).await;
    let marker_check = check("closingmarker", 4);
    let marker_sent = source.send_to(&marker_check, door.local()).await;
    let late_consumed = tokio::time::timeout(WAIT, async {
        while !marker.framer.received().contains(&marker_check) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let holder = parked.finish();
    let cancelled = tokio::time::timeout(WAIT, pending).await;
    let replacement = Association::new(&door, b"reusedfrag", CHANNEL);
    let old_path = source.send_to(b"\x80stale-path", door.local()).await;
    let new_source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    heard(&new_source, &door, &replacement, "reusedfrag").await;
    let fresh = b"\x80replacement";
    new_source.send_to(fresh, door.local()).await.unwrap();
    let delivered = tokio::time::timeout(WAIT, replacement.messages.recv()).await;
    let replacement_input = replacement.framer.received();
    door.close();

    assert!(entered.is_ok() && holder.is_ok() && before.is_pending());
    assert!(late.is_ok() && marker_sent.is_ok() && late_consumed.is_ok() && old_path.is_ok());
    assert!(
        !cancelled.expect("the closed association's waiter resolved before the timeout"),
        "a write waiting on a closed association is refused, not accepted"
    );
    assert_ne!(a.id, replacement.id);
    assert_eq!(a.framer.recording().emitted(), vec![b"occupied".to_vec()]);
    assert_eq!(delivered.unwrap().unwrap().bytes, fresh);
    assert_eq!(
        replacement_input,
        vec![check("reusedfrag", 1), fresh.to_vec()]
    );
    assert_eq!(
        door.assocs.raw_busy_dropped(),
        0,
        "closing and unrouted traffic is not busy loss"
    );
}

#[tokio::test]
async fn admitted_raw_line_output_reaches_the_real_upstream_framer_once() {
    use busbar_contract::conn::{Piece, PieceKind};
    use busbar_contract::ids::StreamId;
    use busbar_contract::transport::wire::WireStatusClass;
    use busbar_core_connector::datagram::Leg;
    use busbar_core_connector::test_support::DatagramSession;
    use busbar_test_kit::root_door_fixtures::datagram_feedback::{Branching, Terminals};

    const CALLER_LINE: u64 = 11;
    const UPSTREAM_LINE: u64 = 21;
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let a = Association::new(&door, b"linefrag", CALLER_LINE);
    a.pair.sort(
        Leg::Caller,
        vec![got(CALLER_LINE, b"kind: feedback\r\n", true)],
        Instant::now(),
    );
    let far = Branching::new(UPSTREAM_LINE, 22, b"upstreamfrag", 1, Terminals::Paths);
    far.consume_without_output();
    let port = ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap();
    let (framing, _) =
        DatagramFraming::accept_minted(Arc::clone(&far) as Arc<dyn FramerDoor>, port.local_addr())
            .unwrap();
    let upstream = DatagramSession::new(framing, port, Arc::clone(&a.pair));
    for (kind, bytes) in [
        (PieceKind::Fields, &[][..]),
        (PieceKind::Body, b"answer".as_slice()),
        (PieceKind::Completion, &[][..]),
    ] {
        upstream
            .exchanged(
                Piece {
                    kind,
                    stream: StreamId(0),
                    len: bytes.len(),
                    end: true,
                    status: (kind == PieceKind::Fields).then_some(WireStatusClass::Success),
                    status_code: None,
                    status_namespace: None,
                    retry_after_secs: None,
                    fault: None,
                    reason: None,
                    declared_len: None,
                },
                bytes,
            )
            .expect("actual upstream exchange");
    }
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    heard(&source, &door, &a, "linefrag").await;
    let line = b"\x80accepted-line";
    source.send_to(line, door.local()).await.unwrap();
    let delivered = tokio::time::timeout(WAIT, async {
        while far.emitted().is_empty() {
            tokio::task::yield_now().await;
        }
        a.pair.published().await
    })
    .await;
    let emitted = far.emitted();
    upstream.close();
    door.close();

    assert!(delivered.unwrap().failure.is_none());
    assert_eq!(emitted, vec![line.to_vec()]);
    assert!(
        a.messages.try_recv().is_err(),
        "LINE output stays out of the application channel"
    );
    assert_eq!(door.assocs.raw_busy_dropped(), 0);
}
