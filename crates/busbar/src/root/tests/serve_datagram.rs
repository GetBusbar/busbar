// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use busbar_core_connector::datagram::Pairing;
use busbar_core_connector::framer::Got;
use busbar_core_connector::publication::{Custody, Message, Messages};
use busbar_core_connector::udp::{bind, ReadyPort};

use super::{lock, CallerLeg, ClaimDoor, CALLER_QUEUE};

pub(super) fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        status_namespace: None,
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

fn leg(capacity: usize) -> (Arc<ClaimDoor>, Arc<CallerLeg>, Arc<Pairing>, Arc<Messages>) {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let rx = Messages::new(capacity);
    let tx = Arc::clone(&rx);
    let leg = CallerLeg::new(&door, tx);
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    (door, leg, pairing, rx)
}

const SESSION_CHANNEL: u64 = 1;

#[tokio::test]
async fn a_plane_that_falls_behind_its_caller_ends_the_session() {
    let (_door, leg, pairing, rx) = leg(2);
    let now = Instant::now();
    let mut pieces = vec![got(1, b"label: events\r\n", true)];
    pieces.extend((0..3).map(|_| got(1, b"m", false)));
    leg.take(pieces, now);
    assert!(pairing.closed(), "the third message found the queue full");
    assert!(lock(&leg.to_session).is_none());
    assert_eq!(rx.recv().await.unwrap(), b"m");
    assert_eq!(rx.recv().await.unwrap(), b"m");
    assert!(rx.recv().await.is_none(), "the session's caller side ended");
}

#[tokio::test]
async fn a_plane_that_writes_past_the_bound_before_the_channel_opens_ends_the_session() {
    let (_door, leg, pairing, rx) = leg(8);
    for _ in 0..CALLER_QUEUE {
        assert!(leg.write(b"early", false).await);
    }
    assert!(
        !leg.write(b"one too many", false).await,
        "the write past the bound is refused"
    );
    assert!(pairing.closed(), "the session ended");
    assert!(
        lock(&leg.outbound).held.is_empty(),
        "what it held went with it"
    );
    assert!(lock(&leg.to_session).is_none());
    assert!(rx.recv().await.is_none(), "the session's caller side ended");
    assert!(
        !leg.write(b"after", false).await,
        "a closed leg takes no write"
    );
    assert!(lock(&leg.outbound).held.is_empty(), "nor holds one");
}

#[tokio::test]
async fn the_open_answers_under_the_head_the_plane_states() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let location = (b"location".to_vec(), b"/v1/calls/c_0123abcd".to_vec());
    tx.send((201, vec![location.clone()])).unwrap();
    let head = super::plane_head(rx, std::time::Duration::from_secs(5)).await;
    assert_eq!(head, Some((201, vec![location])));
}

#[tokio::test]
async fn a_plane_that_states_no_head_in_time_answers_nothing() {
    let (_held, rx) = tokio::sync::oneshot::channel::<(u32, super::HeadFields)>();
    let started = Instant::now();
    assert_eq!(
        super::plane_head(rx, std::time::Duration::from_millis(50)).await,
        None
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(50));
    let (dropped, rx) = tokio::sync::oneshot::channel::<(u32, super::HeadFields)>();
    drop(dropped);
    assert_eq!(
        super::plane_head(rx, std::time::Duration::from_secs(5)).await,
        None
    );
}

#[tokio::test]
async fn the_caller_side_opens_with_one_empty_piece() {
    use busbar_kernel::plane_driver::SessionCaller;
    let (_door, leg, _pairing, _rx) = leg(8);
    let from = Messages::new(8);
    let to = Arc::clone(&from);
    let (head, _rx) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from,
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    };
    to.send(Message {
        bytes: b"{\"type\":\"x\"}".to_vec(),
        end: true,
        consumed: 0,
        custody: Custody::default().reader(),
    })
    .unwrap();
    assert_eq!(caller.read().await, Some(Vec::new()), "the open");
    assert_eq!(caller.read().await, Some(b"{\"type\":\"x\"}".to_vec()));
    to.close();
    assert_eq!(caller.read().await, None);
}

#[tokio::test]
async fn a_closed_leg_with_an_open_channel_refuses_further_writes() {
    let (_door, leg, pairing, _rx) = leg(8);
    let now = Instant::now();
    leg.take(vec![got(1, b"label: events\r\n", true)], now);
    pairing.close();
    assert!(!leg.write(b"after close", false).await);
}

#[tokio::test]
async fn session_delivery_and_close_allow_the_receiver_waker_to_reenter_the_leg() {
    struct Reenter {
        leg: std::sync::Weak<CallerLeg>,
        locked: std::sync::atomic::AtomicBool,
        wakes: std::sync::atomic::AtomicUsize,
    }
    impl std::task::Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let leg = self.leg.upgrade().unwrap();
            if leg.to_session.try_lock().is_err() || leg.outbound.try_lock().is_err() {
                self.locked.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            }

            leg.failed();
        }
    }

    for deliver in [true, false] {
        let (_door, leg, pairing, rx) = leg(8);
        let wake = Arc::new(Reenter {
            leg: Arc::downgrade(&leg),
            locked: std::sync::atomic::AtomicBool::new(false),
            wakes: std::sync::atomic::AtomicUsize::new(0),
        });
        let waker = std::task::Waker::from(Arc::clone(&wake));
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(rx.poll_recv(&mut cx).is_pending());
        if deliver {
            leg.take(vec![got(SESSION_CHANNEL, b"piece", false)], Instant::now());
        } else {
            pairing.close();
        }
        assert!(wake.wakes.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(!wake.locked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(pairing.closed());
        if deliver {
            assert_eq!(rx.try_recv().unwrap(), b"piece");
        }
        assert!(rx.recv().await.is_none());
    }
}

pub(crate) mod peer {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use busbar_core_connector::datagram::DatagramFraming;
    use busbar_core_connector::dtls::SessionCert;
    use busbar_core_connector::framer::{FramerDoor, Yielded};
    use busbar_core_connector::{DialJudge, Judged, Verdict};
    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, watch};
    use tokio::task::JoinHandle;

    struct Loopback;

    impl DialJudge for Loopback {
        fn judge_dial(&self, dest: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
            Some(
                dest.parse::<SocketAddr>()
                    .ok()
                    .filter(|addr| addr.ip().is_loopback())
                    .ok_or(1),
            )
        }
    }

    /// Exercise the real transport door; fixtures never construct plugin internals.
    pub(crate) fn offer_description() -> zeroize::Zeroizing<Vec<u8>> {
        let (_framing, yielded) = DatagramFraming::dial(
            super::real::loaded(),
            Arc::new(SessionCert::mint().unwrap()),
            "127.0.0.1:40000".parse().unwrap(),
            &[("channel".into(), b"events".to_vec())],
            Arc::new(Loopback),
            0,
        )
        .expect("the real WebRTC door offers a data channel");
        zeroize::Zeroizing::new(description(&yielded))
    }

    // The WebRTC ABI assigns media line n stream 2^32 + n; this is a fixture's
    // independent expected wire identifier, not an imported implementation constant.
    pub(crate) const FIRST_AUDIO_STREAM: u64 = 1 << 32;

    pub(crate) struct Peer {
        socket: UdpSocket,
        framing: DatagramFraming,
        pending: VecDeque<Yielded>,
    }

    fn description(yielded: &Yielded) -> Vec<u8> {
        yielded
            .pieces
            .iter()
            .find(|piece| piece.stream == 0 && !piece.fields && !piece.failed)
            .expect("the actual WebRTC framer produces its SDP")
            .bytes
            .clone()
    }

    impl Peer {
        pub(crate) async fn offer(framer: Arc<dyn FramerDoor>) -> (Self, Vec<u8>) {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (framing, yielded) = DatagramFraming::dial(
                framer,
                Arc::new(SessionCert::mint().unwrap()),
                socket.local_addr().unwrap(),
                &[("channel".into(), b"events".to_vec())],
                Arc::new(Loopback),
                0,
            )
            .unwrap();
            let offer = description(&yielded);
            (
                Self {
                    socket,
                    framing,
                    pending: VecDeque::from([yielded]),
                },
                offer,
            )
        }

        pub(crate) async fn accept(framer: Arc<dyn FramerDoor>, offer: &[u8]) -> (Self, Vec<u8>) {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (mut framing, first) =
                DatagramFraming::accept_minted(framer, socket.local_addr().unwrap()).unwrap();
            let yielded = framing.rendezvous(offer, Instant::now()).unwrap();
            let answer = description(&yielded);
            (
                Self {
                    socket,
                    framing,
                    pending: VecDeque::from([first, yielded]),
                },
                answer,
            )
        }

        pub(crate) fn answer(&mut self, answer: &[u8]) {
            self.pending
                .push_back(self.framing.rendezvous(answer, Instant::now()).unwrap());
        }

        pub(crate) fn run(
            self,
            stopped: watch::Receiver<bool>,
            announce: Option<&'static [u8]>,
        ) -> (JoinHandle<()>, mpsc::UnboundedReceiver<Vec<u8>>) {
            let (task, received, _opened) = self.run_ready(stopped, announce);
            (task, received)
        }

        pub(crate) fn run_ready(
            mut self,
            mut stopped: watch::Receiver<bool>,
            mut announce: Option<&'static [u8]>,
        ) -> (
            JoinHandle<()>,
            mpsc::UnboundedReceiver<Vec<u8>>,
            tokio::sync::oneshot::Receiver<()>,
        ) {
            let (ready, opened) = tokio::sync::oneshot::channel();
            let mut ready = Some(ready);
            let (output, received) = mpsc::unbounded_channel();
            let task = tokio::spawn(async move {
                let mut bytes = vec![0; 65536];
                loop {
                    if *stopped.borrow() {
                        break;
                    }
                    let mut ended = false;
                    while let Some(mut yielded) = self.pending.pop_front() {
                        ended |= yielded.ended;
                        for piece in yielded.pieces.drain(..) {
                            assert!(
                                !piece.failed,
                                "actual WebRTC peer stream failed: {:?}",
                                piece.reason
                            );
                            if piece.stream == 0 {
                                continue;
                            }
                            if piece.fields && !piece.end && piece.bytes.starts_with(b"label: ") {
                                if let Some(ready) = ready.take() {
                                    let _ = ready.send(());
                                }
                                if let Some(message) = announce.take() {
                                    self.pending.push_back(
                                        self.framing
                                            .emit(piece.stream, message, true, true, Instant::now())
                                            .unwrap(),
                                    );
                                }
                            } else if !piece.fields && !piece.end {
                                let _ = output.send(piece.bytes);
                            }
                        }
                    }
                    while let Some((to, bytes)) = self.framing.poll_send() {
                        self.socket.send_to(&bytes, to).await.unwrap();
                    }
                    if ended {
                        break;
                    }
                    let deadline = self.framing.deadline();
                    let yielded = tokio::select! {
                        changed = stopped.changed() => {
                            if changed.is_err() || *stopped.borrow() {
                                break;
                            }
                            continue;
                        }
                        got = self.socket.recv_from(&mut bytes) => {
                            let (len, from) = got.unwrap();
                            self.framing.datagram(from, &bytes[..len], Instant::now()).unwrap()
                        }
                        () = async move {
                            if let Some(deadline) = deadline {
                                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => self.framing.timeout(Instant::now()).unwrap(),
                    };
                    self.pending.push_back(yielded);
                }
            });
            (task, received, opened)
        }
    }
}

struct ExhaustionDiagnostic(Arc<std::sync::atomic::AtomicUsize>);

impl tracing::Subscriber for ExhaustionDiagnostic {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Reason<'a>(&'a std::sync::atomic::AtomicUsize);
        impl tracing::field::Visit for Reason<'_> {
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "reason" && value == "resource_exhausted" {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        event.record(&mut Reason(&self.0));
    }
}

#[tokio::test]
async fn configured_exhaustion_reports_one_clear_operator_error_and_takes_no_preaccept_bytes() {
    use busbar_kernel::plane_driver::CallerEnd;
    let diagnostics = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dispatch = tracing::Dispatch::new(ExhaustionDiagnostic(Arc::clone(&diagnostics)));
    let _subscriber = tracing::dispatcher::set_default(&dispatch);
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let leg = CallerLeg::new(&door, Messages::new(8));
    let pairing = Pairing::with_memory_limit(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
        Some(1),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    let (head, _answer) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from: Messages::new(8),
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    };
    assert!(!CallerEnd::write(&caller, b"unaccepted").await);
    assert!(!CallerEnd::write(&caller, b"also unaccepted").await);
    assert_eq!(diagnostics.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        pairing.publication_outcome().failure.as_deref(),
        Some(busbar_core_connector::datagram::LINE_MEMORY_EXHAUSTED)
    );
    assert_eq!(pairing.publication_outcome().original_bytes, 0);
    assert!(pairing.closed());
}

include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
owner_test_sources!(datagram_wire);
