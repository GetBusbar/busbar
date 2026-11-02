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

// These controls drive genuine WebRTC bytes over the root's UDP socket. The
// observer never fabricates a yield or alters the product's returned ABI data.
#[cfg(feature = "transport-webrtc")]
pub(crate) mod real {
    use super::*;
    use busbar_contract::transport::TransportSettings;
    use busbar_core_connector::datagram::DatagramFraming;
    use busbar_core_connector::dtls::SessionCert;
    use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor, Yielded};
    use busbar_core_connector::{Connector, DialJudge, Judged, Verdict};
    use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    pub(crate) const WAIT: Duration = Duration::from_secs(10);
    type Observer = Arc<dyn Fn(usize) + Send + Sync>;
    pub(crate) struct Observed {
        inner: Arc<dyn FramerDoor>,
        pub(crate) emitted: Mutex<Vec<usize>>,
        pub(crate) observer: Mutex<Option<Observer>>,
    }
    impl FramerDoor for Observed {
        fn facts(&self) -> &DoorFacts {
            self.inner.facts()
        }
        fn cross(&self, call: Call<'_>) -> Crossed {
            if let Call::Emit(input, _) = &call {
                self.emitted.lock().unwrap().push(input.len);
                let observe = self.observer.lock().unwrap().clone();
                if let Some(observe) = observe {
                    observe(input.len);
                }
            }
            self.inner.cross(call)
        }
    }
    pub(crate) fn loaded() -> Arc<dyn FramerDoor> {
        let plugin = crate::root::test_plugins::linked_transport(
            busbar_transport_webrtc::door,
            crate::root::doors::bind(),
        );
        Arc::new(
            crate::root::doors::Dispatched::open(plugin, &TransportSettings::default()).unwrap(),
        )
    }
    struct Loopback;
    impl DialJudge for Loopback {
        fn judge_dial(&self, dest: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
            Some(
                dest.parse::<SocketAddr>()
                    .ok()
                    .filter(|a| a.ip().is_loopback())
                    .ok_or(1),
            )
        }
    }
    pub(crate) enum Input {
        Message(Vec<u8>),
        Raw(Vec<u8>),
    }
    pub(crate) struct Pair {
        pub(crate) door: Arc<ClaimDoor>,
        pub(crate) caller: super::super::DatagramCaller,
        pub(crate) pairing: Arc<Pairing>,
        pub(crate) framer: Arc<Observed>,
        pub(crate) input: tokio::sync::mpsc::Sender<Input>,
        received: tokio::sync::mpsc::Receiver<Vec<u8>>,
        pub(crate) connector: Arc<Connector>,
        peer: tokio::task::JoinHandle<()>,
    }
    fn collect(y: Yielded, tx: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        for piece in y.pieces {
            assert!(
                !piece.failed,
                "actual WebRTC stream failed: {:?}",
                piece.reason
            );
            if piece.stream != 0 && !piece.fields && !piece.end {
                tx.try_send(piece.bytes)
                    .expect("bounded actual peer output");
            }
        }
    }
    impl Pair {
        pub(crate) async fn new(early: &[&[u8]]) -> Self {
            Self::on(
                ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap()),
                early,
            )
            .await
        }
        pub(crate) async fn on(door: Arc<ClaimDoor>, early: &[&[u8]]) -> Self {
            Self::configured(door, early, None, None).await
        }
        pub(crate) async fn with_limit(limit: usize) -> Self {
            Self::configured(
                ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap()),
                &[],
                Some(limit),
                None,
            )
            .await
        }
        pub(crate) async fn with_framer(door: Arc<ClaimDoor>, framer: Arc<dyn FramerDoor>) -> Self {
            Self::configured(door, &[], None, Some(framer)).await
        }
        async fn configured(
            door: Arc<ClaimDoor>,
            early: &[&[u8]],
            limit: Option<usize>,
            inner: Option<Arc<dyn FramerDoor>>,
        ) -> Self {
            let framer = Arc::new(Observed {
                inner: inner.unwrap_or_else(loaded),
                emitted: Mutex::new(Vec::new()),
                observer: Mutex::new(None),
            });
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (mut peer, offer) = DatagramFraming::dial(
                loaded(),
                Arc::new(SessionCert::mint().unwrap()),
                socket.local_addr().unwrap(),
                &[("channel".into(), b"events".to_vec())],
                Arc::new(Loopback),
                0,
            )
            .unwrap();
            let offer = offer
                .pieces
                .into_iter()
                .find(|p| p.stream == 0 && !p.fields)
                .unwrap()
                .bytes;
            let opened = {
                let limits = busbar_kernel::config::limits::LimitsResolved {
                    datagram_line_memory_bytes: limit,
                    ..Default::default()
                };
                let _scope = busbar_kernel::config::limits::BuildScope::enter(&limits);
                super::super::Opened::open(&door, framer.clone(), &offer).unwrap()
            };
            let super::super::Opened {
                caller,
                joining,
                description,
                head,
            } = opened;
            let pairing = lock(&caller.leg.pairing).clone().unwrap();
            for bytes in early {
                assert!(caller.write(bytes).await);
            }
            assert_eq!(lock(&caller.leg.outbound).held.len(), early.len());
            let connector = Arc::new(Connector::new());
            joining.admit_into(1, &connector).unwrap();
            let first = peer.rendezvous(&description.bytes, Instant::now()).unwrap();
            drop((description, head));
            let (input, mut commands) = tokio::sync::mpsc::channel(32);
            let (output, received) = tokio::sync::mpsc::channel(CALLER_QUEUE + 32);
            let target = door.local();
            let peer = tokio::spawn(async move {
                collect(first, &output);
                let mut bytes = vec![0; 65536];
                loop {
                    while let Some((to, bytes)) = peer.poll_send() {
                        socket.send_to(&bytes, to).await.unwrap();
                    }
                    let yielded = tokio::select! {
                        input = commands.recv() => match input {
                            Some(Input::Message(bytes)) => peer.emit(1, &bytes, true, false, Instant::now()).unwrap(),
                            Some(Input::Raw(bytes)) => { socket.send_to(&bytes, target).await.unwrap(); continue; }
                            None => break,
                        },
                        got = socket.recv_from(&mut bytes) => {
                            let (n, from) = got.unwrap();
                            peer.datagram(from, &bytes[..n], Instant::now()).unwrap()
                        },
                        () = tokio::time::sleep(Duration::from_millis(10)) => peer.timeout(Instant::now()).unwrap(),
                    };
                    collect(yielded, &output);
                }
            });
            tokio::time::timeout(WAIT, async {
                while lock(&caller.leg.outbound).channel.is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("actual ICE, DTLS and SCTP establish the root's data channel");
            Self {
                door,
                caller,
                pairing,
                framer,
                input,
                received,
                connector,
                peer,
            }
        }
        pub(crate) async fn received(&mut self) -> Vec<u8> {
            tokio::time::timeout(WAIT, self.received.recv())
                .await
                .expect("real peer receives before timeout")
                .expect("live peer")
        }
        pub(crate) async fn send(&self, bytes: &[u8]) {
            self.input
                .send(Input::Message(bytes.to_vec()))
                .await
                .unwrap();
        }
    }
    impl Drop for Pair {
        fn drop(&mut self) {
            self.connector.unpair(1);
            self.door.close();
            self.peer.abort();
        }
    }
}

#[cfg(feature = "transport-webrtc")]
#[tokio::test]
async fn a_real_channel_releases_early_writes_in_fifo_order_and_keeps_descriptions_out_of_messages()
{
    use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};
    let mut pair = real::Pair::new(&[b"early one", b"early two"]).await;
    assert_eq!(pair.received().await, b"early one");
    assert_eq!(pair.received().await, b"early two");
    assert!(pair.caller.write(b"after opening").await);
    assert_eq!(pair.received().await, b"after opening");
    assert!(lock(&pair.caller.leg.outbound).held.is_empty());
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    pair.send(b"from real peer").await;
    assert_eq!(
        tokio::time::timeout(real::WAIT, pair.caller.read())
            .await
            .unwrap(),
        Some(b"from real peer".to_vec())
    );
    assert!(
        pair.caller.from.try_recv().is_err(),
        "the SDP is never an application piece"
    );
    assert!(!pair.pairing.closed());
}

#[cfg(feature = "transport-webrtc")]
#[tokio::test]
async fn early_writes_up_to_the_bound_cross_the_real_channel_once() {
    let bytes: Vec<_> = (0..CALLER_QUEUE).map(|_| b"early".as_slice()).collect();
    let mut pair = real::Pair::new(&bytes).await;
    for _ in 0..CALLER_QUEUE {
        assert_eq!(pair.received().await, b"early");
    }
    assert_eq!(pair.framer.emitted.lock().unwrap().len(), CALLER_QUEUE);
    assert!(!pair.pairing.closed());
}

#[cfg(feature = "transport-webrtc")]
#[tokio::test]
async fn closing_an_actual_channel_ends_pending_reads_and_refuses_later_writes() {
    use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};
    let pair = real::Pair::new(&[]).await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    pair.door.close();
    assert!(pair.pairing.closed());
    assert_eq!(
        tokio::time::timeout(real::WAIT, pair.caller.read())
            .await
            .unwrap(),
        None
    );
    assert!(!pair.caller.write(b"after shutdown").await);
    assert!(pair.door.assocs.is_empty());
    assert!(lock(&pair.door.legs).is_empty());
}

#[cfg(feature = "transport-webrtc")]
#[tokio::test]
async fn boot_binds_a_claim_door_for_the_actual_datagram_product_and_no_stream_listener() {
    use super::ClaimDoors;
    fn need(transport: &str, listen: &str) -> crate::root::loader::boot::InboundBind {
        crate::root::loader::boot::InboundBind {
            owner: crate::root::loader::boot::BindOwner::Need {
                instance: "streams".into(),
                kind: busbar_contract::abi::mechanism::KindCode::Plane,
                need: 0,
            },
            transport: transport.into(),
            at: format!("streams.{transport}"),
            listen: listen.parse().unwrap(),
            tls: None,
            max_conns: 1024,
        }
    }
    fn framers(scheme: &str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
        match scheme {
            "webrtc" => Some(real::loaded()),
            "http" => {
                let plugin = crate::root::test_plugins::linked_transport(
                    busbar_transport_http::door::door,
                    crate::root::doors::bind(),
                );
                Some(Arc::new(
                    crate::root::doors::Dispatched::open(
                        plugin,
                        &busbar_contract::transport::TransportSettings::default(),
                    )
                    .unwrap(),
                ))
            }
            _ => None,
        }
    }
    let doors = ClaimDoors::bind(
        &[need("http", "127.0.0.1:0"), need("webrtc", "127.0.0.1:0")],
        framers,
    )
    .unwrap();
    assert!(doors.get("http").is_none());
    let door = doors.get("webrtc").unwrap();
    assert!(door.local().ip().is_loopback());
    assert_ne!(door.local().port(), 0);
    assert!(ClaimDoors::bind(&[need("webrtc", "0.0.0.0:0")], framers)
        .unwrap_err()
        .contains("streams.webrtc.listen"));
    assert!(ClaimDoors::bind(
        &[need("webrtc", "127.0.0.1:0"), need("webrtc", "127.0.0.1:0")],
        framers
    )
    .unwrap_err()
    .contains("a second claim door"));
}
