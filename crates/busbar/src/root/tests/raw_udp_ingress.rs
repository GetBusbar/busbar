// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(feature = "transport-webrtc")]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Waker};
use std::time::Instant;

use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};

use super::tests::real::{Input, Pair, WAIT};
use super::{lock, ClaimDoor};

struct Parked {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<bool>>,
}
impl Parked {
    fn start(pair: &Pair) -> (Self, std::sync::mpsc::Receiver<()>) {
        let (entered, inside) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let resume = std::sync::Mutex::new(resume);
        *pair.framer.observer.lock().unwrap() = Some(Arc::new(move |len| {
            if len == b"occupied".len() {
                let _ = entered.send(());
                let _ = resume.lock().unwrap().recv();
            }
        }));
        let door = pair.door.clone();
        let id = lock(&pair.caller.leg.id).unwrap();
        let thread =
            std::thread::spawn(move || door.emit(id, 1, b"occupied", true, false, Instant::now()));
        (
            Self {
                release: Some(release),
                thread: Some(thread),
            },
            inside,
        )
    }
    fn finish(mut self) -> bool {
        self.release.take().unwrap().send(()).unwrap();
        self.thread.take().unwrap().join().unwrap()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_output_credit_readiness_drops_before_acceptance_and_resumes_without_replay() {
    use busbar_core_connector::datagram::Leg;
    use busbar_core_connector::framer::FRAME_CAP;
    use busbar_core_connector::test_support::datagram_output_reservation_bytes;

    let limit = 4 * datagram_output_reservation_bytes() + 32 * FRAME_CAP;
    let pair = Pair::with_limit(limit).await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    assert!(pair.pairing.published().await.failure.is_none());
    let memory = pair.pairing.memory_account();

    let held = vec![0_u8; limit - memory.used() - 1024];
    let custody = pair
        .pairing
        .reserve_input_for(Leg::Caller, held.capacity())
        .unwrap();
    let before = pair.pairing.publication_outcome();
    let used = memory.used();
    let ingested = pair.framer.ingested.lock().unwrap().clone();
    let dropped_before = pair.door.assocs.raw_busy_dropped();
    pair.input
        .send(Input::Raw(b"\x80no-output-credit".to_vec()))
        .await
        .unwrap();
    tokio::time::timeout(WAIT, async {
        while pair.door.assocs.raw_busy_dropped() == dropped_before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("missing output credit refuses raw input before framer acceptance");
    assert_eq!(pair.door.assocs.raw_busy_dropped(), dropped_before + 1);
    assert_eq!(pair.pairing.publication_outcome(), before);
    assert_eq!(memory.used(), used);
    assert_eq!(
        *pair.framer.ingested.lock().unwrap(),
        ingested,
        "receive-readiness refusal never crosses the real framer"
    );
    assert!(!pair.pairing.closed());
    assert!(pair.caller.from.try_recv().is_err());
    drop(held);
    drop(custody);

    pair.send(b"credit returned").await;
    assert_eq!(
        tokio::time::timeout(WAIT, pair.caller.read())
            .await
            .unwrap(),
        Some(b"credit returned".to_vec())
    );
    assert!(pair.pairing.published().await.failure.is_none());
    assert!(
        pair.caller.from.try_recv().is_err(),
        "no discarded input replay"
    );
    assert_eq!(pair.door.assocs.raw_busy_dropped(), dropped_before + 1);
    assert!(!pair.pairing.closed());
    pair.door.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_raw_ingress_drops_before_acceptance_and_other_real_associations_progress() {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let mut a = Pair::on(door.clone(), &[]).await;
    let b = Pair::on(door.clone(), &[]).await;
    assert_eq!(b.caller.read().await, Some(Vec::new()));
    assert_eq!(a.caller.read().await, Some(Vec::new()));

    for pair in [&a, &b] {
        pair.send(b"pause barrier").await;
        assert_eq!(
            tokio::time::timeout(WAIT, pair.caller.read())
                .await
                .unwrap(),
            Some(b"pause barrier".to_vec())
        );
    }
    // Finish the real channel exchange before parking its protocol driver: an
    // accepted SCTP message may still require the peer's advertised timer or ACK.
    a.pause().await;
    b.pause().await;
    let (parked, inside) = Parked::start(&a);
    inside.recv_timeout(WAIT).expect("host crossing paused");
    let wake = Waker::noop();
    let mut cx = Context::from_waker(wake);
    let mut cancelled = Box::pin(a.caller.write(b"cancelled"));
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    drop(cancelled);
    let mut pending = Box::pin(a.caller.write(b"accepted once"));
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    let before = door.assocs.raw_busy_dropped();

    for bytes in [
        b"\x80busy-one".as_slice(),
        b"\x80busy-two",
        b"\x80busy-three",
    ] {
        a.input.send(Input::Raw(bytes.to_vec())).await.unwrap();
    }
    tokio::time::timeout(WAIT, async {
        while door.assocs.raw_busy_dropped() < before + 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("busy raw inputs are counted before acceptance");
    assert_eq!(
        door.assocs.raw_busy_dropped(),
        before + 3,
        "only the three injected raw packets entered this paused-peer window"
    );
    b.resume().await;
    b.send(b"healthy").await;
    assert_eq!(
        tokio::time::timeout(WAIT, b.caller.read()).await.unwrap(),
        Some(b"healthy".to_vec())
    );
    assert!(
        !b.pairing.closed(),
        "one busy association cannot stall the shared socket"
    );
    assert!(parked.finish());
    assert!(tokio::time::timeout(WAIT, pending).await.unwrap());
    a.resume().await;
    assert_eq!(a.received().await, b"occupied");
    assert_eq!(a.received().await, b"accepted once");
    assert_eq!(
        *a.framer.emitted.lock().unwrap(),
        vec![8, 13],
        "cancelled input never crosses"
    );
    assert!(a.pairing.published().await.failure.is_none());
    assert!(b.pairing.published().await.failure.is_none());

    a.send(b"after release").await;
    assert_eq!(
        tokio::time::timeout(WAIT, a.caller.read()).await.unwrap(),
        Some(b"after release".to_vec())
    );
    assert!(
        a.caller.from.try_recv().is_err(),
        "dropped raw packets are never replayed as application data"
    );
    door.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_a_busy_real_association_cancels_unaccepted_writes_and_retires_its_path() {
    let a = Pair::new(&[]).await;
    let door = a.door.clone();
    let (parked, inside) = Parked::start(&a);
    inside.recv_timeout(WAIT).unwrap();
    let mut pending = Box::pin(a.caller.write(b"closed waiter"));
    assert!(pending
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    a.pairing.close();
    assert!(parked.finish());
    assert!(!tokio::time::timeout(WAIT, pending).await.unwrap());
    assert_eq!(*a.framer.emitted.lock().unwrap(), vec![8]);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());

    let replacement = Pair::on(door.clone(), &[]).await;
    assert_ne!(*lock(&a.caller.leg.id), *lock(&replacement.caller.leg.id));
    replacement.send(b"replacement").await;
    assert_eq!(replacement.caller.read().await, Some(Vec::new()));
    assert_eq!(
        tokio::time::timeout(WAIT, replacement.caller.read())
            .await
            .unwrap(),
        Some(b"replacement".to_vec())
    );
    assert_eq!(a.caller.read().await, Some(Vec::new()));
    assert_eq!(
        tokio::time::timeout(WAIT, a.caller.read()).await.unwrap(),
        None
    );
    assert!(!replacement.pairing.closed());
    door.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_real_srtp_line_reaches_the_real_upstream_framer_once() {
    use crate::root::serve::serve_datagram::peer::FIRST_AUDIO_STREAM as MEDIA_BASE;
    use busbar_contract::conn::PieceKind;
    use busbar_contract::transport::wire::WireStatusClass;
    use busbar_core_connector::datagram::DatagramFraming;
    use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
    use tokio::net::UdpSocket;

    const OPUS: &[u8] = &[0xF8, 1, 2, 3, 4];

    struct Upstream {
        inner: Arc<dyn FramerDoor>,
        emitted: std::sync::Mutex<Vec<(u64, usize)>>,
    }
    impl FramerDoor for Upstream {
        fn facts(&self) -> &DoorFacts {
            self.inner.facts()
        }
        fn cross(&self, call: Call<'_>) -> Crossed {
            if let Call::Emit(input, _) = &call {
                self.emitted.lock().unwrap().push((input.stream, input.len));
            }
            self.inner.cross(call)
        }
    }
    struct Tasks(Vec<tokio::task::JoinHandle<()>>);
    impl Drop for Tasks {
        fn drop(&mut self) {
            for task in &self.0 {
                task.abort();
            }
        }
    }

    use busbar_contract::conn::{Conns, InstanceId, NeedId, OpenDesc, PollConns};
    use busbar_contract::transport::TransportSettings;
    use http_body_util::Full;

    let pair = Pair::with_audio().await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));

    pair.send(b"SRTP ingress window").await;
    assert_eq!(
        tokio::time::timeout(WAIT, pair.caller.read())
            .await
            .unwrap(),
        Some(b"SRTP ingress window".to_vec())
    );

    pair.pause().await;
    let mut entries = crate::root::connector::entries(
        crate::LINKED_TRANSPORT_DOORS,
        &TransportSettings::default(),
    )
    .unwrap();
    let entry = entries
        .iter_mut()
        .find(|entry| entry.door.facts().datagram)
        .unwrap();
    let observed = Arc::new(Upstream {
        inner: entry.door.clone(),
        emitted: std::sync::Mutex::new(Vec::new()),
    });
    entry.door = observed.clone();
    let connector = busbar_core_connector::process::build_with_secrets(
        || Ok(entries),
        crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
            block_private_addresses: true,
            allow: vec!["127.0.0.1".into()],
            ..Default::default()
        })
        .unwrap(),
        &[],
        Arc::new(|_, _| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
        busbar_core_connector::spawn_env::linked_spawn_secret,
    )
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (peer, _) =
        DatagramFraming::accept_minted(super::tests::real::loaded(), socket.local_addr().unwrap())
            .unwrap();
    let signal = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/session", signal.local_addr().unwrap());
    let (peer_out, peer_in) = tokio::sync::oneshot::channel();
    let peer = Arc::new(std::sync::Mutex::new(Some((peer, peer_out))));
    let mut tasks = Tasks(Vec::new());
    let signaling = tokio::spawn(async move {
        let (socket, _) = signal.accept().await.unwrap();
        let service =
            hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let peer = peer.clone();
                async move {
                    assert_eq!(request.method(), hyper::Method::POST);
                    assert_eq!(request.uri().path(), "/session");
                    let description =
                        axum::body::to_bytes(axum::body::Body::new(request.into_body()), 64 * 1024)
                            .await
                            .unwrap();
                    assert!(
                        description.starts_with(b"v=0\r\n"),
                        "the actual production HTTP/TCP path carries real SDP"
                    );
                    let (mut peer, peer_out) = peer.lock().unwrap().take().unwrap();
                    let answer = peer.rendezvous(&description, Instant::now()).unwrap();
                    let answer = answer
                        .pieces
                        .iter()
                        .find(|p| p.stream == 0 && !p.fields)
                        .unwrap()
                        .bytes
                        .clone();
                    peer_out
                        .send(peer)
                        .unwrap_or_else(|_| panic!("actual far peer remains owned by the test"));
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(201)
                            .header("content-type", "application/sdp")
                            .body(Full::new(bytes::Bytes::from(answer)))
                            .unwrap(),
                    )
                }
            });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
            .await
            .unwrap();
    });
    tasks.0.push(signaling);
    let owner = InstanceId(91);
    let need = NeedId(1);
    connector
        .declare_need_to(
            owner,
            need,
            "webrtc",
            busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE,
            &target,
        )
        .unwrap();
    let unit = 27;
    connector.pair(unit, pair.pairing.clone()).unwrap();
    let connection = connector
        .open(
            owner,
            need,
            &OpenDesc {
                target: &target,
                fields: &[("content-type", b"application/sdp")],
                method: b"POST",
                head_target: b"/session",
                unit,
                timeout_ms: 5000,
                ..Default::default()
            },
        )
        .expect("production Connector::open begins the actual WebRTC-over-HTTP exchange");
    let heads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let driving = {
        let connector = connector.clone();
        let heads = heads.clone();
        tokio::spawn(async move {
            let mut bytes = [0_u8; 1024];
            loop {
                let piece = std::future::poll_fn(|cx| {
                    connector.poll_read(owner, connection, cx, &mut bytes)
                })
                .await
                .unwrap();
                assert_eq!(
                    piece.kind,
                    PieceKind::Fields,
                    "LINE forwarding creates no application channel body"
                );
                assert_eq!(piece.status, Some(WireStatusClass::Success));
                assert_eq!(piece.status_code, Some(201));
                heads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })
    };
    tasks.0.push(driving);
    let mut peer = tokio::time::timeout(WAIT, peer_in)
        .await
        .expect("actual production HTTP request reaches the real peer")
        .unwrap();
    let (opened, ready) = tokio::sync::oneshot::channel();
    let (delivered, mut received) = tokio::sync::mpsc::channel(8);
    let far = tokio::spawn(async move {
        let mut opened = Some(opened);
        let mut bytes = vec![0_u8; 65536];
        loop {
            while let Some((to, bytes)) = peer.poll_send() {
                socket.send_to(&bytes, to).await.unwrap();
            }
            let mut yielded = tokio::select! {
                got = socket.recv_from(&mut bytes) => {
                    let (n, from) = got.unwrap();
                    peer.datagram(from, &bytes[..n], Instant::now()).unwrap()
                },
                () = tokio::time::sleep(std::time::Duration::from_millis(10)) => peer.timeout(Instant::now()).unwrap(),
            };
            for piece in yielded.pieces.drain(..) {
                assert!(
                    !piece.failed,
                    "actual upstream peer failed: {:?}",
                    piece.reason
                );
                if piece.stream == 1 && piece.fields {
                    if let Some(opened) = opened.take() {
                        let _ = opened.send(());
                    }
                }
                if piece.stream == MEDIA_BASE && !piece.fields && !piece.end {
                    delivered.try_send(piece.bytes).unwrap();
                }
            }
        }
    });
    tasks.0.push(far);
    tokio::time::timeout(WAIT, ready)
        .await
        .expect("actual upstream ICE/DTLS/SCTP opens")
        .unwrap();
    let dropped_before_media = pair.door.assocs.raw_busy_dropped();
    pair.input.send(Input::Audio(OPUS.to_vec())).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, received.recv())
            .await
            .unwrap_or_else(|_| panic!(
                "actual paced SRTP did not reach the upstream: drops {} -> {}, publication {:?}, upstream emits {:?}",
                dropped_before_media,
                pair.door.assocs.raw_busy_dropped(),
                pair.pairing.publication_outcome(),
                observed.emitted.lock().unwrap()
            )),
        Some(OPUS.to_vec())
    );
    let outcome = pair.pairing.published().await;
    assert!(outcome.failure.is_none(), "{outcome:?}");
    assert_eq!(
        *observed.emitted.lock().unwrap(),
        vec![(MEDIA_BASE, OPUS.len())]
    );
    assert_eq!(
        (
            outcome.accepted_frames,
            outcome.handed_frames,
            outcome.cancelled_frames
        ),
        (1, 1, 0)
    );
    assert_eq!(
        (outcome.accepted_bytes, outcome.handed_bytes),
        (OPUS.len() as u64, OPUS.len() as u64)
    );
    assert!(
        pair.caller.from.try_recv().is_err(),
        "audio LINE never enters the application channel"
    );
    assert!(
        received.try_recv().is_err(),
        "one accepted SRTP frame is forwarded once"
    );
    assert_eq!(
        pair.door.assocs.raw_busy_dropped(),
        dropped_before_media,
        "the explicit SRTP frame incurs no receive-readiness drop in the paused-peer window"
    );
    assert_eq!(
        heads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the actual HTTP response head is observed once while SDP remains internal"
    );
    assert!(
        !tasks.0[1].is_finished(),
        "the actual connector reader remains live without application output"
    );
    connector.close(owner, connection).unwrap();
    connector.unpair(unit);
    assert!(pair.pairing.closed());
    pair.door.close();
}
