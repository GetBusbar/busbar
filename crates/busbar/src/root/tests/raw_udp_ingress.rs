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

// Pause a host crossing while leaving the actual WebRTC output untouched.
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
    // Retain genuine host storage, leaving less than the next pre-read output
    // reservation. The actual WebRTC association and UDP path are established.
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

    // The discarded malformed RTP is a receive-readiness negative, not an echo
    // protocol. A fresh genuine SCTP message proves progress after retirement.
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
    // Pause autonomous ICE/timer work only after the real channels exist. An
    // explicit real message behind all prior peer sends is observed by the
    // root before the exact injected-drop window begins.
    a.pause().await;
    b.pause().await;
    for pair in [&a, &b] {
        pair.send(b"pause barrier").await;
        assert_eq!(
            tokio::time::timeout(WAIT, pair.caller.read())
                .await
                .unwrap(),
            Some(b"pause barrier".to_vec())
        );
    }
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
    // Genuine malformed RTP inputs exercise the host's receive-readiness seam.
    // WebRTC never promises arbitrary UDP echo or application delivery for them.
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
    // Live ICE resumes outside the exact injected window and may itself
    // encounter receive-not-ready. Its traffic is not one of our three inputs.
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
    // A new real peer negotiates fresh ICE credentials and owns a fresh path.
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
    use busbar_contract::conn::{ConnError, Piece, PieceKind};
    use busbar_contract::ids::StreamId;
    use busbar_contract::transport::wire::WireStatusClass;
    use busbar_core_connector::datagram::DatagramFraming;
    use busbar_core_connector::dtls::SessionCert;
    use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
    use busbar_core_connector::test_support::DatagramSession;
    use busbar_transport_webrtc::framing::MEDIA_BASE;
    use std::task::Poll;
    use tokio::net::UdpSocket;

    const OPUS: &[u8] = &[0xF8, 1, 2, 3, 4];
    // Observe the actual upstream operation without changing product output.
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

    let pair = Pair::with_audio().await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    let observed = Arc::new(Upstream {
        inner: super::tests::real::loaded(),
        emitted: std::sync::Mutex::new(Vec::new()),
    });
    let port = ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap();
    let (framing, offer) = DatagramFraming::dial(
        observed.clone(),
        Arc::new(SessionCert::mint().unwrap()),
        port.local_addr(),
        &[
            ("channel".into(), b"events".to_vec()),
            ("media".into(), b"audio".to_vec()),
        ],
        Arc::new(super::tests::real::Loopback),
        0,
    )
    .unwrap();
    let description = offer
        .pieces
        .iter()
        .find(|p| p.stream == 0 && !p.fields)
        .unwrap()
        .bytes
        .clone();
    // A dialling product yields its audio LINE head at Begin, before the
    // exchange answer. This direct host composition must publish that genuine
    // batch; keeping only the SDP loses the upstream half of the bridge.
    assert!(offer
        .pieces
        .iter()
        .any(|piece| piece.stream == MEDIA_BASE && piece.fields));
    let opening = pair.pairing.publish(
        busbar_core_connector::datagram::Leg::Upstream,
        offer,
        Instant::now(),
    );
    assert!(opening.pieces.iter().all(|piece| piece.stream == 0));
    drop(opening);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut peer, _) =
        DatagramFraming::accept_minted(super::tests::real::loaded(), socket.local_addr().unwrap())
            .unwrap();
    let answer = peer.rendezvous(&description, Instant::now()).unwrap();
    let answer = answer
        .pieces
        .iter()
        .find(|p| p.stream == 0 && !p.fields)
        .unwrap()
        .bytes
        .clone();
    let upstream = Arc::new(DatagramSession::new(framing, port, pair.pairing.clone()));
    for (kind, bytes) in [
        (PieceKind::Fields, &[][..]),
        (PieceKind::Body, answer.as_slice()),
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
            .expect("the genuine SDP answer settles the actual upstream");
    }
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
    let driving = {
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let mut bytes = [0_u8; 1024];
            std::future::poll_fn(|cx| match upstream.read(cx.waker(), &mut bytes) {
                Err(ConnError::Pending) => Poll::<()>::Pending,
                result => panic!(
                    "LINE forwarding must not create upstream application output: {result:?}"
                ),
            })
            .await;
        })
    };
    let _tasks = Tasks(vec![far, driving]);
    tokio::time::timeout(WAIT, ready)
        .await
        .expect("actual upstream ICE/DTLS/SCTP opens")
        .unwrap();
    pair.input.send(Input::Audio(OPUS.to_vec())).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, received.recv()).await.unwrap(),
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
    assert_eq!(pair.door.assocs.raw_busy_dropped(), 0);
    upstream.close();
    pair.door.close();
}
