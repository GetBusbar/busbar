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
        tokio::time::timeout(WAIT, pair.caller.read()).await.unwrap(),
        Some(b"credit returned".to_vec())
    );
    assert!(pair.pairing.published().await.failure.is_none());
    assert!(pair.caller.from.try_recv().is_err(), "no discarded input replay");
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
    assert_eq!(a.received().await, b"occupied");
    assert_eq!(a.received().await, b"accepted once");
    assert_eq!(
        *a.framer.emitted.lock().unwrap(),
        vec![8, 13],
        "cancelled input never crosses"
    );
    assert!(a.pairing.published().await.failure.is_none());
    assert!(b.pairing.published().await.failure.is_none());
    assert_eq!(door.assocs.raw_busy_dropped(), before + 3);
    a.send(b"after release").await;
    assert_eq!(a.caller.read().await, Some(Vec::new()));
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
