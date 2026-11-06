// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(feature = "transport-webrtc")]

use std::future::Future;
use std::task::{Context, Waker};

use busbar_core_connector::datagram::{Leg, LINE_MEMORY_EXHAUSTED};
use busbar_core_connector::framer::FRAME_CAP;
use busbar_core_connector::test_support::datagram_output_reservation_bytes;
use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};

use super::tests::real::{Pair, WAIT};

fn limit() -> usize {
    4 * datagram_output_reservation_bytes() + 32 * FRAME_CAP
}

#[tokio::test]
async fn a_finite_real_channel_preserves_messages_in_both_directions() {
    let mut pair = Pair::with_limit(limit()).await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    let before = pair.pairing.publication_outcome();
    for n in 0..16_u8 {
        let mut bytes = vec![n; FRAME_CAP];
        bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
        assert!(tokio::time::timeout(WAIT, pair.caller.write(&bytes))
            .await
            .unwrap());
        assert_eq!(
            pair.received().await,
            bytes,
            "one accepted source reaches the real peer exactly once"
        );
        pair.send(&bytes).await;
        assert_eq!(
            tokio::time::timeout(WAIT, pair.caller.read())
                .await
                .unwrap(),
            Some(bytes)
        );
        assert!(pair.pairing.published().await.failure.is_none());
    }
    let emitted = pair.framer.emitted.lock().unwrap().clone();
    eprintln!("actual ABI Emit lengths (including empty same-operation recalls): {emitted:?}");
    assert!(
        emitted.iter().all(|&len| len == 0 || len == FRAME_CAP),
        "every crossing is one full source or an empty recall: {emitted:?}"
    );
    assert_eq!(
        emitted.iter().filter(|&&len| len != 0).count(),
        16,
        "each accepted source crosses exactly once: {emitted:?}"
    );
    let outcome = pair.pairing.published().await;
    let accepted_bytes = 16 * FRAME_CAP as u64;
    assert_eq!(
        outcome.original_bytes - before.original_bytes,
        accepted_bytes
    );
    assert_eq!(
        outcome.original_handed_bytes - before.original_handed_bytes,
        accepted_bytes
    );
    assert_eq!(
        outcome.original_cancelled_bytes,
        before.original_cancelled_bytes
    );
    assert_eq!(
        outcome.original_uncertain_bytes,
        before.original_uncertain_bytes
    );
    assert!(!pair.pairing.closed());
    assert!(pair.pairing.memory_account().used() <= limit());
}

#[tokio::test]
async fn real_reader_custody_remains_charged_until_the_last_consumer_releases_it() {
    let pair = Pair::with_limit(limit()).await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    let memory = pair.pairing.memory_account();
    let before = memory.used();
    let bytes = vec![b'x'; FRAME_CAP];
    pair.send(&bytes).await;
    let input = tokio::time::timeout(WAIT, pair.caller.read_owned())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(input.bytes, bytes);
    assert!(input.custody.is_some());
    assert!(
        memory.used() >= before + bytes.len(),
        "actual reader owns its retained payload"
    );
    let custody = input.custody.clone();
    let held = memory.used();
    drop(input);
    assert_eq!(
        memory.used(),
        held,
        "cloning custody cannot retire its payload early"
    );
    drop(custody);
    assert!(
        memory.used() < held,
        "the last actual consumer releases the payload charge"
    );
    assert!(pair.pairing.published().await.failure.is_none());
}

#[tokio::test]
async fn an_unaccepted_write_waits_for_upstream_reader_credit_and_cancelled_bytes_never_cross() {
    let mut pair = Pair::with_limit(limit()).await;
    let memory = pair.pairing.memory_account();

    let capacity = limit() - memory.used() - 1024;
    let bytes = vec![0_u8; capacity];
    let custody = pair
        .pairing
        .reserve_input_for(Leg::Upstream, bytes.capacity())
        .unwrap()
        .reader_on(Leg::Upstream);
    let before = pair.pairing.publication_outcome();
    let cancelled_bytes = vec![b'c'; FRAME_CAP];
    let mut cancelled = Box::pin(pair.caller.write(&cancelled_bytes));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    assert_eq!(
        pair.pairing.publication_outcome(),
        before,
        "Pending accepts no bytes"
    );
    assert!(
        pair.framer.emitted.lock().unwrap().is_empty(),
        "no ABI Emit before actual storage credit"
    );
    drop(cancelled);
    #[derive(Default)]
    struct CreditWake(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for CreditWake {
        fn wake(self: std::sync::Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let wake = std::sync::Arc::new(CreditWake::default());
    let waker = Waker::from(wake.clone());
    let fresh = vec![b'f'; FRAME_CAP];
    let mut writing = Box::pin(pair.caller.write(&fresh));
    assert!(writing
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    assert_eq!(pair.pairing.publication_outcome(), before);
    let registered = wake.0.load(std::sync::atomic::Ordering::SeqCst);
    drop(bytes);
    drop(custody);
    assert!(
        wake.0.load(std::sync::atomic::Ordering::SeqCst) > registered,
        "actual upstream reader retirement wakes the same unaccepted write"
    );
    assert!(tokio::time::timeout(WAIT, writing).await.unwrap());
    assert_eq!(pair.received().await, fresh);
    assert_eq!(*pair.framer.emitted.lock().unwrap(), vec![FRAME_CAP]);
    let outcome = pair.pairing.published().await;
    assert!(outcome.failure.is_none());
    assert_eq!(
        outcome.original_bytes - before.original_bytes,
        FRAME_CAP as u64
    );
    assert_eq!(
        outcome.original_handed_bytes - before.original_handed_bytes,
        FRAME_CAP as u64
    );
    assert_eq!(
        outcome.original_cancelled_bytes,
        before.original_cancelled_bytes
    );
    assert!(!pair.pairing.closed());
}

#[tokio::test]
async fn own_unread_real_output_cannot_keep_an_unaccepted_write_waiting() {
    let pair = Pair::with_limit(limit()).await;
    assert_eq!(pair.caller.read().await, Some(Vec::new()));
    pair.send(&vec![b'x'; FRAME_CAP]).await;
    let input = tokio::time::timeout(WAIT, pair.caller.read_owned())
        .await
        .unwrap()
        .unwrap();
    let before = pair.pairing.publication_outcome();
    assert!(
        !tokio::time::timeout(WAIT, pair.caller.write(&vec![b'i'; limit()]))
            .await
            .expect("own unread output causes explicit preaccept refusal")
    );
    let outcome = pair.pairing.published().await;
    assert_eq!(outcome.failure.as_deref(), Some(LINE_MEMORY_EXHAUSTED));
    assert_eq!(outcome.original_bytes, before.original_bytes);
    assert_eq!(outcome.original_handed_bytes, before.original_handed_bytes);
    assert_eq!(
        outcome.original_uncertain_bytes,
        before.original_uncertain_bytes
    );
    assert!(pair.framer.emitted.lock().unwrap().is_empty());
    assert!(pair.pairing.closed());
    let memory = pair.pairing.memory_account();
    assert!(
        memory.used() >= input.bytes.len(),
        "accepted reader output stays in custody after refusal"
    );
    drop(input);
}

#[tokio::test]
async fn shutdown_wakes_a_credit_waiter_without_crossing_or_accepting_its_input() {
    let pair = Pair::with_limit(limit()).await;
    let memory = pair.pairing.memory_account();
    let bytes = vec![0_u8; limit() - memory.used() - 1024];
    let custody = pair
        .pairing
        .reserve_input_for(Leg::Upstream, bytes.capacity())
        .unwrap()
        .reader_on(Leg::Upstream);
    let before = pair.pairing.publication_outcome();
    let input = vec![b'i'; FRAME_CAP];
    let mut writing = Box::pin(pair.caller.write(&input));
    assert!(writing
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    pair.door.close();
    assert!(!tokio::time::timeout(WAIT, writing).await.unwrap());
    assert_eq!(
        pair.pairing.publication_outcome().original_bytes,
        before.original_bytes
    );
    assert!(pair.framer.emitted.lock().unwrap().is_empty());
    assert!(pair.pairing.closed());
    drop(bytes);
    drop(custody);
}
