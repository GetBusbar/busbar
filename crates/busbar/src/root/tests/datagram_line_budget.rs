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
    assert_eq!(pair.framer.emitted.lock().unwrap().len(), 16);
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
    // This is the host reservation seam for an upstream reader, independent of
    // the peer protocol. No plugin yield is invented to manufacture pressure.
    let capacity = limit() - memory.used() - 1024;
    let bytes = vec![0_u8; capacity];
    let custody = pair
        .pairing
        .reserve_input_for(Leg::Upstream, bytes.capacity())
        .unwrap()
        .reader();
    let before = pair.pairing.publication_outcome();
    let mut cancelled = Box::pin(pair.caller.write(b"cancelled"));
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
    drop(bytes);
    drop(custody);
    assert!(tokio::time::timeout(WAIT, pair.caller.write(b"fresh"))
        .await
        .unwrap());
    assert_eq!(pair.received().await, b"fresh");
    assert_eq!(*pair.framer.emitted.lock().unwrap(), vec![5]);
    let outcome = pair.pairing.published().await;
    assert!(outcome.failure.is_none());
    assert_eq!(outcome.original_bytes - before.original_bytes, 5);
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
        .reader();
    let before = pair.pairing.publication_outcome();
    let mut writing = Box::pin(pair.caller.write(b"never accepted"));
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
