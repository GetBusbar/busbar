// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Controlled retirement seams around failed reservations, without timing or allocator probes.

use super::*;
use crate::datagram::Leg;
use std::future::Future;
use std::task::{Context, Poll};

fn full_reader(leg: Leg) -> (Arc<Memory>, ReaderCustody) {
    let memory = Memory::new(Some(Memory::reservation_size(128).unwrap()));
    let credit = memory.reserve(128).unwrap();
    let reader = credit.reader_on(leg);
    drop(credit);
    (memory, reader)
}

#[tokio::test]
async fn last_reader_retirement_between_refusal_and_wait_retries_the_freed_credit() {
    let (memory, reader) = full_reader(Leg::Upstream);
    let generation = memory.generation();
    assert!(memory.reserve(1).is_none());

    drop(reader);
    assert!(memory.reader_progress(generation).await);
    assert!(memory.reserve(128).is_some());
}

#[tokio::test]
async fn queued_custody_does_not_masquerade_as_an_active_consumption_transfer() {
    let (memory, reader) = full_reader(Leg::Caller);
    let generation = memory.generation();
    assert!(memory.reserve(1).is_none());
    assert!(!memory.reader_progress(generation).await);
    let transfer = reader.copying();
    let mut progress = Box::pin(memory.reader_progress(memory.generation()));
    let mut context = Context::from_waker(futures::task::noop_waker_ref());
    assert!(progress.as_mut().poll(&mut context).is_pending());
    drop(reader);
    assert!(progress.await);
    drop(transfer);
    assert_eq!(memory.used(), 0);
}

#[test]
fn input_fit_and_other_leg_progress_are_one_atomic_reservation_decision() {
    let (memory, reader) = full_reader(Leg::Caller);
    assert!(matches!(
        memory.input(1, false, Some(0)),
        Err(ReservationError::Exhausted)
    ));
    assert!(matches!(
        memory.input(1, false, Some(1)),
        Err(ReservationError::Pending)
    ));

    drop(reader);
    assert!(memory.input(128, false, Some(0)).is_ok());
}

#[test]
fn synchronous_driver_observes_a_retirement_before_registering_its_wait() {
    struct Sink;
    impl crate::datagram::LegSink for Sink {
        fn line(&self, _: crate::datagram::Across, _: std::time::Instant) {}
        fn close(&self) {}
    }
    let pair = crate::datagram::Pairing::with_memory_limit(
        Arc::new(Sink),
        "127.0.0.1:1".parse().unwrap(),
        Some(Memory::reservation_size(128).unwrap()),
    );
    let memory = pair.memory_account();
    let credit = memory.reserve(128).unwrap();
    let reader = credit.reader_on(Leg::Upstream);
    drop(credit);
    let generation = pair.storage_generation();
    assert!(memory.reserve(1).is_none());
    drop(reader);
    assert!(pair.wait_storage(futures::task::noop_waker_ref(), generation));
    assert!(!pair.closed());
    assert!(memory.reserve(128).is_some());
}

#[tokio::test]
async fn receiver_cancellation_retires_its_active_handoff_without_dropping_queued_output() {
    let (memory, reader) = full_reader(Leg::Caller);
    let messages = Messages::new(1);
    let mut receiving = Box::pin(messages.recv());
    let mut context = Context::from_waker(futures::task::noop_waker_ref());
    assert!(receiving.as_mut().poll(&mut context).is_pending());
    messages
        .send(Message {
            bytes: vec![b'x'],
            end: true,
            consumed: 0,
            custody: reader,
        })
        .unwrap();
    let mut progress = Box::pin(memory.reader_progress(memory.generation()));
    assert_eq!(progress.as_mut().poll(&mut context), Poll::Pending);
    drop(receiving);
    assert!(progress.await);
    assert!(
        messages.try_recv().is_ok(),
        "accepted output survives cancellation of a receive"
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn attached_owner_survives_queue_and_partial_consumption() {
    let (memory, reader) = full_reader(Leg::Caller);
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let queue = Messages::new(1);
    queue
        .send(Message {
            bytes: vec![1, 2, 3],
            end: true,
            consumed: 0,
            custody: reader.with_owner(owner).unwrap(),
        })
        .unwrap();
    assert!(
        weak.upgrade().is_some(),
        "enqueue already retains external custody"
    );
    let mut message = queue.try_recv().unwrap();
    message.consumed = 1;
    let copying = message.custody.copying();
    assert!(weak.upgrade().is_some());
    assert!(memory.used() > 0);
    drop(copying);
    assert!(weak.upgrade().is_some());
    drop(message);
    assert!(weak.upgrade().is_none());
    assert_eq!(memory.used(), 0);
}

#[test]
fn attaching_twice_preserves_existing_owner_until_reader_retires() {
    let (_, reader) = full_reader(Leg::Caller);
    let first = Arc::new(());
    let first_weak = Arc::downgrade(&first);
    let second = Arc::new(());
    let second_weak = Arc::downgrade(&second);
    let reader = reader.with_owner(first).unwrap();
    let reader = reader.with_owner(second).unwrap_err();
    assert!(first_weak.upgrade().is_some());
    assert!(second_weak.upgrade().is_none());
    drop(reader);
    assert!(first_weak.upgrade().is_none());
}

#[test]
fn rejected_and_abandoned_queues_release_attached_owners() {
    for closed in [false, true] {
        let (_, reader) = full_reader(Leg::Caller);
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let queue = Messages::new(1);
        if closed {
            queue.close();
        }
        let sent = queue.send(Message {
            bytes: vec![1],
            end: true,
            consumed: 0,
            custody: reader.with_owner(owner).unwrap(),
        });
        assert_eq!(sent.is_err(), closed);
        drop(sent);
        drop(queue);
        assert!(weak.upgrade().is_none());
    }
}
