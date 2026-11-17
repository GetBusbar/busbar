// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::future::Future;
use std::task::{Context, Poll};

fn budget(count: usize) -> Arc<ProcessAdmission> {
    ProcessAdmission::with_limits(count, 16, 4)
}

#[test]
fn data_cannot_take_operator_count_or_bytes() {
    let budget = budget(2);
    let data = budget.try_enter(AdmissionClass::Data).unwrap();
    let held = data.try_reserve(12).unwrap();
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    assert!(data.try_reserve(1).is_err());
    let operator = budget.try_enter(AdmissionClass::Operator).unwrap();
    let reserved = operator.try_reserve(4).unwrap();
    assert!(operator.try_reserve(1).is_err());
    assert!(budget.try_enter(AdmissionClass::Operator).is_err());
    assert_eq!(budget.used(), (16, 12));
    drop((held, reserved, data, operator));
    assert_eq!(budget.used(), (0, 0));
    assert_eq!(budget.counts.as_ref().unwrap().total.available_permits(), 2);
}

#[test]
fn operator_can_borrow_spare_capacity_and_overflow_changes_nothing() {
    let budget = budget(2);
    let first = budget.try_enter(AdmissionClass::Operator).unwrap();
    let _second = budget.try_enter(AdmissionClass::Operator).unwrap();
    let credit = first.try_reserve(16).unwrap();
    assert_eq!(budget.used(), (16, 0));
    assert!(first.try_reserve(usize::MAX).is_err());
    assert_eq!(budget.used(), (16, 0));
    drop(credit);
    assert_eq!(budget.used(), (0, 0));
}

#[tokio::test]
async fn one_slot_is_operator_only_and_zero_keeps_count_unlimited() {
    let one = budget(1);
    assert!(one.try_enter(AdmissionClass::Data).is_err());
    assert!(one.enter(AdmissionClass::Data).await.is_err());
    let _operator = one.try_enter(AdmissionClass::Operator).unwrap();
    let unlimited = budget(0);
    let data: Vec<_> = (0..64)
        .map(|_| unlimited.try_enter(AdmissionClass::Data).unwrap())
        .collect();
    let credit = data[0].try_reserve(12).unwrap();
    assert!(data[1].try_reserve(1).is_err());
    let operator = unlimited.try_enter(AdmissionClass::Operator).unwrap();
    let _reserved = operator.try_reserve(4).unwrap();
    drop(credit);
    assert_eq!(unlimited.used(), (4, 0));
}

#[test]
fn production_floors_are_inside_the_configured_totals() {
    let budget = ProcessAdmission::new(8192);
    let counts = budget.counts.as_ref().unwrap();
    assert_eq!(counts.total.available_permits(), 8192);
    assert_eq!(counts.data.available_permits(), 8160);
    assert_eq!(budget.byte_limit, 256 * 1024 * 1024);
    assert_eq!(budget.data_byte_limit, 224 * 1024 * 1024);
}

#[test]
fn backed_clones_and_independent_copies_retain_actual_storage_and_request() {
    let budget = budget(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let bytes = request.copy_input(b"abcd").unwrap().into_bytes();
    let clone = bytes.slice(1..3);
    let copy = request.copy_input(&clone).unwrap().into_bytes();
    assert_eq!(budget.used(), (6, 6));
    drop((request, bytes));
    assert_eq!(budget.used(), (6, 6));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(clone);
    assert_eq!(budget.used(), (2, 2));
    drop(copy);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn split_merge_and_unique_gather_transfer_credit_without_double_charge() {
    let budget = budget(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let mut credit = request.try_reserve(8).unwrap();
    let split = credit.split(3).unwrap();
    assert_eq!(credit.len(), 5);
    assert_eq!(budget.used(), (8, 8));
    credit.try_merge(split).unwrap();
    assert_eq!(credit.len(), 8);
    assert!(credit.split(9).is_err());
    drop(credit);
    let mut first = request.copy_input(b"abcd").unwrap();
    first
        .try_append(request.copy_input(b"efgh").unwrap())
        .unwrap();
    assert_eq!(budget.used(), (8, 8));
    let whole = first.into_bytes();
    assert_eq!(&whole[..], b"abcdefgh");
    drop(whole);
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn credits_from_distinct_requests_do_not_retire_each_others_count() {
    let budget = budget(3);
    let a = budget.try_enter(AdmissionClass::Data).unwrap();
    let b = budget.try_enter(AdmissionClass::Data).unwrap();
    let mut first = a.try_reserve(1).unwrap();
    let second = b.try_reserve(1).unwrap();
    let second = first.try_merge(second).unwrap_err();
    drop((a, b, first));
    assert_eq!(budget.used(), (1, 1));
    assert_eq!(budget.counts.as_ref().unwrap().data.available_permits(), 1);
    drop(second);
    assert_eq!(budget.counts.as_ref().unwrap().data.available_permits(), 2);
}

#[test]
fn sequential_messages_can_exceed_the_lifetime_byte_budget() {
    let budget = budget(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    for _ in 0..100 {
        let input = request.adopt_input(vec![1; 12]).unwrap();
        assert!(request.copy_input(b"x").is_err());
        drop(input);
        assert_eq!(budget.used(), (0, 0));
    }
}

#[test]
fn completed_pair_releases_total_before_data_at_an_observable_interleaving() {
    let budget = budget(2);
    let mut request = budget.try_enter(AdmissionClass::Data).unwrap();
    let observe = Arc::clone(&budget);
    Arc::get_mut(&mut request.0).unwrap()._permits.after_total = Some(Box::new(move || {
        assert_eq!(observe.counts.as_ref().unwrap().data.available_permits(), 0);
        assert!(observe.try_enter(AdmissionClass::Data).is_err());
        assert!(observe.try_enter(AdmissionClass::Operator).is_ok());
    }));
    drop(request);
    assert_eq!(budget.counts.as_ref().unwrap().data.available_permits(), 1);
}

#[test]
fn cancellation_of_assigned_total_returns_it_before_the_data_guard() {
    let budget = budget(2);
    let first = budget.try_enter(AdmissionClass::Operator).unwrap();
    let second = budget.try_enter(AdmissionClass::Operator).unwrap();
    let counts = budget.counts.as_ref().unwrap();
    let data = Arc::clone(&counts.data).try_acquire_owned().unwrap();
    let mut acquisition = Box::pin(AcquirePair::new(Arc::clone(&counts.total), Some(data)));
    let observe = Arc::clone(&budget);
    acquisition.permits.after_total = Some(Box::new(move || {
        // The pending future had an assigned permit even though it was never polled again.
        assert_eq!(
            observe.counts.as_ref().unwrap().total.available_permits(),
            1
        );
        assert_eq!(observe.counts.as_ref().unwrap().data.available_permits(), 0);
        assert!(observe.try_enter(AdmissionClass::Data).is_err());
        assert!(observe.try_enter(AdmissionClass::Operator).is_ok());
    }));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(acquisition.as_mut().poll(&mut cx).is_pending());
    drop(first);
    assert_eq!(
        counts.total.available_permits(),
        0,
        "assigned to the waiter"
    );
    drop(acquisition);
    drop(second);
    assert_eq!(counts.total.available_permits(), 2);
    assert_eq!(counts.data.available_permits(), 1);
}

#[test]
fn cancellation_after_acquired_total_before_delivery_preserves_release_order() {
    let budget = budget(2);
    let counts = budget.counts.as_ref().unwrap();
    let data = Arc::clone(&counts.data).try_acquire_owned().unwrap();
    let mut acquisition = Box::pin(AcquirePair::new(Arc::clone(&counts.total), Some(data)));
    acquisition.hold_after_acquire = true;
    let observe = Arc::clone(&budget);
    acquisition.permits.after_total = Some(Box::new(move || {
        assert_eq!(
            observe.counts.as_ref().unwrap().total.available_permits(),
            2
        );
        assert_eq!(observe.counts.as_ref().unwrap().data.available_permits(), 0);
        assert!(observe.try_enter(AdmissionClass::Data).is_err());
        assert!(observe.try_enter(AdmissionClass::Operator).is_ok());
    }));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(acquisition.as_mut().poll(&mut cx).is_pending());
    assert_eq!(counts.total.available_permits(), 1);
    drop(acquisition);
    assert_eq!(counts.data.available_permits(), 1);
}

#[test]
fn network_only_retirement_wakes_stdio_and_partial_wait_cancels_cleanly() {
    let budget = budget(2);
    let network = budget.try_enter(AdmissionClass::Data).unwrap();
    let mut waiting = Box::pin(budget.enter(AdmissionClass::Data));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    drop(network);
    let Poll::Ready(Ok(stdio)) = waiting.as_mut().poll(&mut cx) else {
        panic!("network retirement alone must make stdio ready");
    };
    drop((waiting, stdio));
    let a = budget.try_enter(AdmissionClass::Operator).unwrap();
    let b = budget.try_enter(AdmissionClass::Operator).unwrap();
    let mut waiting = Box::pin(budget.enter(AdmissionClass::Data));
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    assert_eq!(budget.counts.as_ref().unwrap().data.available_permits(), 0);
    drop(waiting);
    assert_eq!(budget.counts.as_ref().unwrap().data.available_permits(), 1);
    drop((a, b));
}

#[test]
fn simultaneous_classes_keep_both_byte_counters_consistent() {
    let budget = budget(0);
    std::thread::scope(|scope| {
        for class in [AdmissionClass::Data, AdmissionClass::Operator] {
            let budget = Arc::clone(&budget);
            scope.spawn(move || {
                let request = budget.try_enter(class).unwrap();
                for _ in 0..1000 {
                    if let Ok(credit) = request.try_reserve(4) {
                        let (total, data) = budget.used();
                        assert!(data <= 12 && data <= total && total <= 16);
                        drop(credit);
                    }
                }
            });
        }
    });
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn incremental_input_charges_before_growth_and_retires_discarded_payload() {
    let budget = budget(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let mut input = request.adopt_input(Vec::new()).unwrap();
    input.try_extend_from_slice(b"line\r\n").unwrap();
    assert_eq!(input.as_ref(), b"line\r\n");
    assert_eq!(budget.used(), (6, 6));
    assert!(input.try_extend_from_slice(b"1234567").is_err());
    assert_eq!(
        input.as_ref(),
        b"line\r\n",
        "denied growth retains original bytes"
    );
    assert_eq!(budget.used(), (6, 6));
    input.truncate(4);
    assert_eq!(input.as_ref(), b"line");
    assert_eq!(budget.used(), (4, 4));
    input.clear();
    assert!(input.is_empty());
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn staged_credit_and_session_input_retain_the_admitted_request_until_consumed() {
    let budget = budget(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let credit = request.try_reserve(4).unwrap();
    let input = credit.into_input(b"data".to_vec()).unwrap();
    let session = input.into_session_input();
    drop(request);
    assert_eq!(session.bytes, b"data");
    assert!(session.custody.is_some());
    assert_eq!(budget.used(), (4, 4));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(session);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn mismatched_precharged_storage_is_discarded_without_leaking_capacity() {
    let budget = budget(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let credit = request.try_reserve(1).unwrap();
    assert!(credit.into_input(b"too much".to_vec()).is_err());
    assert_eq!(budget.used(), (0, 0));
}
