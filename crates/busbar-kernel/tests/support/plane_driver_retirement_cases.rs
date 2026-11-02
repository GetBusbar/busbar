// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Worker results that arrive before the caller's next poll still belong to the sweep.

use super::*;

/// Poll only the caller until its real pump has submitted a pending crossing. No runtime clock
/// decides the race: the test then completes the worker's cancel and drops the unpolled caller.
async fn worker_cancel_before_caller_poll(member: &'static str) {
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let rows = Arc::new(AuditRows::default());
    r.driver = r.driver.with_audit(rows.clone());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&[member], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let mut running = Box::pin(cases::drive(&units));
    let ticket = std::future::poll_fn(|cx| {
        for _ in 0..32 {
            assert!(running.as_mut().poll(cx).is_pending());
            if let Some(ticket) = r.plane.held.lock().unwrap().keys().next().copied() {
                return Poll::Ready(ticket);
            }
        }
        panic!("the scripted pending crossing was never submitted");
    })
    .await;
    r.plane.drop_client(ticket);
    assert_eq!(r.stats()[stat::CANCELS], 1, "the worker cancelled once");
    drop(running);
    drop(units);
    assert_eq!(r.driver.buried(), 1);
    r.driver.sweep();
    assert_eq!(r.driver.buried(), 0);
    assert_eq!(r.stats()[stat::CANCELS], 1, "no second terminal cancel");
    let bills = r.book.bills();
    assert_eq!(bills.len(), 1);
    assert_eq!(bills[0].disposition, CANCEL_FAILED);
    let expected = if member == "hang-row" {
        vec![(
            "thing.cancel".to_string(),
            "thing:x".to_string(),
            busbar_contract::vocab::OUTCOME_APPLIED,
            common::principal().as_str().to_string(),
        )]
    } else {
        Vec::new()
    };
    assert_eq!(*rows.0.lock().unwrap(), expected);
    r.driver.sweep();
    assert_eq!(r.book.bills().len(), 1);
    assert_eq!(*rows.0.lock().unwrap(), expected);
}

#[tokio::test]
async fn an_unpolled_worker_cancel_keeps_its_disposition_and_record_writes() {
    worker_cancel_before_caller_poll("hang-row").await;
}

#[tokio::test]
async fn an_unpolled_worker_cancel_fault_is_not_cancelled_again() {
    worker_cancel_before_caller_poll("cancel-fault").await;
}
