// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEED-KIND (ABI-MIN3-INTERFACE §14): A Need outside the kind's row FAULTs.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use core::future::Future;
use core::pin::{pin, Pin};
use core::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_abi::host::{CallStack, Caller, Driver, First, InstanceLimits, NeedRow, Pool};
use busbar_plugin_abi::need::op;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_test::FakeNeeds;

use crate::bridge_fixture as fx;

fn caller() -> Caller<'static> {
    Caller {
        plugin: "bridge-fixture",
        kind: KindCode::Secret,
        name: "fixture",
        instance: 1,
        slot: 1,
        chain: 0,
        deadline: Instant::now() + Duration::from_secs(60),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

fn first<'i>(started: fx::Started<'i, fx::Secret>) -> First<'i, fx::Secret> {
    started.into()
}

/// §6.1 "Allowed Needs per kind": the row every chain of a kind is driven under.
#[test]
fn the_rows_are_the_kind_table() {
    use KindCode::{Auth, Export, Hook, Plane, Secret, Store, Transport};
    let ops = [
        op::OPEN,
        op::STARTTLS,
        op::WRITE,
        op::READ,
        op::CLOSE,
        op::FETCH,
        op::SECRET,
        op::RECORD,
        op::DIRECTORY,
    ];
    let row = |kind, open| ops.map(|o| NeedRow::of(kind, open).allows(o));
    let (y, n) = (true, false);
    assert_eq!(row(Store, false), [y, y, y, y, y, n, y, n, n]);
    assert_eq!(row(Secret, false), [y, y, y, y, y, y, y, n, n]);
    assert_eq!(row(Auth, false), [y, y, y, y, y, y, y, y, n]);
    assert_eq!(row(Hook, false), [n, n, n, n, n, y, y, y, n]);
    assert_eq!(row(Export, false), [y, y, y, y, y, y, y, n, n]);
    assert_eq!(row(Plane, false), [n, n, n, n, n, y, y, y, n]);
    assert_eq!(row(Transport, false), [n; 9]);
    assert_eq!(
        row(Transport, true),
        [n, n, n, n, n, n, y, n, n],
        "SECRET in `open` only"
    );
    let provisioning = NeedRow::of(Auth, false).with_directory();
    assert!(
        provisioning.allows(op::DIRECTORY),
        "auth serve/refresh of an FB_PROVISION image"
    );
    assert!(
        ops.iter().all(|&o| !NeedRow::EMPTY.allows(o)),
        "an F_BLOCKING_FILE store"
    );
}

/// The fixture's `secret` chain NEEDs SECRET. Under a row without SECRET the driver FAULTs NeedNotAllowed before
/// any Need runs (nothing seen, nothing released), cancels the parked chain, and the instance keeps serving.
#[test]
fn a_need_outside_the_kinds_row_faults() {
    let instance = fx::instance();
    let needs = FakeNeeds::new();
    {
        let mut drv = Driver::new(&needs, caller()).with_row(NeedRow::EMPTY);
        let req = Pool::global().acquire(1 << 20);
        let mut fut = pin!(drv.run(0, 1 << 20, req, |_, lease| first(fx::start(
            &instance, b"secret", lease
        ))));
        assert!(matches!(
            poll_once(fut.as_mut()),
            Poll::Ready(Err(CallError::Fault(FaultReason::NeedNotAllowed(
                op::SECRET
            ))))
        ));
    }
    assert!(needs.seen().is_empty(), "no handler ran");
    assert_eq!(
        needs.released(),
        0,
        "the chain made no Need, so nothing is released"
    );
    let mut drv = Driver::new(&needs, caller());
    let req = Pool::global().acquire(1 << 20);
    let mut fut = pin!(drv.run(0, 1 << 20, req, |_, lease| first(fx::start(
        &instance,
        b"refuse-plain",
        lease
    ))));
    match poll_once(fut.as_mut()) {
        Poll::Ready(Ok(done)) => assert!(done.answer.answer().fail().is_some()),
        _ => panic!("the instance still serves after the FAULT"),
    }
}
