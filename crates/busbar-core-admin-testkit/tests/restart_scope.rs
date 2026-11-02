// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::restart::swap_forced_unsupervised;
use busbar_core_admin_testkit::with_forced_unsupervised;
use std::future::Future;
use std::task::{Context, Poll, Waker};

#[test]
fn a_dropped_scope_restores_the_previous_supervisor_override() {
    swap_forced_unsupervised(false);
    let mut scope = Box::pin(with_forced_unsupervised(std::future::pending::<()>));
    assert!(scope
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert!(
        swap_forced_unsupervised(true),
        "the pending scope is active"
    );
    drop(scope);
    assert!(
        !swap_forced_unsupervised(false),
        "cancellation restores false"
    );
}

#[test]
fn a_panicking_scope_restores_the_previous_supervisor_override() {
    swap_forced_unsupervised(false);
    let mut scope = Box::pin(with_forced_unsupervised(|| async {
        panic!("fixture panic")
    }));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = scope.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    }));
    assert!(outcome.is_err());
    assert!(!swap_forced_unsupervised(false), "unwind restores false");
}

#[test]
fn a_completed_nested_scope_preserves_the_outer_override() {
    swap_forced_unsupervised(true);
    let mut scope = Box::pin(with_forced_unsupervised(|| async { 7 }));
    assert_eq!(
        scope.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(7)
    );
    assert!(swap_forced_unsupervised(false), "outer override survives");
}
