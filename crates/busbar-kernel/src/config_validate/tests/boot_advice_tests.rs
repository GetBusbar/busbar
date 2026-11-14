// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot-advice mute is scoped to the one future it wraps: never to a thread, never past a drop.

use super::{after_boot_advice, boot_advised};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Pending once (waking itself), then ready: a future that crosses one poll boundary.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// What the wrapped future saw before and after its one yield.
fn wrapped() -> impl Future<Output = (bool, bool)> + Send {
    after_boot_advice(async {
        let before = boot_advised();
        YieldOnce(false).await;
        (before, boot_advised())
    })
}

fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn the_scope_holds_only_inside_the_wrapped_future() {
    assert!(!boot_advised(), "no scope outside");
    let inside = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(after_boot_advice(async { boot_advised() }));
    assert!(inside, "the wrapped future sees the scope");
    assert!(!boot_advised(), "the scope ends when the future completes");
}

#[test]
fn a_future_dropped_mid_poll_leaves_no_scope_behind() {
    let mut fut = Box::pin(wrapped());
    assert!(poll_once(fut.as_mut()).is_pending(), "it yields once");
    assert!(!boot_advised(), "no scope between polls");
    drop(fut);
    assert!(!boot_advised(), "no scope after a mid-poll drop");
}

#[test]
fn the_scope_travels_with_the_future_not_the_thread() {
    let mut fut = Box::pin(wrapped());
    assert!(poll_once(fut.as_mut()).is_pending(), "it yields once");
    assert!(
        !boot_advised(),
        "no scope on the first thread between polls"
    );
    let (seen, after_on_other) = std::thread::spawn(move || {
        let seen = loop {
            if let Poll::Ready(seen) = poll_once(fut.as_mut()) {
                break seen;
            }
        };
        (seen, boot_advised())
    })
    .join()
    .expect("the other thread completes");
    assert_eq!(
        seen,
        (true, true),
        "inside the wrapped future the scope holds on both threads"
    );
    assert!(!after_on_other, "no scope on the other thread outside");
    assert!(!boot_advised(), "no scope on the first thread outside");
}
