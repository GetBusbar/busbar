// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The deadline race's polling order: the deadline is polled first, and work is never polled once
//! the deadline has finished.

use crate::race::{deadline_first, Elapsed};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = std::pin::pin!(f);
    f.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn a_finished_deadline_wins_even_when_the_work_is_also_ready_and_the_work_is_never_polled() {
    let polled = AtomicUsize::new(0);
    let work = std::future::poll_fn(|_| {
        polled.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(7)
    });
    assert_eq!(
        poll_once(deadline_first(work, std::future::ready(()))),
        Poll::Ready(Err(Elapsed))
    );
    assert_eq!(polled.load(Ordering::Relaxed), 0);
}

#[test]
fn ready_work_wins_while_the_deadline_is_pending() {
    assert_eq!(
        poll_once(deadline_first(
            std::future::ready(7),
            std::future::pending::<()>()
        )),
        Poll::Ready(Ok(7))
    );
}

#[test]
fn both_pending_stays_pending() {
    assert_eq!(
        poll_once(deadline_first(
            std::future::pending::<u8>(),
            std::future::pending::<()>()
        )),
        Poll::Pending
    );
}
