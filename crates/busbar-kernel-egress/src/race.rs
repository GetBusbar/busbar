// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Racing a piece of work against a deadline, without a runtime.
//!
//! Every deadline in this unit is a race between the work and a sleep, and the sleep comes from
//! the clock port. Writing the race here rather than taking one from a runtime is what lets the
//! whole walk — including the one bounded wait — run in a test on a single thread with a clock
//! that never actually sleeps.
//!
//! Both races below are BIASED and the bias is part of the behaviour, not an implementation
//! detail. [`with_deadline`] polls the work first, so a piece of work that is already finished
//! when its deadline arrives counts as finished. [`deadline_first`] polls the deadline first, so a
//! wait whose bound has passed sheds even if a permit became available in the same instant — which
//! is what makes "never block past the budget" true rather than nearly true.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The deadline arrived before the work finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

/// Run `work`, giving up if `deadline` finishes first. The work is polled first.
pub async fn with_deadline<T>(
    work: impl Future<Output = T>,
    deadline: impl Future<Output = ()>,
) -> Result<T, Elapsed> {
    Race {
        work: Box::pin(work),
        deadline: Box::pin(deadline),
        work_first: true,
    }
    .await
}

/// Run `work`, giving up if `deadline` finishes first. The DEADLINE is polled first, so an expired
/// bound wins a tie.
pub async fn deadline_first<T>(
    work: impl Future<Output = T>,
    deadline: impl Future<Output = ()>,
) -> Result<T, Elapsed> {
    Race {
        work: Box::pin(work),
        deadline: Box::pin(deadline),
        work_first: false,
    }
    .await
}

struct Race<W, D> {
    work: Pin<Box<W>>,
    deadline: Pin<Box<D>>,
    work_first: bool,
}

// The two futures are boxed and pinned on construction and never moved out, so this future is
// trivially `Unpin` and needs no projection.
impl<T, W: Future<Output = T>, D: Future<Output = ()>> Future for Race<W, D> {
    type Output = Result<T, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.work_first {
            if let Poll::Ready(v) = this.work.as_mut().poll(cx) {
                return Poll::Ready(Ok(v));
            }
            if this.deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Elapsed));
            }
        } else {
            if this.deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Elapsed));
            }
            if let Poll::Ready(v) = this.work.as_mut().poll(cx) {
                return Poll::Ready(Ok(v));
            }
        }
        Poll::Pending
    }
}

/// Drive a future to completion on the calling thread.
///
/// This exists for the crate's own tests and for a caller that has no runtime of its own. It parks
/// nothing and spawns nothing: it polls until the future is ready, and a future that is genuinely
/// pending forever would spin, which is exactly why every await in this unit is bounded by a
/// deadline that the clock port can satisfy immediately.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}
