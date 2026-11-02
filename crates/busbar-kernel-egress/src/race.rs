// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Racing a piece of work against a deadline, without a runtime.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The deadline arrived before the work finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

/// Run `work`, giving up if `deadline` finishes first. The DEADLINE is polled first, so an expired

pub async fn deadline_first<T>(
    work: impl Future<Output = T>,
    deadline: impl Future<Output = ()>,
) -> Result<T, Elapsed> {
    Race {
        work: Box::pin(work),
        deadline: Box::pin(deadline),
    }
    .await
}

struct Race<W, D> {
    work: Pin<Box<W>>,
    deadline: Pin<Box<D>>,
}

impl<T, W: Future<Output = T>, D: Future<Output = ()>> Future for Race<W, D> {
    type Output = Result<T, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Elapsed));
        }
        if let Poll::Ready(v) = this.work.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        Poll::Pending
    }
}
