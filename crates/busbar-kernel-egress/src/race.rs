// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Racing a piece of work against a deadline, without a runtime.

use futures::future::{select, Either};
use std::future::Future;

/// The deadline arrived before the work finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

/// Run `work`, giving up if `deadline` finishes first. The DEADLINE is polled first (`select`
/// polls its left side first), so an expired deadline wins even when the work is also ready, and
/// the work is not polled again once the deadline has finished.
pub async fn deadline_first<T>(
    work: impl Future<Output = T>,
    deadline: impl Future<Output = ()>,
) -> Result<T, Elapsed> {
    match select(std::pin::pin!(deadline), std::pin::pin!(work)).await {
        Either::Left(((), _)) => Err(Elapsed),
        Either::Right((value, _)) => Ok(value),
    }
}
