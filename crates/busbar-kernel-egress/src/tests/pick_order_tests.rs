// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick order, and where a member is excluded from it.

use crate::select::RequestCtx;

#[test]
fn a_deadline_far_in_the_future_does_not_overflow() {
    let ctx = RequestCtx::new(u64::MAX, u64::MAX - 1, u128::MAX - 1);
    assert!(ctx.expired(u64::MAX));
    assert_eq!(ctx.remaining_secs(u64::MAX), 0);
}
