// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READ-TIME ROLLUP: what an operator view builds from figures the one function already priced.
//!
//! An admin read serves per-row spend the one function priced, and then rolls those figures up —
//! a bucket's total, a model's, a key's, a class's summed cost — and shows a budget's headroom.
//! THE DESIGN §7: "The operator surface names no figure of its own: an admin view that shows money
//! reads it through the ledger's read-time view types." So the rollup's arithmetic is here, once,
//! and the operator surface only projects what it returns.

use super::MoneyError;

/// Two priced figures (micro-units) as one, CHECKED like the one function it sums (item 28): a
/// rollup past the range is [`MoneyError::Overflow`], a refused read, never a figure pinned at the
/// ceiling.
///
/// # Errors
///
/// [`MoneyError::Overflow`] when the sum leaves the range.
pub fn sum_spend(rollup: i64, figure: i64) -> Result<i64, MoneyError> {
    rollup.checked_add(figure).ok_or(MoneyError::Overflow)
}

/// What a budget of `cap` minor units has left after `spent`: the cap less the spend, never below
/// nothing — an exhausted budget shows no headroom, never a negative one.
#[must_use]
pub fn budget_remaining(cap: i64, spent: i64) -> i64 {
    cap.saturating_sub(spent).max(0)
}
