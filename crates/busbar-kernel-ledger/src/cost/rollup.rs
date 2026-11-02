// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READ-TIME ROLLUP: what an operator view builds from figures the one function already priced.

use super::MoneyError;

/// Two priced figures (micro-units) as one, CHECKED like the one function it sums (item 28): a
pub fn sum_spend(rollup: i64, figure: i64) -> Result<i64, MoneyError> {
    rollup.checked_add(figure).ok_or(MoneyError::Overflow)
}

/// What a budget of `cap` minor units has left after `spent`: the cap less the spend, never below
#[must_use]
pub fn budget_remaining(cap: i64, spent: i64) -> i64 {
    cap.saturating_sub(spent).max(0)
}
