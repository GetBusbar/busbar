// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READ-TIME ROLLUP: what an operator view builds from figures the one function already priced.

/// What a budget of `cap` minor units has left after `spent`: the cap less the spend, never below
#[must_use]
pub fn budget_remaining(cap: i64, spent: i64) -> i64 {
    cap.saturating_sub(spent).max(0)
}
