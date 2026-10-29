// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The attempt's cap on time to the first answer, against what the walk has left.

use super::attempt_cap_ms;

/// The cap is floored by the request's remaining budget, and never zero: 200 ms under 30 s left is
/// 200 ms; 10 000 ms under 2 s left is 2 000 ms; 10 000 ms with nothing left is 1 ms, never a
/// zero-duration (instant-fail) timer.
#[test]
fn test_attempt_cap_budget_floor() {
    // Plenty of budget: the cap is the configured value.
    assert_eq!(attempt_cap_ms(200, 30_000), 200);
    // Cap larger than the remaining budget: clamped to the budget.
    assert_eq!(attempt_cap_ms(10_000, 2_000), 2_000);
    // Exhausted budget: clamped to 1 ms, never zero.
    assert_eq!(attempt_cap_ms(10_000, 0), 1);
}
