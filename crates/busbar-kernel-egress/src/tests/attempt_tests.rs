// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The attempt's cap on time to the first answer, against what the walk has left.

use super::attempt_cap_ms;

/// The cap is floored by the request's remaining budget, and never zero: 200 ms under 30 s left is

#[test]
fn test_attempt_cap_budget_floor() {
    assert_eq!(attempt_cap_ms(200, 30_000), 200);

    assert_eq!(attempt_cap_ms(10_000, 2_000), 2_000);

    assert_eq!(attempt_cap_ms(10_000, 0), 1);
}
