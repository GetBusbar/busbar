// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-RETIRE (ABI-MIN3-INTERFACE §14): Retired carrier words (§8.7, round 12).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9"]
fn retired_carrier_words() {
    todo!("owner: W1-K9 (C-RETIRE)")
}
