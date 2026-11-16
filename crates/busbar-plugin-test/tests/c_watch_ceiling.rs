// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WATCH-CEILING (ABI-MIN3-INTERFACE §14): Ceilings with a fake clock in `scan` (round 14).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn ceilings_quarantine_and_the_reuse_race() {
    todo!("owner: W1-L2 (C-WATCH-CEILING)")
}
