// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WATCH-CHURN (ABI-MIN3-INTERFACE §14): Watchdog registration churn, alignment and the full table (rounds 12,
//! 17, 24).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn thread_churn_leaves_the_table_at_baseline() {
    todo!("owner: W1-H1 (C-WATCH-CHURN)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn a_full_table_entry_is_still_attributed_and_scrubbed() {
    todo!("owner: W1-L2 (C-WATCH-CHURN)")
}
