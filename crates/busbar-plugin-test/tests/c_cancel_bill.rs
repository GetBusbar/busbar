// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-BILL (ABI-MIN3-INTERFACE §14): Cumulative USAGE and the §12.4 cancel table.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn cumulative_usage_and_the_cancel_table() {
    todo!("owner: W1-K8A (C-CANCEL-BILL)")
}
