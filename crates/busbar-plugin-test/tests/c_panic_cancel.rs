// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PANIC-CANCEL (ABI-MIN3-INTERFACE §14): A future's and a session's `Drop` panicking during cancel and close:
//! FAULT, quarantine, no abort.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn drop_panic_in_cancel_or_close_faults_and_quarantines() {
    todo!("owner: W1-L2 (C-PANIC-CANCEL)")
}
