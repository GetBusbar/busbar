// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PANIC (ABI-MIN3-INTERFACE §14): A plugin panic in any entry is FAULT and quarantine, never an abort.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn plugin_panic_faults_and_quarantines_without_abort() {
    todo!("owner: W1-L2 (C-PANIC)")
}
