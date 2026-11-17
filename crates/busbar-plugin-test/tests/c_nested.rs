// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NESTED (ABI-MIN3-INTERFACE §14): Two OutBufs; a nested entry restores ACTIVE and the watchdog word.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: entry::guard absent (GetBusbar/busbar#272); owner W1-H1"]
fn a_nested_entry_restores_active_and_the_watchdog_word() {
    todo!("owner: W1-H1 (C-NESTED)")
}
