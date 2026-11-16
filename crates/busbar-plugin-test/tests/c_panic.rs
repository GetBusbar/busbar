// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PANIC (ABI-MIN3-INTERFACE §14): A plugin panic in any entry is FAULT and quarantine, never an abort.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: quarantine needs the registry watchdog (W1-L2) and a fixture that panics in every entry kind; the mid-poll FAULT is covered by c_stale_panic and entry::guard tests"]
fn plugin_panic_faults_and_quarantines_without_abort() {
    todo!("owner: W1-L2 (C-PANIC)")
}
