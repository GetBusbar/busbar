// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STALE-PANIC (ABI-MIN3-INTERFACE §14): A stash after a panic mid-poll FAULTs StaleHandle; CURRENT is restored;
//! the negative controls must be red.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn a_stale_stash_after_a_panic_faults() {
    todo!("owner: W1-A3 (C-STALE-PANIC)")
}
