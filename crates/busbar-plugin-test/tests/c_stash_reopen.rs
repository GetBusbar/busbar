// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STASH-REOPEN (ABI-MIN3-INTERFACE §14): A stashed ChainBytes across FAULT, reopen and reconfigure onto the
//! same slot: every later `with` FAULTs StaleHandle.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn a_stash_across_reopen_and_reconfigure_faults_stale_handle() {
    todo!("owner: W1-L2 (C-STASH-REOPEN)")
}
