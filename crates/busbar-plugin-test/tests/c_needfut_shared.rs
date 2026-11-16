// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEEDFUT-SHARED (ABI-MIN3-INTERFACE §14): A `NeedFut` shared across instances: B's poll FAULTs StaleHandle,
//! A's later poll gets A's value.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn a_shared_needfut_faults_for_the_other_instance() {
    todo!("owner: W1-A3 (C-NEEDFUT-SHARED)")
}
