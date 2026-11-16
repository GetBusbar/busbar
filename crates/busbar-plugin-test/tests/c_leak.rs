// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LEAK (ABI-MIN3-INTERFACE §14): A `Box::leak` handle used from a later chain and from a sync call.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn a_leaked_handle_used_later_faults() {
    todo!("owner: W1-A3 (C-LEAK)")
}
