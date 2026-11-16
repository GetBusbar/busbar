// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALLOC (ABI-MIN3-INTERFACE §14): The counting allocator over I5's machinery.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: the counting allocator, W1-U1, and the EC2 bench)"]
fn sync_zero_and_async_steady_state_three() {
    todo!("owner: W1-H1 (C-ALLOC)")
}

#[test]
#[ignore = "owner: W1-L3"]
fn a_store_lane_entry_allocates_four() {
    todo!("owner: W1-L3 (C-ALLOC)")
}
