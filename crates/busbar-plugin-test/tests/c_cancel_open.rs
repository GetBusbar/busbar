// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-OPEN (ABI-MIN3-INTERFACE §14): An `open` chain parked mid-NEED cancelled three ways (rounds 6, 8, 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: an `open` that NEEDs, a plugin! fixture, and the registry, W1-L2)"]
fn an_open_parked_mid_need_is_cancelled_three_ways_once_inline() {
    todo!("owner: W1-H1 (C-CANCEL-OPEN)")
}

#[test]
#[ignore = "owner: W1-H1 (blocked: an `open` that NEEDs, a plugin! fixture, and the registry, W1-L2)"]
fn buffers_are_released_zeroed_after_cancel_returns_and_the_lease_last() {
    todo!("owner: W1-H1 (C-CANCEL-OPEN)")
}
