// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SECRET-CYCLE (ABI-MIN3-INTERFACE §14): Secret fixtures A -> B -> A: Cycle at the second hop; depth 5 refused.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L4"]
fn a_cycle_is_found_at_the_second_hop_and_depth_5_is_refused() {
    todo!("owner: W1-L4 (C-SECRET-CYCLE)")
}
