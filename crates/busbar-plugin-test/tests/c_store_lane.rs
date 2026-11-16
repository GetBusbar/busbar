// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STORE-LANE (ABI-MIN3-INTERFACE §14): An F_BLOCKING_FILE store on the lane: no worker blocked, ceilings, NEED
//! refused, readback after drop.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L3 (blocked: needs a store fixture image (plugin!-built, lane/info facts) admitted through Harness over Registry open_store; no such fixture exists in busbar-plugin-test)"]
fn a_blocking_store_runs_on_the_lane() {
    todo!("owner: W1-L3 (C-STORE-LANE)")
}
