// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STDIO-RESPAWN (ABI-MIN3-INTERFACE §14): A CARRIER_STDIO child starts in `cwd`, is respawned at
//! 100/200/400/800 ms and trips on the 5th exit in 60 s.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn a_stdio_child_backs_off_then_trips() {
    todo!("owner: W1-K8A (C-STDIO-RESPAWN)")
}
