// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-INFLIGHT (ABI-MIN3-INTERFACE §14): Hand-polled boot and reconfigure futures dropped after every poll
//! boundary (§10.5; round 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: the registry open and reconfigure futures, W1-L2)"]
fn every_poll_boundary_drop_cancels_or_closes_exactly_once() {
    todo!("owner: W1-H1 (C-CANCEL-INFLIGHT)")
}
