// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-BACKPRESSURE (ABI-MIN3-INTERFACE §14): STREAM_FULL/STREAM_WRITABLE, the stall deadline and the conn
//! staying up (C1 + L9). Each framer's arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1C"]
fn backpressure_core_arms() {
    todo!("owner: W1-C1C (C-TRANSPORT-BACKPRESSURE)")
}
