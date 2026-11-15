// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WEBRTC-ICE-RESTART (ABI-MIN3-INTERFACE §14): MemIo's deterministic `random_into` records every draw (round
//! 18). The transport-webrtc arms run in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A12"]
fn memio_records_every_draw() {
    todo!("owner: W1-A12 (C-WEBRTC-ICE-RESTART)")
}
