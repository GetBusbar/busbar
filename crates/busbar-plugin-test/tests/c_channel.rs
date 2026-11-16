// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CHANNEL (ABI-MIN3-INTERFACE §14): Two sessions on one CARRIER_STDIO channel: one greet per generation,
//! CH_SERIAL order, replies demuxed.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn one_greet_per_generation_and_replies_demuxed() {
    todo!("owner: W1-K8A (C-CHANNEL)")
}
