// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL (ABI-MIN3-INTERFACE §14): A chain cancelled mid-chain.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn a_chain_cancelled_mid_chain_drops_its_future_once() {
    todo!("owner: W1-H1 (C-CANCEL)")
}
