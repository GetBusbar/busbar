// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SESSION-ORDER (ABI-MIN3-INTERFACE §14): A plane session with WAKE_AT: the timer piece and a client piece are
//! delivered in turn, never interleaved.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn timer_and_client_pieces_are_delivered_in_turn() {
    todo!("owner: W1-K8A (C-SESSION-ORDER)")
}
