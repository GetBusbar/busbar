// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CONN-SCOPE (ABI-MIN3-INTERFACE §14): Conns scoped to `(instance, chain)` (rounds 15, 16).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A"]
fn conns_are_scoped_to_their_chain() {
    todo!("owner: W1-C1A (C-CONN-SCOPE)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn an_unclosed_conn_is_released_and_a_never_need_chain_makes_no_call() {
    todo!("owner: W1-C1A (C-CONN-SCOPE)")
}
