// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EGRESS-OWNPORT (ABI-MIN3-INTERFACE §14): OPEN and FETCH to the node's own `listen`/`admin_listen` ports are
//! DENIED for every stated class.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A"]
fn the_nodes_own_ports_are_denied_for_every_class() {
    todo!("owner: W1-C1A (C-EGRESS-OWNPORT)")
}
