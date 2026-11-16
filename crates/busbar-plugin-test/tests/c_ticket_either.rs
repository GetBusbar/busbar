// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TICKET-EITHER (ABI-MIN3-INTERFACE §14): Route class sets PRINCIPAL/TICKET and the ticket row (§12.11; K8 +
//! K10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn ticket_either_arms() {
    todo!("owner: W1-K8B (C-TICKET-EITHER)")
}
