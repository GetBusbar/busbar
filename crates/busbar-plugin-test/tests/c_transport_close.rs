// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-CLOSE (ABI-MIN3-INTERFACE §14): E_CLOSE on drain, revoke, timeout and capacity; no E_CLOSE after
//! CLOSE, EOF or a lost socket (C1 + K8). Each framer's arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn close_reasons_core_arms() {
    todo!("owner: W1-K8A (C-TRANSPORT-CLOSE)")
}
