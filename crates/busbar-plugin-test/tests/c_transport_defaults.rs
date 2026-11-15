// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-DEFAULTS (ABI-MIN3-INTERFACE §14): `offer(ROLE_CLIENT)` defaults and the head order; the
//! transport-ws ROLE_CLIENT arm (rounds 22, 23).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn client_defaults_and_head_order() {
    todo!("owner: W1-K8B (C-TRANSPORT-DEFAULTS)")
}
