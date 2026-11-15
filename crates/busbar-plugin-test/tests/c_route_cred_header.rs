// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ROUTE-CRED-HEADER (ABI-MIN3-INTERFACE §14): D_ROUTE_CRED_HEADER routes and `routes.<id>.auth_instances`
//! (§12.11; K8 + L8). The plane-streaming image arm is on #217.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B"]
fn route_credential_header_core_arms() {
    todo!("owner: W1-K8B (C-ROUTE-CRED-HEADER)")
}
