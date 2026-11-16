// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-TASKS (ABI-MIN3-INTERFACE §14): The two-replica arm (round 20). Arms (a)-(f) need the plane-mcp image:
//! GetBusbar/busbar #217 (WBS delta 4). The two-process harness stays here.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: two-process gateway harness needs the plane-mcp image (GetBusbar/busbar#217); owner W1-K8A"]
fn two_gateways_over_one_store_harness() {
    todo!("owner: W1-K8A (C-MCP-TASKS)")
}
