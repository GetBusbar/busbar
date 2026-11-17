// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-TASKS (ABI-MIN3-INTERFACE §14): The two-replica arm (round 20). Arms (a)-(f) need the plane-mcp image:
//! GetBusbar/busbar #217 (WBS delta 4). The two-process harness stays here.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: needs two gateway processes over one shared store with the plane-mcp image and a tool member (plugin repo; no such two-process harness exists in this tree, GetBusbar/busbar#217 moved the assembled-product cases out of plugin repos) plus the booted plane serving (no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING); lands with W2-SW-PLANE (!2480)"]
fn two_gateways_over_one_store_harness() {
    todo!("owner: W1-K8A (C-MCP-TASKS)")
}
