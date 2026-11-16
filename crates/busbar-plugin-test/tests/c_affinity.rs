// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AFFINITY (ABI-MIN3-INTERFACE §14): The affinity rule (§8.6).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the rule is not implemented. Nothing sets RQ_AFFINITY (const only, crates/busbar-plugin-abi/src/kinds/plane.rs:720; no use under busbar-kernel or busbar) and core never reads `affinity.header_name` on the plane path (only config_validate and readback touch it); only the plane-stated W_AFFINITY reaches the walk (plane_driver/port_egress.rs:377 affinity_of, tested at port_egress_tests.rs:480). OUTSTANDING row 5 (K8A tail); the arm also needs a plane fixture through a booted seat (no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING)"]
fn affinity_rule() {
    todo!("owner: W1-K8A (C-AFFINITY)")
}
