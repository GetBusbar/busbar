// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UPGRADE (ABI-MIN3-INTERFACE §14): Server-side WebSocket upgrade (§12.27; K8 + L9 + C1C). The
//! transport-http/-ws image arms belong to W2-SW-TRANSPORT and are filed on #217.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: needs the real transport-http and transport-ws images (plugin repos, not in this tree) with a plane fixture and a ROUTE_UPGRADE GET through a booted seat (crates/busbar/src/root/port_mount.rs mounts it; no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING); transport images arrive with W2-SW-TRANSPORT (OUTSTANDING row 7, after W1-C1C !2644) and the plane with W2-SW-PLANE (!2480)"]
fn upgrade_fixture_arm() {
    todo!("owner: W1-K8A (C-UPGRADE)")
}
