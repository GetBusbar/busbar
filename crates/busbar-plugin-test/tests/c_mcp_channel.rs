// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-CHANNEL (ABI-MIN3-INTERFACE §14): DemuxRec, MSG_ASK and DX_* delivery on shared channels (round 18). The
//! plane-mcp arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: core's side is covered in busbar-kernel (channels/carrier_tests.rs:349-412 ask routing, fallback and broadcast, channels/tests.rs:124-193 signal fan-out and MAX_FANOUT, plane_driver/tests/port_channels_tests.rs:478 demux decode) but the arm is plane-mcp's P arm: a stdio member and a legacy-SSE member, three DETACHed sessions relaying P_SIGNAL|P_TEXT to clients, and decode FAULT arms through a real plane-mcp image (plugin repo, not in this tree), no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING; image arm lands with W2-SW-PLANE (!2480)"]
fn demux_ask_and_broadcast_core_arms() {
    todo!("owner: W1-K8A (C-MCP-CHANNEL)")
}
