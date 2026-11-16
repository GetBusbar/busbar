// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SESSION-ORDER (ABI-MIN3-INTERFACE §14): A plane session with WAKE_AT: the timer piece and a client piece are
//! delivered in turn, never interleaved.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: WAKE_AT and P_TIMER are implemented (plane_driver/port_carrier.rs, session.rs select loop) and only the timer alone is tested (port_carrier_tests.rs:622); no test races a timer against a client piece, and kernel's session rigs (port_carrier_tests.rs rig/run) are private to busbar-kernel so no plugin-test harness drives a session with a plane double; no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING. OUTSTANDING row 5 (K8A tail serve wiring)"]
fn timer_and_client_pieces_are_delivered_in_turn() {
    todo!("owner: W1-K8A (C-SESSION-ORDER)")
}
