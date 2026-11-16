// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WEBRTC-DIAL (ABI-MIN3-INTERFACE §14): UP_NEW(CARRIER_RTC) mirror resolution and its FAULTs in core (round 27;
//! K11 + C1 + K8). The transport-webrtc arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: core's part of (a)-(d) is covered in busbar-kernel (crates/busbar-kernel/src/media/tests.rs: accepted leg gives media/channel head, a non-mirroring answer closes with mirrored text, a mirroring answer opens, bad openings never dial, UP_NEW PAIR resolution), which keeps this partial; clause (e) is transport-webrtc's own begin(ROLE_DATAGRAM, CONN_DIAL) empty-head R_CONFIG refusal (plugin repo, transport-webrtc/src/framing.rs:506) and the end-to-end arm needs that image plus a plane fixture (no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING); lands with W2-SW-TRANSPORT (OUTSTANDING row 7) and W2-SW-PLANE (!2480)"]
fn rtc_dial_mirrors_the_accepted_offer() {
    todo!("owner: W1-K8A (C-WEBRTC-DIAL)")
}
