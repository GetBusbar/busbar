// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-REFUSE (ABI-MIN3-INTERFACE §14): `emit(E_REFUSE)` before and after E_HEAD; the pre-101 arm (round
//! 13). Each framer's byte-equal arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the connector still drives framers over the old FramerDoor/Framing (crates/busbar-core-connector/src/framer.rs, compose.rs, framed_stream.rs name neither E_REFUSE nor E_CLOSE, and no .alpn(role) call exists in the connector), OUTSTANDING row 6; lands with W1-C1C !2644 (open). The per-framer outputs (grpc grpc-status 8, http 429, ws close 1008) are the framer images' (plugin repos); lands with W2-SW-TRANSPORT (OUTSTANDING row 7)"]
fn e_refuse_before_and_after_the_head() {
    todo!("owner: W1-L9 (C-TRANSPORT-REFUSE)")
}

#[test]
#[ignore = "re-checked 2026-11-16: the connector still drives framers over the old FramerDoor/Framing (crates/busbar-core-connector/src/framer.rs, compose.rs, framed_stream.rs name neither E_REFUSE nor E_CLOSE, and no .alpn(role) call exists in the connector), OUTSTANDING row 6; lands with W1-C1C !2644 (open). The pre-101 refusal of an upgrade route also needs the transport-http and transport-ws images and a ROUTE_UPGRADE plane through a booted seat (crates/busbar/src/root/port_mount.rs; HOST-LAYERING); lands with W2-SW-TRANSPORT (OUTSTANDING row 7) and W2-SW-PLANE (!2480)"]
fn pre_101_refusals_on_an_upgrade_route() {
    todo!("owner: W1-K8A (C-TRANSPORT-REFUSE)")
}
