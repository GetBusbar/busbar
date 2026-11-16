// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-CLOSE (ABI-MIN3-INTERFACE §14): E_CLOSE on drain, revoke, timeout and capacity; no E_CLOSE after
//! CLOSE, EOF or a lost socket (C1 + K8). Each framer's arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the connector still drives framers over the old FramerDoor/Framing (crates/busbar-core-connector/src/framer.rs, compose.rs, framed_stream.rs name neither E_REFUSE nor E_CLOSE, and no .alpn(role) call exists in the connector), OUTSTANDING row 6; lands with W1-C1C !2644 (open). E_CLOSE with CR_DRAIN/CR_REVOKED/CR_TIMEOUT/CR_CAPACITY_EXHAUSTED, and the ws close codes and webrtc close datagrams, need the ws and webrtc framer images (plugin repos); lands with W2-SW-TRANSPORT (OUTSTANDING row 7)"]
fn close_reasons_core_arms() {
    todo!("owner: W1-K8A (C-TRANSPORT-CLOSE)")
}
