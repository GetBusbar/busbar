// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-A2A-PUSH-URL (ABI-MIN3-INTERFACE §14): Push URLs refused at set time and at delivery (§12.9). The plane-a2a
//! arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: core's judging pieces are on the branch (plane_driver/plane_judge.rs JUDGE answers, push/mod.rs queue, port_intents.rs PUSH) but the arm is plane-a2a's P arm: it needs the plane-a2a image (plugin repo, OUTSTANDING row 23, not in this tree) taking a client push-config set, a scripted resolver, and a delivery-time re-judge; no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING; image arms land with W2-SW-PLANE (!2480)"]
fn push_urls_are_judged_at_set_and_delivery() {
    todo!("owner: W1-K8A (C-A2A-PUSH-URL)")
}
