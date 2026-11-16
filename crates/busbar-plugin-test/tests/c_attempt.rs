// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ATTEMPT (ABI-MIN3-INTERFACE §14): ATTEMPT(RETRY, FC_CONTEXT_LENGTH), ATT_HARD, ATT_RELAY, ATT_DECLINE and
//! walk exhaustion.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: partial cover in busbar-kernel plane_driver (port_upstream_tests.rs:532 ATT_DECLINE never dialled, :579 RETRY/HARD verdicts, port_serve_tests.rs:409 and :647 P_EXHAUSTED, far_end_tests.rs:1131 401 relay) keeps this ignored. Missing pieces: FC_CONTEXT_LENGTH from an ATTEMPT(RETRY) is not mapped to a larger-window re-ask (port_egress.rs:163 fault_of reads only ATT_HARD and FC_RATE_LIMIT; FC_CONTEXT_LENGTH is only defined, plugin-abi kinds/plane.rs:885), ATT_RELAY has no walk consumer outside answer decoding (port_session.rs), and the case needs a plane fixture walking real members through a booted seat (no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING). OUTSTANDING row 5 (K8A tail)"]
fn attempt_answers_drive_the_walk() {
    todo!("owner: W1-K8A (C-ATTEMPT)")
}
