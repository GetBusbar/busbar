// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-DEFERRED-FORWARD (ABI-MIN3-INTERFACE §14): The deferred FORWARD after LOOKUP(LK_CALLER) and its FAULT
//! arms (round 18). The plane-llm arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the FAULT arms are mostly covered in busbar-kernel (port_session_tests.rs:252 second FORWARD, :271 deferred FORWARD, :282 after RESPOND, :314 in a client or upstream answer) but not FORWARD beside a LOOKUP or UP_NEW before any FORWARD, and the ROUTE_AUTHENTICATED flow (LOOKUP(LK_CALLER), P_LOOKUP, FORWARD + W_MODEL + W_UPSTREAM, miss answers 404 with upstream never called; plane_driver/authenticated_route.rs, git grep finds no test of it) has no test; the plane-llm arm is the plugin repo's. plugin-test's plane suite still refuses LK_CALLER and LK_CHAIN (src/suites/plane.rs:220). Needs no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING; plane arm lands with W2-SW-PLANE (!2480)"]
fn deferred_forward_and_its_faults() {
    todo!("owner: W1-K8A (C-PLANE-DEFERRED-FORWARD)")
}
