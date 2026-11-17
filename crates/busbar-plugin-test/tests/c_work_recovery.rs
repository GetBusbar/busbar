// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WORK-RECOVERY (ABI-MIN3-INTERFACE §14): Durable paid work and its recovery (§12.24).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the scheduler is on the branch now (crates/busbar/src/root/min3_boot.rs:351 recover_ports, off_path/serve.rs:4059 recover_work, plane_driver/port.rs:572 recovery_route, port_routes.rs:166 recovery_request) and kernel covers WORK custody (plane_driver/tests/port_work_tests.rs: open binds principal, find denied for another principal, settle durable, new process finds the row, recoverable); not covered: the end-to-end arm (create only after WORK_OPEN, scan delivers RQ_RECOVERY with the original identity, exactly one upstream create, no re-poll, restart, revoked principal, 404 on the data listener, pinned BBPOLL01 dev row) needs a plane fixture plus durable store and governance through a booted seat: no booted plane seat is reachable from busbar-plugin-test: PortSeat, plane_seats and min3_boot live in the busbar root crate (crates/busbar/src/root/min3_boot.rs, plane_seats.rs) and boot wiring through the MIN-3 Registry is HOST-LAYERING"]
fn durable_work_recovery() {
    todo!("owner: W1-K8A (C-WORK-RECOVERY)")
}
