// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WORK-RECOVERY (ABI-MIN3-INTERFACE §14): Durable paid work and its recovery (§12.24).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A (blocked: W1-K8A tail: serve_lines, recover_work and cost.rs wiring, and the plane audit actions, are not on dev; OUTSTANDING A5)"]
fn durable_work_recovery() {
    todo!("owner: W1-K8A (C-WORK-RECOVERY)")
}
