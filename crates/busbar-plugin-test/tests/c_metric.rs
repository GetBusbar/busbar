// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-METRIC (ABI-MIN3-INTERFACE §14): Declared metrics recorded and kept across reconfigure; undeclared and
//! over-cardinality dropped and audited.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8D"]
fn declared_metrics_survive_reconfigure() {
    todo!("owner: W1-K8D (C-METRIC)")
}
