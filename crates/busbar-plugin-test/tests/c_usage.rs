// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-USAGE (ABI-MIN3-INTERFACE §14): An undeclared USAGE class is dropped and audited.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn an_undeclared_usage_class_is_dropped_and_audited() {
    todo!("owner: W1-K8A (C-USAGE)")
}
