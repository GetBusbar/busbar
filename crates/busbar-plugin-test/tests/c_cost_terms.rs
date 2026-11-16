// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-COST-TERMS (ABI-MIN3-INTERFACE §14): A hook view carries weight, available_concurrency and one C_COST_TERM
//! per declared class.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn hook_views_carry_cost_terms() {
    todo!("owner: W1-K8A (C-COST-TERMS)")
}
