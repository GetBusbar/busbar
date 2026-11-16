// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-COST-TERMS (ABI-MIN3-INTERFACE §14): A hook view carries weight, available_concurrency and one C_COST_TERM
//! per declared class.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the hook view carries available_concurrency (plane_driver/hooks/mod.rs:573) and the plane EXPECT reaches usage.rs:209 expected_units, but there is no C_COST_TERM nested record, CostTermRec or COST_UNPRICED anywhere in the tree (grep over busbar-kernel, busbar-plugin-abi, busbar-contract, busbar is empty), so the cost terms are not on the view. OUTSTANDING row 5 (K8A tail: EXPECT pricing into cost terms, IF §12.4)"]
fn hook_views_carry_cost_terms() {
    todo!("owner: W1-K8A (C-COST-TERMS)")
}
