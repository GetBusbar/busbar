// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MINT (ABI-MIN3-INTERFACE §14): FROM_CORE results arrive in the §8.6 order, before any other call (K10 lands
//! the results; plane serving delivers them).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: FROM_CORE MINT result ordering needs the core plane driver (K10) and a serving plane image; loader MINT decode is adapters/plane.rs only; owner W1-K8A"]
fn mint_results_arrive_first_in_order() {
    todo!("owner: W1-K8A (C-MINT)")
}
