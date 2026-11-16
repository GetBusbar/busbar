// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SIGN (ABI-MIN3-INTERFACE §14): FROM_CORE results arrive in the §8.6 order, before any other call (K10 lands
//! the results; plane serving delivers them).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A (blocked: the SIGN result path rides K10's connection/trust custody, which is still a W0 stub on dev: busbar-kernel connections/mod.rs and trust/plane_book.rs; OUTSTANDING A3)"]
fn sign_results_arrive_first_in_order() {
    todo!("owner: W1-K8A (C-SIGN)")
}
