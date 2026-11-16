// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT-REFUSE (ABI-MIN3-INTERFACE §14): `emit(E_REFUSE)` before and after E_HEAD; the pre-101 arm (round
//! 13). Each framer's byte-equal arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L9"]
fn e_refuse_before_and_after_the_head() {
    todo!("owner: W1-L9 (C-TRANSPORT-REFUSE)")
}

#[test]
#[ignore = "owner: W1-K8A"]
fn pre_101_refusals_on_an_upgrade_route() {
    todo!("owner: W1-K8A (C-TRANSPORT-REFUSE)")
}
