// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PATH-CLAIM (ABI-MIN3-INTERFACE §14): Path claims per listener (§12.26).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C"]
fn path_claims_per_listener() {
    todo!("owner: W1-K8C (C-PATH-CLAIM)")
}
