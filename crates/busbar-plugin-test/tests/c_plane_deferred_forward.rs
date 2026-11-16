// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-DEFERRED-FORWARD (ABI-MIN3-INTERFACE §14): The deferred FORWARD after LOOKUP(LK_CALLER) and its FAULT
//! arms (round 18). The plane-llm arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A"]
fn deferred_forward_and_its_faults() {
    todo!("owner: W1-K8A (C-PLANE-DEFERRED-FORWARD)")
}
