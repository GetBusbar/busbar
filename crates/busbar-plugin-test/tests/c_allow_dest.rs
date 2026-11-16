// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALLOW-DEST (ABI-MIN3-INTERFACE §14): A K9 core-config fixture: core's resolved private providers are allowed
//! (round 18).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K9"]
fn core_resolved_private_providers_are_allowed() {
    todo!("owner: W1-K9 (C-ALLOW-DEST)")
}
