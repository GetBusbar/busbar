// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-COMMIT (ABI-MIN3-INTERFACE §14): Two concurrent conflicting COMMITs on one key: exactly one APPLIED; a failed
//! predicate applies nothing.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K5"]
fn two_conflicting_commits_apply_exactly_one() {
    todo!("owner: W1-K5 (C-COMMIT)")
}
