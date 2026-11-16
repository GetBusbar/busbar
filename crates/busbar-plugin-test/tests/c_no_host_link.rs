// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NO-HOST-LINK (ABI-MIN3-INTERFACE §14): §15.11, X1's job, run in each plugin repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-X1"]
fn no_host_link_job() {
    todo!("owner: W1-X1 (C-NO-HOST-LINK)")
}
