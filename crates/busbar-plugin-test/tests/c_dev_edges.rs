// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DEV-EDGES (ABI-MIN3-INTERFACE §14): §15 rule 1b: a dev-dependency other than `busbar-plugin-test` fails the
//! job.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-X1; blocked (re-checked on dev 2026-11-16): a busbar-ci-checks job and fixture, not a plugin-test arm; no job on dev"]
fn a_direct_dev_edge_fails_the_job() {
    todo!("owner: W1-X1 (C-DEV-EDGES)")
}
