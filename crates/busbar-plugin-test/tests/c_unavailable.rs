// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNAVAILABLE (ABI-MIN3-INTERFACE §14): The facade's test-support stub backend: unsupported algs,
//! `EXTERNAL_PLUGINS`, stamp crypto; C-FIPS-GATE's admit arm (round 13). C-FIPS-GATE's facade build arm is
//! W0-H0B's contract test.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A2"]
fn stub_backend_unsupported_algs_answer_unavailable() {
    todo!("owner: W1-A2 (C-UNAVAILABLE)")
}

#[test]
#[ignore = "owner: W1-L1"]
fn admit_refuses_external_without_external_plugins_and_a_foreign_backend() {
    todo!("owner: W1-L1 (C-UNAVAILABLE)")
}
