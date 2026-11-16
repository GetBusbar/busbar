// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FAIL-RESET (ABI-MIN3-INTERFACE §14): `Err(Full)` after writing max_out is exactly one FAIL F_LIMIT and the
//! instance stays LIVE; a REFUSED answer's `records()` is empty.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn full_is_one_fail_f_limit_and_the_instance_stays_live() {
    todo!("owner: W1-H1 (C-FAIL-RESET)")
}
