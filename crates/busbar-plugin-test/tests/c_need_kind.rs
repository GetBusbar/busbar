// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEED-KIND (ABI-MIN3-INTERFACE §14): A Need outside the kind's row FAULTs.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn a_need_outside_the_kinds_row_faults() {
    todo!("owner: W1-H1 (C-NEED-KIND)")
}
