// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-HEADER (ABI-MIN3-INTERFACE §14): The C header: static asserts, the C fixture's admit arm, the arena arm and
//! the full-table nested arm (rounds 11, 20, 22). The secret-c arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A13"]
fn the_static_asserts_compile_with_the_header() {
    todo!("owner: W1-A13 (C-HEADER)")
}

#[test]
#[ignore = "owner: W1-L1"]
fn the_c_fixture_admits_and_runs_every_entry() {
    todo!("owner: W1-L1 (C-HEADER)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn arena_outputs_never_overlap_and_are_zero_after_the_entry() {
    todo!("owner: W1-H1 (C-HEADER)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn the_full_table_nested_arm() {
    todo!("owner: W1-H1 (C-HEADER)")
}
