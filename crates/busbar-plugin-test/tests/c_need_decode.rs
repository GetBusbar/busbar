// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEED-DECODE (ABI-MIN3-INTERFACE §14): Every row of the §10.3 decode table, both ways (rounds 28, 29), plus
//! the ENDPOINT rows (TRANSPORT-SECURITY-POLICY §8 test 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn every_decode_table_row_both_ways() {
    todo!("owner: W1-H1 (C-NEED-DECODE)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn hostneeds_judges_the_stated_class() {
    todo!("owner: W1-C1A (C-NEED-DECODE)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn bad_endpoint_records_are_invalid() {
    todo!("owner: W1-L2 (C-NEED-DECODE)")
}
