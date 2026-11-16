// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SECRET-REF (ABI-MIN3-INTERFACE §14): Each secret plugin's 1.5.x `check` corpus gives the same verdict through
//! `--validate` with D_REF_SCHEMA.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7"]
fn the_check_corpus_through_validate() {
    todo!("owner: W1-K7 (C-SECRET-REF)")
}
