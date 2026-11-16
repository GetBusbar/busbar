// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MIGRATE (ABI-MIN3-INTERFACE §14): Read through `open` and `Open::settled` (round 31, WBS rule 12): every
//! "migrate" below is the plugin's `open`.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A4"]
fn the_macro_echo_and_the_settled_shim() {
    todo!("owner: W1-A4 (C-MIGRATE)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn core_cfg_conflicts_secret_round_trip_and_former_names_mismatch() {
    todo!("owner: W1-L2 (C-MIGRATE)")
}

#[test]
#[ignore = "owner: W1-K9"]
fn the_settled_write_back_through_boot() {
    todo!("owner: W1-K9 (C-MIGRATE)")
}
