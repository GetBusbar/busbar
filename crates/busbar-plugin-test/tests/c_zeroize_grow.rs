// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE-GROW (ABI-MIN3-INTERFACE §14): Growth from 4 KiB to 16 MiB frees only zeroed blocks; the crypto arena
//! never reallocates; the H1/H2 clamp (round 13; its C plugin arm included, A13's fixture).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn every_freed_growth_block_is_zero() {
    todo!("owner: W1-H1 (C-ZEROIZE-GROW)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn the_arena_never_reallocates_and_frees_zero_on_thread_exit() {
    todo!("owner: W1-H1 (C-ZEROIZE-GROW)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn out_len_and_grow_clamps_keep_high_water_within_own_cap() {
    todo!("owner: W1-H1 (C-ZEROIZE-GROW)")
}
