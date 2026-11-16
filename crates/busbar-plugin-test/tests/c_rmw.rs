// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-RMW (ABI-MIN3-INTERFACE §14): The counting configuration of `slots.rs`/`bridge.rs`/`scrub.rs` (rounds 8-17).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3 (needs a test hook in busbar-ffi slots.rs, owner-pinned: GetBusbar/busbar#265)"]
fn zero_rmw_per_piece_ingest_and_resume_two_per_opener_and_end() {
    todo!("owner: W1-A3 (C-RMW)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn zero_refcount_and_four_pool_cas_per_never_need_chain() {
    todo!("owner: W1-H1 (C-RMW)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn two_rmw_per_scrubbed_text_and_none_per_clean_sync_answer() {
    todo!("owner: W1-H1 (C-RMW)")
}
