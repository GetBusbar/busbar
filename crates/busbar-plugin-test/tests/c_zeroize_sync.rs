// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE-SYNC (ABI-MIN3-INTERFACE §14): Sync buffers and the arena read back zero after `Err(Full)`, a refusal
//! and an OK (round 6).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn sync_buffers_and_the_arena_read_back_zero() {
    todo!("owner: W1-H1 (C-ZEROIZE-SYNC)")
}
