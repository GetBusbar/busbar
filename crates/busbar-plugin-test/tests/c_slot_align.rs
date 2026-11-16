// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-ALIGN (ABI-MIN3-INTERFACE §14): Every slot address 128-byte aligned; `free_head` off the `pages` line.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3 (needs a test hook in busbar-ffi slots.rs, owner-pinned: GetBusbar/busbar#265)"]
fn slots_are_128_byte_aligned() {
    todo!("owner: W1-A3 (C-SLOT-ALIGN)")
}
