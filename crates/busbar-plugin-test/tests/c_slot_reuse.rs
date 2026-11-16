// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-REUSE (ABI-MIN3-INTERFACE §14): A freed slot is reused without crossing tokens.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn a_freed_slot_is_reused_without_crossing_tokens() {
    todo!("owner: W1-A3 (C-SLOT-REUSE)")
}
