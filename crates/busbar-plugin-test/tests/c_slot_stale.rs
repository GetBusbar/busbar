// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-STALE (ABI-MIN3-INTERFACE §14): A stale token after FAULT: no-op cancel, BadToken resume, the GLOBAL
//! slab, `tok` zeroed, a panic in Drop (Miri, loom).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn stale_tokens_never_reach_another_chain() {
    todo!("owner: W1-A3 (C-SLOT-STALE)")
}
