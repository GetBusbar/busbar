// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-KEYS-STALE (ABI-MIN3-INTERFACE §14): Unknown kid: one refresh, one re-verify; 100 concurrent requests share
//! it; a second within the interval is declined.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L5"]
fn an_unknown_kid_refreshes_once() {
    todo!("owner: W1-L5 (C-KEYS-STALE)")
}
