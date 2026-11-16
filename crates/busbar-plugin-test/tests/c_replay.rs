// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REPLAY (ABI-MIN3-INTERFACE §14): A byte-identical replay of a REPLAY-answered request is refused R_REPLAYED
//! and never served from the verdict cache.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K10"]
fn a_replay_is_refused_and_never_cached() {
    todo!("owner: W1-K10 (C-REPLAY)")
}
