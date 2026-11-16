// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ENTRY-GUARD (ABI-MIN3-INTERFACE §14): `grow` and `log` inside resume, describe and close, all inline under
//! `entry::guard` (round 10). H0 is not an owner here (W1-H0 handoff): the guard needs A2's `HOST` and H1's pool
//! and watch words. The source check (no `spawn_blocking`/`on_plugin_thread` around an entry) is ci/hop's
//! `the_tree_has_no_hop` (W1-H0) and is not repeated.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1"]
fn grow_to_16_mib_and_the_arena_is_zero_when_the_open_step_returns() {
    todo!("owner: W1-H1 (C-ENTRY-GUARD)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn describe_open_and_close_log_lines_are_attributed_and_scrubbed_and_64_kib_answers_pass() {
    todo!("owner: W1-L2 (C-ENTRY-GUARD)")
}
