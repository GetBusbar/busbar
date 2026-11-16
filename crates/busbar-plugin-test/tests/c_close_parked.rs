// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CLOSE-PARKED (ABI-MIN3-INTERFACE §14): `close` with chains left parked in the slots: the plugin value drops
//! last (Miri in abi CI).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn close_with_parked_chains_drops_the_plugin_last() {
    todo!("owner: W1-A3 (C-CLOSE-PARKED)")
}
