// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNIX-DEST (ABI-MIN3-INTERFACE §14): `unix:` destinations (§12.1; C1 + K1). The store-mysql and store-valkey
//! arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A"]
fn unix_destinations() {
    todo!("owner: W1-C1A (C-UNIX-DEST)")
}
