// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNIX-DEST (ABI-MIN3-INTERFACE §14): `unix:` destinations (§12.1; C1 + K1). The store-mysql and store-valkey
//! arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): (a) is the store-mysql/store-valkey P arms (plugin-repo images on MIN-3 stores booted by core, OUTSTANDING rows 7-11); the core clauses run through HostNeeds::open over a real unix socket with a binder double and a counting resolver, which needs a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet (the arm then moves there). Unix rules (1)-(3) alone run as busbar_core_connector::need::unix::tests"]
fn unix_destinations() {
    todo!("owner: W1-C1A (C-UNIX-DEST)")
}
