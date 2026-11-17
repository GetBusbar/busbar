// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-WARM (ABI-MIN3-INTERFACE §14): 1,000 sequential OPEN -> CLOSE(REUSABLE) on one dest: one DNS lookup, one
//! guard check, one cert resolve.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): a Guard::publish does not flush HostNeeds' NeedPool (busbar-core-connector need/key.rs has no flush and nothing ties the guard to the pool), so the flush-and-re-dial clause is red (a cert rotation re-dials: the digest is keyed by custody generation, need/certs.rs); the counting clauses run through HostNeeds::open/close and need a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet. The arm then moves into busbar-core-connector (not a dependency of this crate)"]
fn reusable_opens_resolve_and_judge_once() {
    todo!("owner: W1-C1A (C-POOL-WARM)")
}
