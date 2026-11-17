// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-STATE (ABI-MIN3-INTERFACE §14): Pooled-conn ids (round 19). FakeNeeds mints the same way (`fake_needs`
//! unit tests). The store and ldap arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): a Guard::publish does not flush HostNeeds' NeedPool (need/key.rs has no flush), so the publish-flush clause is red; the rest runs through HostNeeds::open/starttls/close and needs a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet (the arm then moves there). Id minting alone runs as busbar_core_connector::need::table::tests::pooled_ids_are_per_instance_and_never_repeat; FakeNeeds minting is covered by fake_needs unit tests"]
fn pooled_ids_through_the_connector() {
    todo!("owner: W1-C1A (C-POOL-STATE)")
}
