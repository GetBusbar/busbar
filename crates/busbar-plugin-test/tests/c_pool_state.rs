// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-STATE (ABI-MIN3-INTERFACE §14): Pooled-conn ids (round 19). FakeNeeds mints the same way (`fake_needs`
//! unit tests). The store and ldap arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: pooled-conn ids go through busbar-core-connector, which is not a dependency of busbar-plugin-test; FakeNeeds minting is covered by fake_needs unit tests (W1-C1A)"]
fn pooled_ids_through_the_connector() {
    todo!("owner: W1-C1A (C-POOL-STATE)")
}
