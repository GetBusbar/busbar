// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CONN-SCOPE (ABI-MIN3-INTERFACE §14): Conns scoped to `(instance, chain)` (rounds 15, 16).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): (b) and (c) at the conn table run as busbar_core_connector::need::table::tests::{a_conn_is_reachable_only_under_its_own_instance_and_chain, release_returns_exactly_the_chains_conns_and_leaves_no_row}; the arm needs two Driver::new chains of one booted store fixture OPENing through HostNeeds (a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet; the suites Harness drives FakeNeeds), 10,000 chains on 16 threads and the trybuild case"]
fn conns_are_scoped_to_their_chain() {
    todo!("owner: W1-C1A (C-CONN-SCOPE)")
}

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): needs a booted store fixture whose chain OPENs through HostNeeds, drops its Conn unclosed and ends OK, REFUSED and FAILED, under a counting Needs (a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet; the suites Harness drives FakeNeeds); table release alone runs as busbar_core_connector::need::table::tests::release_returns_exactly_the_chains_conns_and_leaves_no_row"]
fn an_unclosed_conn_is_released_and_a_never_need_chain_makes_no_call() {
    todo!("owner: W1-C1A (C-CONN-SCOPE)")
}
