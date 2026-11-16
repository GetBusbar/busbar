// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EGRESS-OWNPORT (ABI-MIN3-INTERFACE §14): OPEN and FETCH to the node's own `listen`/`admin_listen` ports are
//! DENIED for every stated class.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): the judge clause runs as busbar_core_connector::need::judge::tests::the_nodes_own_port_is_refused_in_every_class; OPEN and FETCH through HostNeeds (a hostname resolving to loopback caught after resolution) need a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet, and the MediaRendezvous dial is the connector's datagram path, still driven over the old FramerDoor (OUTSTANDING row 6)"]
fn the_nodes_own_ports_are_denied_for_every_class() {
    todo!("owner: W1-C1A (C-EGRESS-OWNPORT)")
}
