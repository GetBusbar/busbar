// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract-transport/src/transport.rs` (relocated from
//! `busbar-substrate-values` 1.6.0).

use super::*;

/// The full-duplex leg is enumerated and carries the same bounded, unique label every other
/// variant does — so the axis stays walkable and no metric label collides.
#[test]
fn websocket_is_enumerated_with_a_stable_unique_label() {
    assert_eq!(Transport::WebSocket.name(), "websocket");
    assert!(
        Transport::ALL.contains(&Transport::WebSocket),
        "WebSocket must be in Transport::ALL or nothing enumerates it"
    );
    let names: Vec<_> = Transport::ALL.iter().map(|t| t.name()).collect();
    let mut deduped = names.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(deduped.len(), names.len(), "transport names must be unique");
}

/// The axis answers the full-duplex leg with its neutral wire shape — the one match on this axis,
/// mapping WebSocket to the bidirectional framed byte wire.
#[cfg(any(feature = "dispatch", feature = "runtime"))]
#[test]
fn websocket_selects_the_duplex_upstream_wire() {
    assert_eq!(
        Transport::WebSocket.upstream_wire(),
        Some(UpstreamWireKind::Duplex)
    );
}

/// THE AXIS NAMES CHANNELS AND NO PLANE'S BINDINGS (Law 1; THE DESIGN §1, "kernel, contract and
/// cleanliness crates × every kind instance = 0"). Which wire formats a plane speaks is the plane's
/// own declaration; the contract's axis is the channels a framed operation rides, and nothing else.
#[test]
fn the_transport_axis_names_channels_and_no_plane_binding() {
    let names: Vec<_> = Transport::ALL.iter().map(|t| t.name()).collect();
    assert_eq!(
        names,
        ["http", "stdio", "websocket"],
        "the transport axis carries a plane's bindings as channels"
    );
}
