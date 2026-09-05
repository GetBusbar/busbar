// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/transport.rs`.

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
