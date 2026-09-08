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

/// THE TWO AXES ARE TWO, and neither one names the other's vocabulary.
///
/// `jsonrpc` and `http+json` are not channels. They are what a plane's messages are FRAMED as, and
/// A2A speaks both of them down one HTTP channel — which is why the conformance instrument scores
/// them as separate legs while the socket underneath is the same socket. `grpc` is the other way
/// round: a channel of its own whose framing happens to be protobuf.
///
/// So the family of every A2A binding is the family of the channel it really rides, and the thing
/// that tells the three apart lives on the framing axis. A single closed enum holding `Http` beside
/// `JsonRpc` cannot state that, because it makes a dialect and a channel the same kind of word.
#[test]
fn a_dialect_is_a_framing_and_a_channel_is_a_family() {
    use crate::plane::WireFraming;

    // Three legs, ONE channel. The A2A JSON-RPC and HTTP+JSON bindings and an ordinary plane POST
    // all ride the HTTP family; nothing about the channel distinguishes them.
    for leg in [Transport::Http, Transport::JsonRpc, Transport::HttpJson] {
        assert_eq!(leg.family(), TransportFamily::Http, "{}", leg.name());
    }
    // And the framing is where they differ.
    assert_eq!(Transport::Http.framing(), WireFraming::Native);
    assert_eq!(Transport::JsonRpc.framing(), WireFraming::JsonRpc);
    assert_eq!(Transport::HttpJson.framing(), WireFraming::HttpJson);

    // The transport axis's own vocabulary is channels and nothing else: no family is named after a
    // message framing. `grpc` is the deliberate coincidence — a channel AND a framing that share a
    // spelling — and it is admitted rather than hidden, which is why it is excluded by name here.
    for family in TransportFamily::ALL {
        assert!(
            !["jsonrpc", "http+json"].contains(&family.name()),
            "a transport family named a message framing: {}",
            family.name()
        );
    }
}

/// Every leg's label is exactly what it was before the axes were split. The label is a live metric
/// dimension and a served agent card's `protocolBinding`; changing one to make a point about
/// tidiness would be changing what an operator's dashboard means.
#[test]
fn the_labels_are_unchanged_by_the_split() {
    let names: Vec<&str> = Transport::ALL.iter().map(|t| t.name()).collect();
    assert_eq!(
        names,
        vec!["http", "jsonrpc", "http+json", "grpc", "stdio", "websocket"]
    );
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
