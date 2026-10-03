// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BODY IS NOT COPIED ON ITS WAY OUT (the zero-copy body law).
//!
//! The request's body is the largest thing on the money path, and the far end hands it to the
//! connector where it lies: one allocation, from the plane's bound request to the connector's
//! open. A copy pays for the whole body a second time per attempt. The address is the proof: the
//! same allocation is the same address, and a copy is somewhere else. (The push attempt's twin of
//! this test asserted the same of the transport's arena; the far end has no arena, the bound
//! request's own buffer is the one.)

use super::harness::{ok_frames, Script};
use super::{member, Node};
use busbar_contract::conn::ConnError;
use busbar_kernel_egress::ports::DestinationId;

#[test]
fn the_body_the_connector_is_handed_is_the_requests_own_and_not_a_copy() {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    // A failover, so the property is held on every attempt and not only the first.
    node.conns
        .script("a", Script::DialError(ConnError::Refused));
    node.conns.script("b", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());

    let sent = node.sent_at.lock().unwrap().clone();
    let opened = node.conns.bodies_at.lock().unwrap().clone();
    assert_eq!(sent.len(), 2, "one request per attempt");
    assert_eq!(
        opened, sent,
        "the connector was handed each request's own body rather than a second copy of it"
    );
}
