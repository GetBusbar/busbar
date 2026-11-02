// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
