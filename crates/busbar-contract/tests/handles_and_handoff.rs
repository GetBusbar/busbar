// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The opaque handles, and the one value that crosses an in-band upgrade.

use busbar_contract::transport::{Conn, ConnHandle, RawStream};
use std::sync::Arc;

struct Socket {
    id: u64,
    peer: &'static str,
}
impl ConnHandle for Socket {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.to_string()
    }
}

#[test]
fn a_connection_answers_with_its_own_handles_identity_and_peer() {
    let conn = Conn::new(Arc::new(Socket {
        id: 77,
        peer: "203.0.113.9:51234",
    }));
    assert_eq!(conn.id(), 77);
    assert_eq!(conn.peer(), "203.0.113.9:51234");

    let held = conn.clone();
    assert_eq!(held.id(), conn.id());
    assert_eq!(held.peer(), conn.peer());

    let rendered = format!("{conn:?}");
    assert!(rendered.contains("Conn"), "{rendered}");
    assert!(rendered.contains("77"), "{rendered}");
}

#[test]
fn a_detached_stream_carries_the_layer_that_handed_it_up() {
    let stream = RawStream::new(
        "request",
        "198.51.100.4:44300".to_string(),
        Box::new(futures::io::Cursor::new(Vec::new())),
    );
    assert_eq!(stream.from(), "request");
    assert_eq!(stream.peer(), "198.51.100.4:44300");

    let rendered = format!("{stream:?}");
    assert!(rendered.contains("request"), "{rendered}");
    assert!(rendered.contains("198.51.100.4:44300"), "{rendered}");
    assert!(rendered.contains("RawStream"), "{rendered}");

    let io = stream.into_io();
    drop(io);
}

#[test]
fn a_handoff_between_two_layers_is_told_apart_by_the_layer_it_names() {
    let from_request = RawStream::new(
        "request",
        "peer:1".to_string(),
        Box::new(futures::io::Cursor::new(Vec::new())),
    );
    let from_piped = RawStream::new(
        "piped",
        "peer:1".to_string(),
        Box::new(futures::io::Cursor::new(Vec::new())),
    );
    assert_ne!(from_request.from(), from_piped.from());
    assert_eq!(from_request.peer(), from_piped.peer());
}
