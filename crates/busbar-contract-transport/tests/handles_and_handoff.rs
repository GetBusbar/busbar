// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The opaque handles, and the one value that crosses an in-band upgrade.
//!
//! A listener, a connection and a detached stream are all "a handle plus the few facts the layer
//! above is allowed to read". Every one of those facts was reachable and none of them was read back
//! by a test: the bound address a listener reports, the peer a connection names, and — the one that
//! decides whether a session happens at all — the layer a detached stream says handed it up. A
//! handoff is only admissible between the layers that declared it, so a stream that forgot which
//! layer made it is a session adopted by whoever dialled it.
//!
//! The `Debug` renderings are proofs too, not decoration: they are what a transport author reads off
//! a log line while an upgrade is failing, and each of these types hand-rolls one.

use busbar_contract_transport::{Conn, ConnHandle, Listener, ListenerHandle, RawStream};
use std::sync::Arc;

struct Bound(&'static str);
impl ListenerHandle for Bound {
    fn local_addr(&self) -> String {
        self.0.to_string()
    }
}

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
fn a_listener_reports_the_address_its_own_handle_is_bound_to() {
    // The address comes from the transport's handle, not from the contract: a listener that
    // answered with something of its own would have the kernel reporting a socket nobody is on.
    let listener = Listener::new(Arc::new(Bound("127.0.0.1:8443")));
    assert_eq!(listener.local_addr(), "127.0.0.1:8443");
    let rendered = format!("{listener:?}");
    assert!(rendered.contains("127.0.0.1:8443"), "{rendered}");
    assert!(rendered.contains("Listener"), "{rendered}");
}

#[test]
fn listener_identities_are_minted_here_and_never_repeat() {
    // Two listeners on one address are still two listeners, and the identity is what tells them
    // apart. Minted at construction, monotonic, and never handed to a transport to choose.
    let first = Listener::new(Arc::new(Bound("0.0.0.0:0")));
    let second = Listener::new(Arc::new(Bound("0.0.0.0:0")));
    assert!(
        second.id() > first.id(),
        "identities go forward: {} then {}",
        first.id(),
        second.id()
    );
}

#[test]
fn a_connection_answers_with_its_own_handles_identity_and_peer() {
    let conn = Conn::new(Arc::new(Socket {
        id: 77,
        peer: "203.0.113.9:51234",
    }));
    assert_eq!(conn.id(), 77);
    assert_eq!(conn.peer(), "203.0.113.9:51234");

    // Cloning a handle is not a second connection.
    let held = conn.clone();
    assert_eq!(held.id(), conn.id());
    assert_eq!(held.peer(), conn.peer());

    let rendered = format!("{conn:?}");
    assert!(rendered.contains("Conn"), "{rendered}");
    assert!(rendered.contains("77"), "{rendered}");
}

#[test]
fn a_detached_stream_carries_the_layer_that_handed_it_up() {
    // The whole reason the value exists: `from` is what the adopting layer checks before it adopts
    // anything, and a stream that lost it would be adopted by whoever took it. The peer travels with
    // it so the adopting layer does not have to ask a socket it does not own.
    let stream = RawStream::new(
        "http",
        "198.51.100.4:44300".to_string(),
        Box::new(futures::io::Cursor::new(Vec::new())),
    );
    assert_eq!(stream.from(), "http");
    assert_eq!(stream.peer(), "198.51.100.4:44300");

    let rendered = format!("{stream:?}");
    assert!(rendered.contains("http"), "{rendered}");
    assert!(rendered.contains("198.51.100.4:44300"), "{rendered}");
    assert!(rendered.contains("RawStream"), "{rendered}");

    // Consuming: after a handoff there is exactly one owner, and it is whoever took the io.
    let io = stream.into_io();
    drop(io);
}

#[test]
fn a_handoff_between_two_layers_is_told_apart_by_the_layer_it_names() {
    // Two streams that differ only in which layer detached them. A target that composes over `http`
    // adopts the first and refuses the second, so the field the refusal turns on has to be the one
    // the source actually named.
    let from_http = RawStream::new(
        "http",
        "peer:1".to_string(),
        Box::new(futures::io::Cursor::new(Vec::new())),
    );
    let from_stdio = RawStream::new(
        "stdio",
        "peer:1".to_string(),
        Box::new(futures::io::Cursor::new(Vec::new())),
    );
    assert_ne!(from_http.from(), from_stdio.from());
    assert_eq!(from_http.peer(), from_stdio.peer());
}
