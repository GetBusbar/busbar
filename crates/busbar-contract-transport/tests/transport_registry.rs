// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry's boot check over what a node was actually composed out of, the kind's ABI, and the
//! identity a listener carries.
//!
//! `COMPOSES_OVER` was declared, typed, and read by nothing: a transport could name a layer no
//! deployment had, and a composition root could build one over a layer it never declared, and both
//! booted. A declaration nothing checks is the frame-honesty problem one layer up — the stack a
//! node reports is the stack its declarations describe, so the description has to be true.

use busbar_contract_transport::{
    check_composition, CompositionError, Listener, ListenerHandle, Registered,
};
use std::sync::Arc;

fn declared(
    key: &'static str,
    composes_over: &'static [&'static str],
    composed_over: Option<&'static str>,
) -> Registered {
    Registered {
        key,
        composes_over,
        composed_over,
    }
}

#[test]
fn the_real_stack_boots() {
    // `tcp → tls → http → ws`, with `grpc` beside `ws` — the design's own table, wired the way the
    // crates are actually built.
    let registry = [
        declared("tcp", &[], None),
        declared("tls", &["tcp"], None),
        declared("http", &["tcp", "tls"], None),
        declared("ws", &["http", "tcp"], Some("http")),
        declared("grpc", &["http", "tcp"], Some("tcp")),
    ];
    assert_eq!(check_composition(&registry), Ok(()));
}

#[test]
fn a_declared_layer_that_nothing_registered_refuses_the_boot() {
    let registry = [
        declared("tcp", &[], None),
        declared("webrtc", &["udp"], None),
    ];
    assert_eq!(
        check_composition(&registry),
        Err(CompositionError::UnregisteredLayer {
            transport: "webrtc",
            layer: "udp",
        })
    );
}

#[test]
fn a_composition_the_transport_never_declared_refuses_the_boot() {
    // The other direction: every name resolves, but `ws` was built over a layer it does not
    // declare. Nothing about the registry's contents catches this — only comparing what was
    // declared against what was used.
    let registry = [
        declared("tcp", &[], None),
        declared("stdio", &[], None),
        declared("ws", &["tcp"], Some("stdio")),
    ];
    assert_eq!(
        check_composition(&registry),
        Err(CompositionError::UndeclaredComposition {
            transport: "ws",
            used: "stdio",
        })
    );
}

#[test]
fn two_transports_cannot_share_one_key() {
    let registry = [declared("tcp", &[], None), declared("tcp", &[], None)];
    assert_eq!(
        check_composition(&registry),
        Err(CompositionError::DuplicateKey("tcp"))
    );
}

#[test]
fn a_transport_that_opens_its_own_socket_is_checked_only_on_what_it_declares() {
    let registry = [declared("tcp", &[], None), declared("tls", &["tcp"], None)];
    assert_eq!(check_composition(&registry), Ok(()));
}

#[test]
fn the_transport_kind_has_one_abi_generation() {
    // Transports are in-tree, so there is no loader window to police — but the ABI-surface scan
    // needs something to compare against, and every transport naming the same constant is what
    // makes "one generation" a fact rather than a coincidence between six crates.
    assert_eq!(
        busbar_contract_transport::TRANSPORT_ABI,
        busbar_contract_transport::AbiVersion(1)
    );
}

struct Bound(&'static str);
impl ListenerHandle for Bound {
    fn local_addr(&self) -> String {
        self.0.to_string()
    }
}

#[test]
fn two_listeners_on_one_address_are_still_two_listeners() {
    // A node always holds at least two — data and admin — and a configuration is free to give them
    // the same bound address. A transport keying per-listener state on the address string was
    // keying it on something two listeners could share.
    let data = Listener::new(Arc::new(Bound("127.0.0.1:8080")));
    let admin = Listener::new(Arc::new(Bound("127.0.0.1:8080")));
    assert_eq!(data.local_addr(), admin.local_addr());
    assert_ne!(data.id(), admin.id(), "the identity is not the address");
}

#[test]
fn a_listener_keeps_its_identity_across_clones() {
    let listener = Listener::new(Arc::new(Bound("127.0.0.1:0")));
    let held = listener.clone();
    assert_eq!(
        listener.id(),
        held.id(),
        "cloning a handle is not a new listener"
    );
    assert!(format!("{listener:?}").contains(&listener.id().to_string()));
}
