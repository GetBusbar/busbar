// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry's boot check over what a node was actually composed out of, and the kind's ABI.
//!
//! `COMPOSES_OVER` was declared, typed, and read by nothing: a transport could name a layer no
//! deployment had, and a composition root could build one over a layer it never declared, and both
//! booted. A declaration nothing checks is the frame-honesty problem one layer up — the stack a
//! node reports is the stack its declarations describe, so the description has to be true.

use busbar_contract::transport::{check_composition, CompositionError, Registered};

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
    // `tcp → tls → http → { sse, ws, grpc }`, with `stdio` standing on its own — the seven
    // transports' actual `TransportMeta::COMPOSES_OVER` declarations and the `composed_over` each
    // registered row records, side by side. `tcp`, `tls` and `http` each open their own socket and answer `None`
    // regardless of what they declare; `sse`, `ws` and `grpc` are only ever built by holding (or
    // being handed) another instance, so they name it; `stdio` composes over nothing at all.
    let registry = [
        declared("tcp", &[], None),
        declared("tls", &["tcp"], None),
        declared("http", &["tcp", "tls"], None),
        declared("sse", &["http"], Some("http")),
        declared("ws", &["http", "tcp"], Some("http")),
        declared("grpc", &["http", "tcp"], Some("tcp")),
        declared("stdio", &[], None),
    ];
    assert_eq!(check_composition(&registry), Ok(()));
}

#[test]
fn a_declared_layer_that_nothing_registered_refuses_the_boot() {
    let registry = [
        declared("tcp", &[], None),
        declared("dgram", &["udp"], None),
    ];
    assert_eq!(
        check_composition(&registry),
        Err(CompositionError::UnregisteredLayer {
            transport: "dgram",
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
        busbar_contract::transport::TRANSPORT_ABI,
        busbar_contract::transport::AbiVersion(1)
    );
}
