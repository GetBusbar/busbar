// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry's boot check over what a node was actually composed out of, and the kind's ABI.

use busbar_contract::transport::{check_composition, CompositionError, Registered};

fn declared(
    key: &'static str,
    composes_over: &'static [&'static str],
    composed_over: Option<&'static str>,
) -> Registered {
    Registered {
        key,
        composes_over: std::borrow::Cow::Borrowed(composes_over),
        composed_over,
    }
}

#[test]
fn a_layered_stack_boots() {
    let registry = [
        declared("base", &[], None),
        declared("sealed", &["base"], None),
        declared("request", &["base", "sealed"], None),
        declared("events", &["request"], Some("request")),
        declared("duplex", &["request", "base"], Some("request")),
        declared("call", &["request", "base"], Some("base")),
        declared("piped", &[], None),
    ];
    assert_eq!(check_composition(&registry), Ok(()));
}

#[test]
fn a_declared_layer_that_nothing_registered_refuses_the_boot() {
    let registry = [
        declared("base", &[], None),
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
    let registry = [
        declared("base", &[], None),
        declared("piped", &[], None),
        declared("duplex", &["base"], Some("piped")),
    ];
    assert_eq!(
        check_composition(&registry),
        Err(CompositionError::UndeclaredComposition {
            transport: "duplex",
            used: "piped",
        })
    );
}

#[test]
fn two_transports_cannot_share_one_key() {
    let registry = [declared("base", &[], None), declared("base", &[], None)];
    assert_eq!(
        check_composition(&registry),
        Err(CompositionError::DuplicateKey("base"))
    );
}

#[test]
fn a_transport_that_opens_its_own_socket_is_checked_only_on_what_it_declares() {
    let registry = [
        declared("base", &[], None),
        declared("sealed", &["base"], None),
    ];
    assert_eq!(check_composition(&registry), Ok(()));
}

#[test]
fn the_transport_kind_has_one_abi_generation() {
    assert_eq!(
        busbar_contract::transport::TRANSPORT_ABI,
        busbar_contract::transport::AbiVersion(1)
    );
}

/// THE RUST FACE'S GENERATION IS THE KIND'S. `TRANSPORT_ABI` is the transport kind's
#[test]
fn the_transport_generation_is_the_abi_kind_version() {
    assert_eq!(
        u32::from(busbar_contract::transport::TRANSPORT_ABI.0),
        busbar_contract::abi::transport::ABI_VERSION
    );
    assert_eq!(
        busbar_contract::TRANSPORT_ABI,
        busbar_contract::abi::transport::TRANSPORT_ABI
    );
}
