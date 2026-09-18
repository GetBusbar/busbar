// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed transport.
//!
//! The same file, modulo the crate's own type, that every sibling of the transport kind carries
//! (`PLUGIN-TREE.md` §3). It drives the kind's own trait through THIS crate's implementor, so the
//! battery has a subject rather than a tautology: a wire that stopped implementing `Transport`, or
//! whose declared `KEY`/`ABI` drifted from what it registers, fails here rather than at boot.

use busbar_contract::{Kind, Plugin, Transport, TransportMeta};
use busbar_contract_transport::registry::TRANSPORT_ABI;
use busbar_transport_ws::WsTransport;

fn subject() -> WsTransport {
    WsTransport::default()
}

#[test]
fn kind_is_transport() {
    assert_eq!(subject().kind(), Kind::Transport);
}

#[test]
fn abi_matches_the_transport_floor() {
    assert_eq!(subject().abi(), TRANSPORT_ABI);
}

#[test]
fn key_is_the_declared_meta_key_and_is_lowercase() {
    let key = subject().key();
    assert_eq!(key, <WsTransport as TransportMeta>::KEY);
    assert!(!key.is_empty());
    assert_eq!(key, key.to_ascii_lowercase());
}

#[test]
fn object_safe_as_a_transport() {
    let s = subject();
    let _: &dyn Transport = &s;
}

#[test]
fn status_namespace_is_present_exactly_when_a_status_class_is() {
    assert_eq!(
        <WsTransport as TransportMeta>::STATUS_CLASS.is_some(),
        <WsTransport as TransportMeta>::STATUS_NAMESPACE.is_some(),
    );
}

#[test]
fn composition_claim_is_the_registration_claim() {
    assert_eq!(
        <WsTransport as TransportMeta>::COMPOSES_OVER,
        busbar_transport_ws::claims::COMPOSES_OVER,
    );
}
