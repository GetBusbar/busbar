// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed transport.
//!
//! The same file, modulo the crate's own type, that every sibling of the transport kind carries
//! (`PLUGIN-TREE.md` §3). It drives the kind's own trait through THIS crate's implementor, so the
//! battery has a subject rather than a tautology: a wire that stopped implementing `Transport`, or
//! whose declared `KEY`/`ABI` drifted from what it registers, fails here rather than at boot.

use std::sync::Arc;

use busbar_contract::{Kind, Plugin, Transport, TransportMeta};
use busbar_contract_transport::registry::TRANSPORT_ABI;
use busbar_transport_http::{ClientSettings, HttpTransport};
use busbar_transport_sse::SseTransport;

fn subject() -> SseTransport {
    SseTransport::new(Arc::new(HttpTransport::new(ClientSettings::default())))
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
    assert_eq!(key, <SseTransport as TransportMeta>::KEY);
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
    // The two halves of the status leg cannot disagree: a wire that names WHICH frame carries its
    // status must also name the vocabulary that numbered it, and one that carries no status leg
    // names neither.
    assert_eq!(
        <SseTransport as TransportMeta>::STATUS_CLASS.is_some(),
        <SseTransport as TransportMeta>::STATUS_NAMESPACE.is_some(),
    );
}

#[test]
fn composition_claim_is_the_registration_claim() {
    // The claim the boot reads is exactly the crate's own claims constant.
    assert_eq!(
        <SseTransport as TransportMeta>::COMPOSES_OVER,
        busbar_transport_sse::claims::COMPOSES_OVER,
    );
}
