// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A fourth transport family costs no reader an edit.
//!
//! Both shapes in this crate used to name transports in their own vocabulary: a status was
//! `Http(u16)` or `Grpc(u8)`, and a destination that needed a method name got an arm of its own.
//! Either way, the family list lived in the type, so a fourth family was an edit to every reader
//! that matched the arms by name — and the tree matches them by name deliberately, so that edit was
//! fifty sites, not one.
//!
//! These tests plant a family this tree does not have — `quic` — and assert it answers every
//! question the two shipped families answer, through the same keyed accessors, without a line
//! changing anywhere. A closed vocabulary cannot pass them; a keyed one passes them for free.

use busbar_contract_transport::registry::{facts, status_ns};
use busbar_contract_transport::wire::WireStatus;
use busbar_contract_transport::UpstreamAddress;

/// A status namespace nothing in this tree registers, spelled here and nowhere else.
const QUIC: &str = "quic";

#[test]
fn a_fourth_status_namespace_needs_no_reader_edit() {
    let quic = WireStatus::new(QUIC, 42);

    // The planted family carries its own numbering, unmangled, and answers its own question.
    assert_eq!(quic.namespace, QUIC);
    assert_eq!(quic.code, 42);
    assert_eq!(quic.in_namespace(QUIC), Some(42));

    // It answers `None` to the two shipped questions BECAUSE THE NAMESPACES DIFFER — not because
    // of a variant it is not, which is the reading that had to be re-stated at every match site.
    assert_eq!(quic.http(), None);
    assert_eq!(quic.grpc(), None);

    // And the two shipped families are unchanged in what they say.
    assert_eq!(WireStatus::new(status_ns::HTTP, 503).http(), Some(503));
    assert_eq!(WireStatus::new(status_ns::GRPC, 14).grpc(), Some(14));

    // The spelling collision the namespace exists for: `14` in gRPC's numbering is `UNAVAILABLE`
    // and is not a status at all in HTTP's. Neither answers the other's question.
    assert_eq!(WireStatus::new(status_ns::GRPC, 14).http(), None);
    assert_eq!(WireStatus::new(status_ns::HTTP, 14).grpc(), None);
    assert_ne!(
        WireStatus::new(status_ns::GRPC, 14),
        WireStatus::new(status_ns::HTTP, 14)
    );
}

#[test]
fn the_reserved_status_namespaces_are_spelled_once() {
    assert!(status_ns::is_reserved(status_ns::HTTP));
    assert!(status_ns::is_reserved(status_ns::GRPC));
    assert!(
        !status_ns::is_reserved(QUIC),
        "a namespace the kernel does not reserve is a transport's own to name"
    );
}

#[test]
fn a_fourth_destination_family_needs_no_reader_edit() {
    // The planted family dials a socket and needs one wire fact of its own beside the address.
    // That used to mean a third arm, and a third arm meant an answer at all six accessors from
    // every family that has nothing to say about it — six edits to spell "not mine" six times.
    let quic = UpstreamAddress::Socket {
        authority: "upstream.internal:8443",
        sni: Some("upstream.internal"),
        extras: &[("stream-group", "inference")],
    };

    // The SHAPE is what the two arms are for: a peer you connect to. That much the planted family
    // shares with every other socket family, and it reads it through the same accessors.
    assert_eq!(quic.authority(), Some("upstream.internal:8443"));
    assert_eq!(quic.sni(), Some("upstream.internal"));

    // What is its own is a KEY, and a key needs no arm.
    assert_eq!(quic.extra("stream-group"), Some("inference"));

    // A transport that does not understand a key does not see one: it asks for its own and gets
    // `None`, which is the ignoring the negotiation is built on.
    assert_eq!(quic.extra(facts::METHOD), None);
}

#[test]
fn the_method_a_call_per_path_family_dials_by_is_a_key_on_a_socket() {
    // The gRPC destination is a SOCKET — a peer you connect to — carrying one declared fact, under
    // the same reserved key the arrival grammar already spells for a request method.
    let grpc = UpstreamAddress::Socket {
        authority: "upstream.internal:8443",
        sni: Some("upstream.internal"),
        extras: &[(facts::METHOD, "/vendor.Inference/Chat")],
    };
    assert_eq!(grpc.authority(), Some("upstream.internal:8443"));
    assert_eq!(grpc.extra(facts::METHOD), Some("/vendor.Inference/Chat"));

    // The other shape is a process you spawn, and it is a shape rather than a key because nothing
    // about an argument vector or a spawn environment is a socket's business.
    let program = UpstreamAddress::Program {
        path: "/usr/local/bin/server",
        args: &["--stdio"],
        env: &[],
        extras: &[],
    };
    assert_eq!(program.authority(), None);
    assert_eq!(program.extra(facts::METHOD), None);
}

#[test]
fn a_transport_refuses_the_key_it_requires_and_ignores_the_rest() {
    // The other half of the negotiation, and the half a silent default hid: a transport that
    // CANNOT dial without a key says so against the destination, once, rather than substituting
    // something of its own and dialling somewhere nobody named.
    let bare = UpstreamAddress::socket("upstream.internal:8443");
    assert_eq!(
        bare.missing(&[facts::METHOD]),
        Some(facts::METHOD),
        "a required key the destination never declared is the refusal, not a default"
    );

    let named = UpstreamAddress::Socket {
        authority: "upstream.internal:8443",
        sni: None,
        extras: &[(facts::METHOD, "/vendor.Inference/Chat")],
    };
    assert_eq!(named.missing(&[facts::METHOD]), None);

    // A transport that requires nothing is refused by nothing, however much the destination
    // declares that it has never heard of.
    assert_eq!(named.missing(&[]), None);
}
