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

use busbar_contract_transport::registry::status_ns;
use busbar_contract_transport::wire::WireStatus;

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
