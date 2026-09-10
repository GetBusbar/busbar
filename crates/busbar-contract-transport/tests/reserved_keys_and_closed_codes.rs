// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two closed lists this crate exists to pin: the fact keys the kernel reserves, and the codes
//! a transport is allowed to end something with.
//!
//! Both were declarations nothing read back. `facts::RESERVED` was a list, `is_reserved` a lookup
//! into it and `undeclared` the registration check built on the lookup — and no test named a single
//! one of the six spellings, so a key renamed, dropped from the list, or answered for by a check
//! that had quietly inverted its condition all still passed. A reserved key that stops being
//! recognised is a value a plane reads and no boot check knows about, which is the exact failure the
//! module says it exists to make impossible.
//!
//! The closed codes are the same claim on the other axis: each maps one-to-one onto a unit end, so
//! the set has to be complete and each member has to render as itself. The exhaustive matches below
//! are the totality half — a code added to any of these enums stops this file compiling until
//! somebody says what it renders as — and the rendering assertions are the other half.

use busbar_contract_transport::registry::{facts, status_ns};
use busbar_contract_transport::{
    CloseReason, CompositionError, Decode, Direction, DiscardCode, Encode, Framing, StatusAt,
    TransportError, Unit0Trigger, WireStatus, WireStatusClass,
};

// ── the reserved fact keys ───────────────────────────────────────────────────────────────────────

/// The six spellings, written out here rather than read off the constants.
///
/// A test that compared `facts::PATH` against `facts::PATH` would agree with itself for free: the
/// point of the list is that three planes each guessed `"path"`, so the guess is what has to be
/// pinned. These literals are that guess, recorded once.
const SPELLINGS: [(&str, &str); 6] = [
    ("PATH", "path"),
    ("METHOD", "method"),
    ("AUTHORITY", "authority"),
    ("ALPN", "alpn"),
    ("SNI", "sni"),
    ("PEER", "peer"),
];

#[test]
fn every_reserved_key_is_spelled_the_way_the_planes_guessed_it() {
    assert_eq!(
        [
            facts::PATH,
            facts::METHOD,
            facts::AUTHORITY,
            facts::ALPN,
            facts::SNI,
            facts::PEER,
        ],
        SPELLINGS.map(|(_, wire)| wire),
    );
}

#[test]
fn the_reserved_list_is_exactly_the_six_keys_and_names_none_of_them_twice() {
    assert_eq!(facts::RESERVED, &SPELLINGS.map(|(_, wire)| wire)[..]);
    let mut seen = facts::RESERVED.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), before, "a key is named twice in RESERVED");
}

#[test]
fn a_reserved_key_is_recognised_and_a_transports_own_key_is_not() {
    for (name, wire) in SPELLINGS {
        assert!(facts::is_reserved(wire), "{name} is not recognised");
    }
    // The other side of the answer, without which "reserved" is a function that says yes to
    // everything: a transport's own vocabulary is open, and none of it is the kernel's.
    for own in ["x-request-id", "Path", "path ", "", "peer_addr"] {
        assert!(
            !facts::is_reserved(own),
            "`{own}` is a transport's own key, not one the kernel reserves"
        );
    }
}

#[test]
fn a_reserved_key_published_without_being_declared_is_the_one_that_comes_back() {
    // The registration check: what a transport WRITES, against what it DECLARED.
    assert_eq!(
        facts::undeclared(&[facts::PATH], &[facts::PATH, facts::METHOD]),
        Some(facts::METHOD),
    );
    // First in publication order, not first in RESERVED order — the answer names the key the
    // registration actually tripped over.
    assert_eq!(
        facts::undeclared(&[], &[facts::SNI, facts::PATH]),
        Some(facts::SNI),
    );
}

#[test]
fn a_declared_key_and_a_transports_own_key_both_pass_the_registration_check() {
    // Declared: the transport said it publishes it, so publishing it is exactly what was promised.
    // A check that had dropped the negation would refuse the one registration that is correct.
    assert_eq!(facts::undeclared(facts::RESERVED, facts::RESERVED), None);
    assert_eq!(
        facts::undeclared(&[facts::PATH, facts::PEER], &[facts::PEER, facts::PATH]),
        None,
    );
    // Not reserved: none of this applies, however undeclared it is. A check reading the two
    // conditions as an either/or would fail a transport for publishing its own vocabulary.
    assert_eq!(
        facts::undeclared(&[], &["x-request-id", "trace-parent"]),
        None
    );
    // Nothing published at all: no first offender to name.
    assert_eq!(facts::undeclared(&[], &[]), None);
}

#[test]
fn a_composition_refusal_says_which_transport_and_which_layer() {
    // Each of the three is read by a human at boot, off a node that will not start. A refusal that
    // rendered as nothing would leave the operator with an exit code.
    let unregistered = CompositionError::UnregisteredLayer {
        transport: "webrtc",
        layer: "udp",
    };
    let rendered = unregistered.to_string();
    assert!(
        rendered.contains("webrtc") && rendered.contains("udp"),
        "{rendered}"
    );
    assert!(rendered.contains("no registered transport"), "{rendered}");

    let undeclared = CompositionError::UndeclaredComposition {
        transport: "ws",
        used: "stdio",
    };
    let rendered = undeclared.to_string();
    assert!(
        rendered.contains("ws") && rendered.contains("stdio"),
        "{rendered}"
    );
    assert!(rendered.contains("does not declare"), "{rendered}");

    let duplicate = CompositionError::DuplicateKey("tcp");
    let rendered = duplicate.to_string();
    assert!(rendered.contains("tcp"), "{rendered}");
    assert!(rendered.contains("two transports"), "{rendered}");
}

// ── the closed codes ─────────────────────────────────────────────────────────────────────────────

/// Every transport failure, named one at a time.
///
/// The exhaustive match is the totality check: a failure added to the enum does not compile until it
/// is named here, which is what "closed set, one-to-one onto a unit end" has to mean in code rather
/// than in prose.
fn every_transport_error() -> Vec<(TransportError, &'static str)> {
    use TransportError::*;
    let all = [
        Refused,
        Timeout,
        Reset,
        Closed,
        HandshakeFailed,
        KeyUnavailable,
        AddressRefused,
        Backpressure,
        Framing,
        HandoffMismatch,
    ];
    all.iter()
        .map(|e| {
            let name = match e {
                Refused => "Refused",
                Timeout => "Timeout",
                Reset => "Reset",
                Closed => "Closed",
                HandshakeFailed => "HandshakeFailed",
                KeyUnavailable => "KeyUnavailable",
                AddressRefused => "AddressRefused",
                Backpressure => "Backpressure",
                Framing => "Framing",
                HandoffMismatch => "HandoffMismatch",
            };
            (*e, name)
        })
        .collect()
}

#[test]
fn every_transport_failure_renders_as_itself_and_no_two_share_a_rendering() {
    let all = every_transport_error();
    assert_eq!(all.len(), 10, "a failure was added or dropped");
    for (code, name) in &all {
        assert_eq!(&code.to_string(), name);
    }
    let mut rendered: Vec<String> = all.iter().map(|(c, _)| c.to_string()).collect();
    rendered.sort();
    let before = rendered.len();
    rendered.dedup();
    assert_eq!(
        rendered.len(),
        before,
        "two transport failures render as one word"
    );
}

#[test]
fn a_transport_failure_is_an_error_a_caller_can_report() {
    // `Display` is what a log line and a refusal both read; the `Error` impl is what lets one
    // travel as a cause. A rendering that produced nothing would put an empty reason on both.
    let err: &dyn std::error::Error = &TransportError::HandoffMismatch;
    assert_eq!(err.to_string(), "HandoffMismatch");
    assert!(err.source().is_none());
}

#[test]
fn every_decode_and_encode_failure_renders_as_itself() {
    let decodes = [
        (Decode::Malformed, "Malformed"),
        (Decode::UnsupportedOperation, "UnsupportedOperation"),
        (Decode::MissingDeclaredFact, "MissingDeclaredFact"),
        (Decode::Oversize, "Oversize"),
    ];
    for (code, name) in decodes {
        assert_eq!(code.to_string(), name);
        // Totality: a fifth arm does not compile until it is answered for here.
        let _: bool = match code {
            Decode::Malformed
            | Decode::UnsupportedOperation
            | Decode::MissingDeclaredFact
            | Decode::Oversize => true,
        };
    }
    let encodes = [
        (Encode::Unrepresentable, "Unrepresentable"),
        (Encode::ArenaExhausted, "ArenaExhausted"),
        (Encode::SecretPlaceholder, "SecretPlaceholder"),
        (Encode::Poisoned, "Poisoned"),
    ];
    for (code, name) in encodes {
        assert_eq!(code.to_string(), name);
        let _: bool = match code {
            Encode::Unrepresentable
            | Encode::ArenaExhausted
            | Encode::SecretPlaceholder
            | Encode::Poisoned => true,
        };
    }
}

#[test]
fn the_close_and_discard_vocabularies_are_complete_and_have_no_duplicates() {
    let closes = [
        CloseReason::Normal,
        CloseReason::PeerClosed,
        CloseReason::Drain,
        CloseReason::Poisoned,
        CloseReason::Revoked,
        CloseReason::Timeout,
        CloseReason::TransportFailed,
        CloseReason::CapacityExhausted,
    ];
    assert_eq!(closes.len(), 8);
    for (i, a) in closes.iter().enumerate() {
        for b in &closes[..i] {
            assert_ne!(a, b, "a close reason is listed twice");
        }
        // Totality: a ninth reason does not compile until it is named.
        let _: bool = match a {
            CloseReason::Normal
            | CloseReason::PeerClosed
            | CloseReason::Drain
            | CloseReason::Poisoned
            | CloseReason::Revoked
            | CloseReason::Timeout
            | CloseReason::TransportFailed
            | CloseReason::CapacityExhausted => true,
        };
    }

    let discards = [
        DiscardCode::Malformed,
        DiscardCode::UnknownCorrelation,
        DiscardCode::ForgedSource,
        DiscardCode::Duplicate,
        DiscardCode::OutOfWindow,
        DiscardCode::Unsupported,
    ];
    assert_eq!(discards.len(), 6);
    for (i, a) in discards.iter().enumerate() {
        for b in &discards[..i] {
            assert_ne!(a, b, "a discard code is listed twice");
        }
        let _: bool = match a {
            DiscardCode::Malformed
            | DiscardCode::UnknownCorrelation
            | DiscardCode::ForgedSource
            | DiscardCode::Duplicate
            | DiscardCode::OutOfWindow
            | DiscardCode::Unsupported => true,
        };
    }
}

#[test]
fn the_frame_axes_a_transport_declares_are_each_closed() {
    // Four small vocabularies the money path reads: which way the bytes went, what the upstream
    // said, which frame said it, and how the bytes are delimited. Each is matched exhaustively, so
    // none of them can grow an arm nobody answered for.
    for d in [Direction::Inbound, Direction::Outbound] {
        let _: bool = match d {
            Direction::Inbound | Direction::Outbound => true,
        };
    }
    for s in [
        WireStatusClass::Success,
        WireStatusClass::ClientError,
        WireStatusClass::ServerError,
        WireStatusClass::Other,
    ] {
        let _: bool = match s {
            WireStatusClass::Success
            | WireStatusClass::ClientError
            | WireStatusClass::ServerError
            | WireStatusClass::Other => true,
        };
    }
    for a in [StatusAt::FirstFrame, StatusAt::Terminal] {
        let _: bool = match a {
            StatusAt::FirstFrame | StatusAt::Terminal => true,
        };
    }
    // Load-bearing, not descriptive: a stream that loses sync loses the connection and a datagram
    // that does not decode is one datagram.
    assert_ne!(Framing::Stream, Framing::Datagram);
    for f in [Framing::Stream, Framing::Datagram] {
        let _: bool = match f {
            Framing::Stream | Framing::Datagram => true,
        };
    }
    for t in [
        Unit0Trigger::FirstBytes,
        Unit0Trigger::FirstLine,
        Unit0Trigger::FirstMessage,
        Unit0Trigger::FirstDatagram,
        Unit0Trigger::Upgrade,
        Unit0Trigger::Handshake,
    ] {
        let _: bool = match t {
            Unit0Trigger::FirstBytes
            | Unit0Trigger::FirstLine
            | Unit0Trigger::FirstMessage
            | Unit0Trigger::FirstDatagram
            | Unit0Trigger::Upgrade
            | Unit0Trigger::Handshake => true,
        };
    }
}

#[test]
fn a_wire_status_answers_only_in_the_numbering_that_spelled_it() {
    // `14` is `UNAVAILABLE` in gRPC's numbering and is not a status at all in HTTP's. A reader
    // handed the number alone matches it against HTTP's bands, finds none, and calls a dead upstream
    // the caller's fault — so neither accessor may coerce the other numbering into an answer.
    let http = WireStatus::new(status_ns::HTTP, 503);
    assert_eq!(http.http(), Some(503));
    assert_eq!(http.grpc(), None);

    let grpc = WireStatus::new(status_ns::GRPC, 14);
    assert_eq!(grpc.grpc(), Some(14));
    assert_eq!(grpc.http(), None);

    // The shared spelling, kept apart: gRPC's `5` is NOT_FOUND and HTTP has no `5`.
    assert_ne!(
        WireStatus::new(status_ns::GRPC, 5),
        WireStatus::new(status_ns::HTTP, 5)
    );
    assert_eq!(WireStatus::new(status_ns::GRPC, 5).http(), None);
}
