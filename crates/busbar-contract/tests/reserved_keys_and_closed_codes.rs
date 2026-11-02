// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two closed lists this crate exists to pin: the fact keys the kernel reserves, and the codes

use busbar_contract::transport::registry::{facts, status_ns};
use busbar_contract::transport::{
    CloseReason, CompositionError, Decode, Direction, DiscardCode, Encode, Framing, StatusAt,
    TransportError, Unit0Trigger, WireStatus, WireStatusClass,
};

/// The six spellings, written out here rather than read off the constants.

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

    for own in ["x-request-id", "Path", "path ", "", "peer_addr"] {
        assert!(
            !facts::is_reserved(own),
            "`{own}` is a transport's own key, not one the kernel reserves"
        );
    }
}

#[test]
fn a_reserved_key_published_without_being_declared_is_the_one_that_comes_back() {
    assert_eq!(
        facts::undeclared(&[facts::PATH], &[facts::PATH, facts::METHOD]),
        Some(facts::METHOD),
    );

    assert_eq!(
        facts::undeclared(&[], &[facts::SNI, facts::PATH]),
        Some(facts::SNI),
    );
}

#[test]
fn a_declared_key_and_a_transports_own_key_both_pass_the_registration_check() {
    assert_eq!(facts::undeclared(facts::RESERVED, facts::RESERVED), None);
    assert_eq!(
        facts::undeclared(&[facts::PATH, facts::PEER], &[facts::PEER, facts::PATH]),
        None,
    );

    assert_eq!(
        facts::undeclared(&[], &["x-request-id", "trace-parent"]),
        None
    );

    assert_eq!(facts::undeclared(&[], &[]), None);
}

#[test]
fn a_composition_refusal_says_which_transport_and_which_layer() {
    let unregistered = CompositionError::UnregisteredLayer {
        transport: "dgram",
        layer: "udp",
    };
    let rendered = unregistered.to_string();
    assert!(
        rendered.contains("dgram") && rendered.contains("udp"),
        "{rendered}"
    );
    assert!(rendered.contains("no registered transport"), "{rendered}");

    let undeclared = CompositionError::UndeclaredComposition {
        transport: "duplex",
        used: "piped",
    };
    let rendered = undeclared.to_string();
    assert!(
        rendered.contains("duplex") && rendered.contains("piped"),
        "{rendered}"
    );
    assert!(rendered.contains("does not declare"), "{rendered}");

    let duplicate = CompositionError::DuplicateKey("base");
    let rendered = duplicate.to_string();
    assert!(rendered.contains("base"), "{rendered}");
    assert!(rendered.contains("two transports"), "{rendered}");
}

/// Every transport failure, named one at a time.

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

        let _: bool = match code {
            Decode::Malformed
            | Decode::UnsupportedOperation
            | Decode::MissingDeclaredFact
            | Decode::Oversize => true,
        };
    }
    let encodes = [
        (Encode::Unrepresentable, "Unrepresentable"),
        (Encode::ScratchExhausted, "ScratchExhausted"),
        (Encode::SecretPlaceholder, "SecretPlaceholder"),
        (Encode::Poisoned, "Poisoned"),
    ];
    for (code, name) in encodes {
        assert_eq!(code.to_string(), name);
        let _: bool = match code {
            Encode::Unrepresentable
            | Encode::ScratchExhausted
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
    for d in [Direction::Inbound, Direction::Outbound] {
        let _: bool = match d {
            Direction::Inbound | Direction::Outbound => true,
        };
    }
    for s in [
        WireStatusClass::Success,
        WireStatusClass::CallerFault,
        WireStatusClass::FarEndFault,
        WireStatusClass::Other,
    ] {
        let _: bool = match s {
            WireStatusClass::Success
            | WireStatusClass::CallerFault
            | WireStatusClass::FarEndFault
            | WireStatusClass::Other => true,
        };
    }
    for a in [StatusAt::FirstFrame, StatusAt::Terminal] {
        let _: bool = match a {
            StatusAt::FirstFrame | StatusAt::Terminal => true,
        };
    }

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
    for &one in status_ns::RESERVED {
        let status = WireStatus::new(one, 503);
        assert_eq!(status.in_namespace(one), Some(503), "{one}");
        for &other in status_ns::RESERVED.iter().filter(|other| **other != one) {
            assert_eq!(status.in_namespace(other), None, "{one} read as {other}");

            assert_ne!(WireStatus::new(one, 5), WireStatus::new(other, 5));
            assert_eq!(WireStatus::new(one, 5).in_namespace(other), None);
        }
    }
}
