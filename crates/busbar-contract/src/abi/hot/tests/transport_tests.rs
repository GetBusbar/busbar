// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::transport::wire::{CloseReason, Framing, StatusAt, Unit0Trigger, WireStatusClass};

/// Every byte decodes, and only the eighteen stated ones decode to themselves: a transport that
/// writes a byte past the vocabulary is read as a fault, never as an enum it cannot be.
#[test]
fn every_outcome_byte_decodes_and_the_unknown_ones_are_faults() {
    for b in 0..=u8::MAX {
        let decoded = RawWireOutcome(b).outcome();
        if b <= 17 {
            assert_eq!(decoded as u8, b, "byte {b} decodes to itself");
            assert_eq!(RawWireOutcome::of(decoded), RawWireOutcome(b));
        } else {
            assert_eq!(
                decoded,
                WireOutcome::Fault,
                "byte {b} is past the vocabulary"
            );
            assert_eq!(WireOutcome::try_from(b), Err(b));
        }
    }
}

/// A transport failure and a rendering refusal each cross and come back as themselves.
#[test]
fn failures_and_refusals_cross_their_outcome_and_come_back() {
    use crate::transport::wire::{Encode, TransportError as E};
    for e in [
        E::Refused,
        E::Timeout,
        E::Reset,
        E::Closed,
        E::HandshakeFailed,
        E::KeyUnavailable,
        E::AddressRefused,
        E::Backpressure,
        E::Framing,
        E::HandoffMismatch,
    ] {
        assert_eq!(WireOutcome::of_error(e).error(), e);
    }
    for e in [
        Encode::Unrepresentable,
        Encode::ScratchExhausted,
        Encode::SecretPlaceholder,
        Encode::Poisoned,
    ] {
        assert_eq!(WireOutcome::of_encode(e).encode_error(), e);
    }
    // The seam's own answers read as a closed operation, never as a failure they are not.
    assert_eq!(WireOutcome::Fault.error(), E::Closed);
    assert_eq!(WireOutcome::Ok.encode_error(), Encode::Poisoned);
}

/// Every closed vocabulary crosses as a byte and comes back as itself; an unknown byte is refused.
#[test]
fn every_closed_vocabulary_crosses_as_a_byte_and_refuses_an_unknown_one() {
    for r in [
        CloseReason::Normal,
        CloseReason::PeerClosed,
        CloseReason::Drain,
        CloseReason::Poisoned,
        CloseReason::Revoked,
        CloseReason::Timeout,
        CloseReason::TransportFailed,
        CloseReason::CapacityExhausted,
    ] {
        assert_eq!(code::close_reason_of(code::close_reason(r)), Some(r));
    }
    assert_eq!(code::close_reason_of(8), None);
    for s in [
        None,
        Some(WireStatusClass::Success),
        Some(WireStatusClass::CallerFault),
        Some(WireStatusClass::FarEndFault),
        Some(WireStatusClass::Other),
    ] {
        assert_eq!(code::status_class_of(code::status_class(s)), Ok(s));
    }
    assert_eq!(code::status_class_of(5), Err(5));
    for s in [None, Some(StatusAt::FirstFrame), Some(StatusAt::Terminal)] {
        assert_eq!(code::status_at_of(code::status_at(s)), Ok(s));
    }
    assert_eq!(code::status_at_of(3), Err(3));
    for f in [Framing::Stream, Framing::Datagram] {
        assert_eq!(code::framing_of(code::framing(f)), Ok(f));
    }
    assert_eq!(code::framing_of(2), Err(2));
    for t in [
        None,
        Some(Unit0Trigger::FirstBytes),
        Some(Unit0Trigger::FirstLine),
        Some(Unit0Trigger::FirstMessage),
        Some(Unit0Trigger::FirstDatagram),
        Some(Unit0Trigger::Upgrade),
        Some(Unit0Trigger::Handshake),
    ] {
        assert_eq!(code::unit0_trigger_of(code::unit0_trigger(t)), Ok(t));
    }
    assert_eq!(code::unit0_trigger_of(7), Err(7));
    for f in code::SELECTOR_FORMS {
        assert_eq!(code::selector_form_of(code::selector_form(f)), Some(f));
    }
    assert_eq!(code::selector_form_of(0), None);
    assert_eq!(code::selector_form_of(14), None);
    for s in [crate::transport::Side::Accept, crate::transport::Side::Dial] {
        assert_eq!(code::side_of(code::side(s)), Some(s));
    }
    assert_eq!(code::side_of(2), None);
}

/// The selector-form table names every form once: a form added to the vocabulary and not to the
/// table would cross as `0` and be refused, and a duplicate would read back as the wrong form.
#[test]
fn every_selector_form_has_one_code() {
    let mut codes: Vec<u8> = code::SELECTOR_FORMS
        .iter()
        .map(|f| code::selector_form(*f))
        .collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes, (1..=13).collect::<Vec<u8>>());
}

/// The decl leads with the frozen preamble, then its own sized header and generation — the three
/// fields every decl generation led with, which is how the host refuses the retired one.
#[test]
fn the_decl_leads_with_the_airlock_then_its_size_and_generation() {
    assert_eq!(core::mem::offset_of!(TransportDecl, abi), 0);
    assert_eq!(
        core::mem::offset_of!(TransportDecl, size),
        core::mem::size_of::<AbiPreamble>()
    );
    assert_eq!(
        core::mem::offset_of!(TransportDecl, version),
        core::mem::size_of::<AbiPreamble>() + 4
    );
    const { assert!(TRANSPORT_DECL_MINOR <= crate::abi::ABI_MINOR) };
    const { assert!(TRANSPORT_DECL_MAJOR == 2) };
    // The retired decl stated its airlock minor (24..=30) here: never this generation.
    const { assert!(TRANSPORT_DECL_MAJOR < 24) };
}

/// Every sized struct that crosses leads with its size, so a receiver reads nothing a shorter
/// sender did not write.
#[test]
fn every_crossing_struct_leads_with_its_size() {
    assert_eq!(core::mem::offset_of!(WireSettings, size), 0);
    assert_eq!(core::mem::offset_of!(WireWaker, size), 0);
    assert_eq!(core::mem::offset_of!(WireDest, size), 0);
    assert_eq!(core::mem::offset_of!(WireConnFacts, size), 0);
    assert_eq!(core::mem::offset_of!(WireFramed, size), 0);
    assert_eq!(core::mem::offset_of!(CarrierSlots, size), 0);
    assert_eq!(core::mem::offset_of!(FramerSlots, size), 0);
}

/// The settings a linked transport is built from cross and come back field for field (distinct
/// values, so a swapped pair cannot pass).
#[test]
fn the_settings_cross_field_for_field() {
    let s = crate::transport::TransportSettings {
        pool_max_idle_per_host: 3,
        pool_idle_timeout_secs: 5,
        upstream_http1_only: true,
        upstream_h2_prior_knowledge: false,
        request_body_max_bytes: 7,
        response_body_max_bytes: 11,
        request_timeout_secs: 13,
    };
    let w = WireSettings::of(&s);
    assert_eq!(w.size as usize, core::mem::size_of::<WireSettings>());
    let back = w.settings();
    assert_eq!(
        (
            back.pool_max_idle_per_host,
            back.pool_idle_timeout_secs,
            back.upstream_http1_only,
            back.upstream_h2_prior_knowledge,
            back.request_body_max_bytes,
            back.response_body_max_bytes,
            back.request_timeout_secs,
        ),
        (3, 5, true, false, 7, 11, 13)
    );
}
