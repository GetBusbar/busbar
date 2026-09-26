// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// Every byte decodes, and only the fourteen stated ones decode to themselves: a transport that
/// writes a byte past the vocabulary is read as a fault, never as an enum it cannot be.
#[test]
fn every_outcome_byte_decodes_and_the_unknown_ones_are_faults() {
    for b in 0..=u8::MAX {
        let decoded = RawWireOutcome(b).outcome();
        if b <= 13 {
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

/// The decl leads with the frozen preamble, then its own sized header — the order the host reads
/// before it trusts a single slot.
#[test]
fn the_decl_leads_with_the_airlock_then_its_size() {
    assert_eq!(core::mem::offset_of!(TransportDecl, abi), 0);
    assert_eq!(
        core::mem::offset_of!(TransportDecl, size),
        core::mem::size_of::<AbiPreamble>()
    );
    const { assert!(TRANSPORT_DECL_MINOR <= crate::ABI_MINOR) };
}

/// Minor 28: the poll shape rides the decl's tail — every appended slot sits after the minor-26
/// `session` fact, so no earlier offset moved — and the host's waker handle leads with its own sized
/// header.
#[test]
fn the_poll_slots_are_appended_after_the_minor_26_row() {
    let tail = core::mem::offset_of!(TransportDecl, _reserved) + core::mem::size_of::<u32>();
    assert_eq!(core::mem::offset_of!(TransportDecl, init), tail);
    for (name, at) in [
        ("connect", core::mem::offset_of!(TransportDecl, connect)),
        (
            "poll_accept",
            core::mem::offset_of!(TransportDecl, poll_accept),
        ),
        ("poll_read", core::mem::offset_of!(TransportDecl, poll_read)),
        (
            "poll_write",
            core::mem::offset_of!(TransportDecl, poll_write),
        ),
        (
            "poll_flush",
            core::mem::offset_of!(TransportDecl, poll_flush),
        ),
        (
            "poll_close",
            core::mem::offset_of!(TransportDecl, poll_close),
        ),
    ] {
        assert!(at > tail, "{name} is appended");
    }
    assert_eq!(
        core::mem::offset_of!(TransportDecl, poll_close) + core::mem::size_of::<usize>(),
        core::mem::size_of::<TransportDecl>()
    );
    assert_eq!(core::mem::offset_of!(WireWaker, size), 0);
    assert_eq!(RawWireOutcome::of(WireOutcome::Pending), RawWireOutcome(13));
    assert_eq!(NO_WAKER, 0);
    const { assert!(TRANSPORT_DECL_MINOR == 28) };
}
