// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// Every byte decodes, and only the thirteen stated ones decode to themselves: a transport that
/// writes a byte past the vocabulary is read as a fault, never as an enum it cannot be.
#[test]
fn every_outcome_byte_decodes_and_the_unknown_ones_are_faults() {
    for b in 0..=u8::MAX {
        let decoded = RawWireOutcome(b).outcome();
        if b <= 12 {
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
