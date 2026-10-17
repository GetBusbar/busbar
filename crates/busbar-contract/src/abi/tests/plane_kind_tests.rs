// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane kind's table, contracts and cancel billing rule hold together.

use std::mem::size_of;

use super::*;
use crate::abi::mechanism::door::{SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED};
use crate::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

#[test]
fn contracts_run_in_slot_order_contiguous_after_the_lifecycle() {
    for (k, c) in CONTRACTS.iter().enumerate() {
        assert_eq!(c.slot, LIFECYCLE_SLOTS + k as u32, "contract {k}");
    }
    assert_eq!(SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
    assert_eq!(
        size_of::<Ops>(),
        size_of::<OpsHead>() + 8 * KIND_SLOTS as usize
    );
}

#[test]
fn only_on_piece_serve_and_the_boot_ops_may_pend() {
    let pend: Vec<u32> = CONTRACTS
        .iter()
        .filter(|c| c.may_pend)
        .map(|c| c.slot)
        .collect();
    assert_eq!(
        pend,
        [slot::ON_PIECE, slot::SERVE, slot::HYDRATE, slot::START]
    );
}

/// The four 1.5.5 cancel billing rules: a translate-abort and a failure never bill, a streamed
/// partial bills the reported units, a non-streamed partial bills nothing.
#[test]
fn cancel_billing_follows_the_four_rules() {
    assert!(!cancel_bills_reported_units(CANCEL_ABORTED, true));
    assert!(!cancel_bills_reported_units(CANCEL_ABORTED, false));
    assert!(!cancel_bills_reported_units(CANCEL_FAILED, true));
    assert!(!cancel_bills_reported_units(CANCEL_FAILED, false));
    assert!(cancel_bills_reported_units(CANCEL_OK_PARTIAL, true));
    assert!(!cancel_bills_reported_units(CANCEL_OK_PARTIAL, false));
    assert!(
        !cancel_bills_reported_units(0, true),
        "unwritten bills nothing"
    );
    assert_ne!(UNITS_REPORTED, UNITS_ESTIMATED);
}

#[test]
fn the_cancel_dispositions_are_distinct_and_nonzero() {
    let d = [CANCEL_OK_PARTIAL, CANCEL_FAILED, CANCEL_ABORTED];
    for (i, a) in d.iter().enumerate() {
        assert_ne!(*a, 0, "0 is an unwritten disposition");
        for b in &d[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn the_section_and_ingress_flags_are_single_distinct_bits() {
    let s = [SECTION_DECLARING, SECTION_REQUIRED, SECTION_CONSUMED];
    let i = [
        INGRESS_REQUEST_RESPONSE,
        INGRESS_RESPONSE_STREAM,
        INGRESS_DUPLEX_SESSION,
        INGRESS_SUBSCRIPTION,
        INGRESS_ACCEPT_LOOP,
    ];
    for set in [&s[..], &i[..]] {
        let mut seen = 0u32;
        for b in set {
            assert_eq!(b.count_ones(), 1);
            assert_eq!(seen & b, 0);
            seen |= b;
        }
    }
}
