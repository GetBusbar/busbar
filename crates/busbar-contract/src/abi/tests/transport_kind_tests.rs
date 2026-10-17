// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind's table, contracts and vocabulary hold together.

use std::mem::size_of;

use super::*;
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
fn framer_ops_never_pend_and_run_on_the_request_path() {
    for c in &CONTRACTS[slot::LOCATE as usize - LIFECYCLE_SLOTS as usize..] {
        assert!(!c.may_pend, "framer op {} may not pend", c.slot);
        assert!(c.request_path, "framer op {} is request-path", c.slot);
    }
}

#[test]
fn every_in_and_out_leads_with_its_head_and_fits_its_contract() {
    for c in &CONTRACTS {
        assert!(c.max_in >= size_of::<crate::abi::mechanism::call::InHead>());
        assert!(c.max_out >= size_of::<crate::abi::mechanism::call::OutHead>());
    }
}

#[test]
fn the_cancel_dispositions_are_distinct_and_nonzero() {
    let d = [CANCEL_NOTHING_MOVED, CANCEL_PARTIAL, CANCEL_COMPLETED];
    for (i, a) in d.iter().enumerate() {
        assert_ne!(*a, 0, "0 is an unwritten disposition");
        for b in &d[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn the_roles_are_distinct() {
    assert_ne!(ROLE_CARRIER, ROLE_FRAMER);
    assert_ne!(ROLE_CARRIER, 0);
    assert_ne!(ROLE_FRAMER, 0);
}
