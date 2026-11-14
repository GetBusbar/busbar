// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::mechanism::call::Outcome;
use crate::abi::sdk::door::{blank_in, blank_out};

#[test]
fn primitive_slots_and_layout_match_the_canonical_store_contract() {
    assert_eq!(super::super::ABI_VERSION, 3);
    assert_eq!(ABI_VERSION, 3);
    assert_eq!(CODEC_VERSION, 1);
    assert_eq!(CODEC_VERSION, crate::persistence::CANDIDATE_VERSION);
    assert_eq!(
        LAYOUT_FINGERPRINT,
        crate::abi::mechanism::layout::fingerprint(LAYOUT_SHAPES)
    );
    assert_eq!(NAMES, ["read", "scan", "commit", "clock", "bootstrap"]);
    for (index, contract) in OPS.iter().enumerate() {
        assert_eq!(contract.slot, LIFECYCLE_SLOTS + index as u32);
        assert!(contract.may_pend);
    }
    assert_eq!(
        core::mem::size_of::<Ops>(),
        core::mem::size_of::<OpsHead>() + 5 * core::mem::size_of::<Option<Op>>()
    );
    assert_eq!(LAYOUT_FINGERPRINT, super::super::LAYOUT_FINGERPRINT);
    assert_eq!(core::mem::offset_of!(ReadIn, head), 0);
    assert_eq!(core::mem::offset_of!(ScanIn, head), 0);
    assert_eq!(core::mem::offset_of!(CommitIn, head), 0);
    assert_eq!(core::mem::offset_of!(ClockIn, head), 0);
    assert_eq!(core::mem::offset_of!(ReadOut, head), 0);
    assert_eq!(core::mem::offset_of!(ScanOut, head), 0);
    assert_eq!(core::mem::offset_of!(CommitOut, head), 0);
    assert_eq!(core::mem::offset_of!(ClockOut, head), 0);
    assert_eq!(core::mem::offset_of!(BootstrapIn, head), 0);
    assert_eq!(core::mem::offset_of!(BootstrapOut, head), 0);
}

#[test]
fn read_envelope_checks_coherent_count_and_time_failure() {
    let mut input = blank_in::<ReadIn>();
    input.addresses_len = 1;
    input.values.items_cap = 1;
    let mut out = blank_out::<ReadOut>();
    out.code = READ_VALUES;
    assert!(check::read(Outcome::Ready, &input, &out).is_err());
    out.items_written = 1;
    assert!(check::read(Outcome::Ready, &input, &out).is_ok());
    out.code = READ_TIME_GUARD_FAILED;
    assert!(check::read(Outcome::Ready, &input, &out).is_err());
    out.items_written = 0;
    assert!(check::read(Outcome::Ready, &input, &out).is_ok());
}

#[test]
fn commit_verdicts_and_slot_constants_are_the_store_transaction_values() {
    let input = blank_in::<CommitIn>();
    let mut out = blank_out::<CommitOut>();
    for code in COMMIT_APPLIED..=COMMIT_STALE {
        out.code = code;
        assert!(check::commit(Outcome::Ready, &input, &out).is_ok());
    }
    out.code = 0;
    assert!(check::commit(Outcome::Ready, &input, &out).is_err());
    assert_eq!((COMMIT_FENCED, COMMIT_STALE), (5, 6));
    assert_eq!(SLOT_SELF_FENCED, u32::MAX);
    assert_eq!(MAX_SLOTS, 65_536);
}
#[test]
fn scan_requires_explicit_continuation_and_stale_has_no_rows() {
    let input = blank_in::<ScanIn>();
    let mut out = blank_out::<ScanOut>();
    out.code = SCAN_PAGE;
    assert!(check::scan(Outcome::Ready, &input, &out).is_err());
    out.continuation = SCAN_EXHAUSTED;
    assert!(check::scan(Outcome::Ready, &input, &out).is_ok());
    out.code = SCAN_STALE;
    assert!(check::scan(Outcome::Ready, &input, &out).is_err());
    out.continuation = 0;
    assert!(check::scan(Outcome::Ready, &input, &out).is_ok());
}
