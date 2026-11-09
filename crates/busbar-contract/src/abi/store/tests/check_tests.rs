// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former business-table validators are now the mandatory primitive envelopes.
//! Nested allocation containment/format checks live in the SDK response tests;
//! lease/pending/cancel custody remains in the native door and loader tests.

use super::*;
use crate::abi::mechanism::call::Outcome;
use crate::abi::sdk::door::{blank_in, blank_out};

fn read_case() -> (ReadIn, ReadOut) {
    let mut input = blank_in::<ReadIn>();
    input.addresses_len = 1;
    input.values.items_cap = 1;
    input.values.bytes.cap = 512;
    let mut out = blank_out::<ReadOut>();
    out.code = READ_VALUES;
    out.items_written = 1;
    (input, out)
}
fn scan_case() -> (ScanIn, ScanOut) {
    let mut input = blank_in::<ScanIn>();
    input.rows.items_cap = 2;
    input.rows.bytes.cap = 512;
    input.max_items = 2;
    let mut out = blank_out::<ScanOut>();
    out.code = SCAN_PAGE;
    out.continuation = SCAN_EXHAUSTED;
    (input, out)
}
#[test]
fn coherent_read_well_formed_and_time_failure_have_distinct_payload_rules() {
    let (input, mut out) = read_case();
    out.bytes_written = 12;
    assert!(check::read(Outcome::Ready, &input, &out).is_ok());
    out.code = READ_TIME_GUARD_FAILED;
    assert!(check::read(Outcome::Ready, &input, &out).is_err());
    out.items_written = 0;
    assert!(check::read(Outcome::Ready, &input, &out).is_err());
    out.bytes_written = 0;
    assert!(check::read(Outcome::Ready, &input, &out).is_ok());
}
#[test]
fn read_status_reserved_counts_and_capacities_are_checked() {
    let (input, out) = read_case();
    for change in [0, 1, 2, 3, 4] {
        let mut bad = out;
        match change {
            0 => bad.code = u32::MAX,
            1 => bad._reserved = 1,
            2 => bad.items_written = 0,
            3 => bad.items_written = 2,
            _ => bad.bytes_written = 513,
        }
        assert!(check::read(Outcome::Ready, &input, &bad).is_err());
    }
}
#[test]
fn needed_sizes_are_only_legal_for_a_failed_short_response() {
    let (input, mut out) = read_case();
    out.items_written = 0;
    out.needed_bytes = 513;
    assert!(check::read(Outcome::Failed, &input, &out).is_ok());
    for outcome in [Outcome::Ready, Outcome::Pending, Outcome::Refused] {
        assert!(check::read(outcome, &input, &out).is_err());
    }
    out.needed_bytes = 512;
    assert!(check::read(Outcome::Failed, &input, &out).is_err());
}
#[test]
fn failed_and_refused_calls_cannot_publish_written_payloads() {
    let (input, out) = read_case();
    for outcome in [Outcome::Failed, Outcome::Refused, Outcome::Pending] {
        assert!(check::read(outcome, &input, &out).is_err());
        let mut empty = out;
        empty.items_written = 0;
        assert!(check::read(outcome, &input, &empty).is_ok());
    }
}
#[test]
fn scan_dimensions_continuation_limit_and_exhausted_cursor_are_checked() {
    let (input, out) = scan_case();
    assert!(check::scan(Outcome::Ready, &input, &out).is_ok());
    for change in 0..5 {
        let mut bad = out;
        match change {
            0 => bad.items_written = 3,
            1 => bad.bytes_written = 513,
            2 => bad.continuation = 0,
            3 => bad.code = 0,
            _ => bad.next.len = 1,
        }
        assert!(check::scan(Outcome::Ready, &input, &bad).is_err());
    }
    let mut smaller = input;
    smaller.max_items = 1;
    let mut two = out;
    two.items_written = 2;
    assert!(check::scan(Outcome::Ready, &smaller, &two).is_err());
}
#[test]
fn stale_scan_carries_no_rows_bytes_or_continuation() {
    let (input, mut out) = scan_case();
    out.code = SCAN_STALE;
    out.continuation = 0;
    assert!(check::scan(Outcome::Ready, &input, &out).is_ok());
    for change in 0..4 {
        let mut bad = out;
        match change {
            0 => bad.items_written = 1,
            1 => bad.bytes_written = 1,
            2 => bad.continuation = SCAN_CONTINUE,
            _ => bad.next.len = 1,
        }
        assert!(check::scan(Outcome::Ready, &input, &bad).is_err());
    }
}
#[test]
fn scan_short_in_one_dimension_is_legal_but_a_fitting_short_is_not() {
    let (input, mut out) = scan_case();
    out.needed_items = 3;
    out.needed_bytes = 100;
    assert!(check::scan(Outcome::Failed, &input, &out).is_ok());
    out.needed_items = 2;
    assert!(check::scan(Outcome::Failed, &input, &out).is_err());
    out.needed_bytes = 513;
    assert!(check::scan(Outcome::Failed, &input, &out).is_ok());
}
#[test]
fn only_an_applied_commit_can_publish_original_result_bytes() {
    let mut input = blank_in::<CommitIn>();
    input.result.cap = 512;
    let mut out = blank_out::<CommitOut>();
    out.code = COMMIT_APPLIED;
    out.written = 1;
    assert!(check::commit(Outcome::Ready, &input, &out).is_ok());
    for code in COMMIT_CONDITION_CONFLICT..=COMMIT_EXPIRED_UNKNOWN {
        out.code = code;
        assert!(check::commit(Outcome::Ready, &input, &out).is_err());
        out.written = 0;
        assert!(check::commit(Outcome::Ready, &input, &out).is_ok());
        out.written = 1;
    }
}
#[test]
fn commit_reserved_capacity_and_failed_short_rules_are_checked() {
    let mut input = blank_in::<CommitIn>();
    input.result.cap = 4;
    let mut out = blank_out::<CommitOut>();
    out.code = COMMIT_APPLIED;
    out.written = 5;
    assert!(check::commit(Outcome::Ready, &input, &out).is_err());
    out.written = 0;
    out._reserved = 1;
    assert!(check::commit(Outcome::Ready, &input, &out).is_err());
    out._reserved = 0;
    out.needed = 5;
    assert!(check::commit(Outcome::Failed, &input, &out).is_ok());
    assert!(check::commit(Outcome::Refused, &input, &out).is_err());
    out.needed = 4;
    assert!(check::commit(Outcome::Failed, &input, &out).is_err());
    out.needed = 0;
    out.written = 1;
    for outcome in [Outcome::Failed, Outcome::Refused, Outcome::Pending] {
        assert!(check::commit(outcome, &input, &out).is_err());
    }
}

#[test]
fn bootstrap_retains_instance_across_pending_short_and_error_responses() {
    let input = blank_in::<BootstrapIn>();
    let mut out = blank_out::<BootstrapOut>();
    out.instance = core::ptr::dangling_mut::<u8>().cast();
    for outcome in [
        Outcome::Ready,
        Outcome::Pending,
        Outcome::Failed,
        Outcome::Refused,
    ] {
        assert!(check::bootstrap(outcome, &input, &out).is_ok());
    }
    out.needed = 1;
    assert!(check::bootstrap(Outcome::Failed, &input, &out).is_ok());
    for outcome in [Outcome::Ready, Outcome::Pending, Outcome::Refused] {
        assert!(check::bootstrap(outcome, &input, &out).is_err());
    }
}

#[test]
fn bootstrap_response_dimensions_follow_commit_short_buffer_rules() {
    let mut input = blank_in::<BootstrapIn>();
    input.result.cap = 16;
    let mut out = blank_out::<BootstrapOut>();
    out.written = 16;
    assert!(check::bootstrap(Outcome::Ready, &input, &out).is_ok());
    out.written = 17;
    assert!(check::bootstrap(Outcome::Ready, &input, &out).is_err());
    out.written = 1;
    for outcome in [Outcome::Pending, Outcome::Failed, Outcome::Refused] {
        assert!(check::bootstrap(outcome, &input, &out).is_err());
    }
    out.written = 0;
    out.needed = 16;
    assert!(check::bootstrap(Outcome::Failed, &input, &out).is_err());
    out.needed = 17;
    assert!(check::bootstrap(Outcome::Failed, &input, &out).is_ok());
    out.written = 1;
    assert!(check::bootstrap(Outcome::Failed, &input, &out).is_err());
}
