// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the shared answer-validator helpers: one per rule, each failing if its check is
//! removed.

use super::*;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready, Refused};

#[test]
fn a_ready_answer_writes_within_its_capacity() {
    assert_eq!(result(Ready, 4, 0, 4, 8, "t"), Ok(Filled::Written));
    assert_eq!(
        result(Ready, 5, 0, 4, 8, "t"),
        Err(fault(Rule::OverCap, "t"))
    );
}

#[test]
fn a_needed_size_on_any_outcome_but_failed_is_fault() {
    for o in [Ready, Pending, Refused] {
        assert_eq!(
            result(o, 0, 9, 4, 16, "t"),
            Err(fault(Rule::NeededNotFailed, "t"))
        );
    }
}

#[test]
fn a_short_answer_is_failed_over_cap_and_wrote_nothing() {
    assert_eq!(result(Failed, 0, 9, 4, 16, "t"), Ok(Filled::Short));
    assert_eq!(
        result(Failed, 0, 4, 4, 16, "t"),
        Err(fault(Rule::WastedRecall, "t"))
    );
    assert_eq!(
        result(Failed, 1, 9, 4, 16, "t"),
        Err(fault(Rule::WrittenOnShort, "t"))
    );
    assert_eq!(
        result(Failed, 0, 17, 4, 16, "t"),
        Err(fault(Rule::OverMax, "t"))
    );
}

#[test]
fn a_no_short_path_length_over_cap_is_fault() {
    assert_eq!(within(5, 4, "t"), Err(fault(Rule::OverCap, "t")));
    assert_eq!(within(4, 4, "t"), Ok(()));
}

#[test]
fn a_counted_null_list_is_fault() {
    assert_eq!(
        listed(std::ptr::null::<u8>(), 1, "t"),
        Err(fault(Rule::NullWithCount, "t"))
    );
    assert_eq!(listed(std::ptr::null::<u8>(), 0, "t"), Ok(()));
}

#[test]
fn indices_codes_and_bits_are_bounded() {
    assert_eq!(index(2, 2, "t"), Err(fault(Rule::IndexOutOfRange, "t")));
    assert_eq!(code(0, 1, 3, "t"), Err(fault(Rule::UnknownCode, "t")));
    assert_eq!(code(4, 1, 3, "t"), Err(fault(Rule::UnknownCode, "t")));
    assert_eq!(bits(4, 3, "t"), Err(fault(Rule::UnknownCode, "t")));
    assert_eq!(bits(3, 3, "t"), Ok(()));
}

#[test]
fn spans_are_absent_or_inside_with_checked_arithmetic() {
    assert_eq!(span(SPAN_ABSENT, 0, 4, "t"), Ok(()));
    assert_eq!(
        span(SPAN_ABSENT, 1, 4, "t"),
        Err(fault(Rule::SpanNotAbsent, "t"))
    );
    assert_eq!(span(2, 2, 4, "t"), Ok(()));
    assert_eq!(span(3, 2, 4, "t"), Err(fault(Rule::SpanOutOfBounds, "t")));
    assert_eq!(
        range(u64::MAX, 2, 4, "t"),
        Err(fault(Rule::SpanOutOfBounds, "t"))
    );
}

#[test]
fn a_weight_is_finite_and_not_negative() {
    assert_eq!(weight(f64::NAN, "t"), Err(fault(Rule::NotFinite, "t")));
    assert_eq!(weight(f64::INFINITY, "t"), Err(fault(Rule::NotFinite, "t")));
    assert_eq!(weight(-0.5, "t"), Err(fault(Rule::NotFinite, "t")));
    assert_eq!(weight(0.5, "t"), Ok(()));
}

#[test]
fn first_never_reads_past_the_buffer() {
    assert_eq!(first(&[1u8, 2], 3, "t"), Err(fault(Rule::OverCap, "t")));
    assert_eq!(first(&[1u8, 2], 2, "t"), Ok(&[1u8, 2][..]));
}

fn dim(written: u64, needed: u64, cap: u64, field: &'static str) -> Dim {
    Dim {
        written,
        needed,
        cap,
        max: 100,
        field,
    }
}

#[test]
fn a_multi_dimension_short_answer_needs_one_dimension_over_its_cap() {
    let one_short = [dim(0, 9, 4, "t.a"), dim(0, 3, 4, "t.b")];
    assert_eq!(
        results(Failed, "t", &one_short),
        Ok(Filled::Short),
        "a fitting dimension reports its size"
    );
    let both_fit = [dim(0, 4, 4, "t.a"), dim(0, 3, 4, "t.b")];
    assert_eq!(
        results(Failed, "t", &both_fit),
        Err(fault(Rule::WastedRecall, "t"))
    );
}

#[test]
fn a_multi_dimension_answer_keeps_every_other_rule() {
    assert_eq!(
        results(Ready, "t", &[dim(0, 0, 4, "t.a"), dim(0, 9, 4, "t.b")]),
        Err(fault(Rule::NeededNotFailed, "t.b"))
    );
    assert_eq!(
        results(Failed, "t", &[dim(0, 101, 4, "t.a")]),
        Err(fault(Rule::OverMax, "t.a"))
    );
    assert_eq!(
        results(Failed, "t", &[dim(1, 9, 4, "t.a"), dim(0, 0, 4, "t.b")]),
        Err(fault(Rule::WrittenOnShort, "t"))
    );
    assert_eq!(
        results(Ready, "t", &[dim(4, 0, 4, "t.a"), dim(5, 0, 4, "t.b")]),
        Err(fault(Rule::OverCap, "t.b"))
    );
    assert_eq!(
        results(Ready, "t", &[dim(4, 0, 4, "t.a"), dim(4, 0, 4, "t.b")]),
        Ok(Filled::Written)
    );
}

#[test]
fn a_string_counted_with_a_null_pointer_is_fault() {
    use crate::abi::mechanism::call::AbiStr;
    let bad = AbiStr {
        ptr: std::ptr::null(),
        len: 1,
    };
    let empty = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    assert_eq!(text(empty, "t"), Ok(()));
    assert_eq!(text(bad, "t"), Err(fault(Rule::NullWithCount, "t")));
    assert_eq!(
        texts(&[empty, bad], "t"),
        Err(fault(Rule::NullWithCount, "t"))
    );
}
