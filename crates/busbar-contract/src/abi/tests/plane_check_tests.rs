// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the plane answer validators: one per rule, each failing if its check is removed.

use std::mem::zeroed;

use super::*;
use crate::abi::mechanism::call::Outcome::{Failed, Ready};
use crate::abi::plane::{
    ArriveOut, OnPieceOut, OutField, PlaneSnapshot, PlaneTail, RecordWrite, RefusalOut, Section,
    ServeOut, Span, UnitCount, CANCEL_ABORTED, INGRESS_REQUEST_RESPONSE, RECORD_PUT,
    SECTION_DECLARING, SECTION_REQUIRED, SPAN_ABSENT,
};

fn z<T>() -> T {
    // SAFETY: every answer shape is plain C data (integers, raw pointers); all-zero is a valid
    // value of each.
    unsafe { zeroed() }
}

fn bounds() -> Bounds {
    Bounds {
        op_classes: 1,
        dialects: 1,
        billable_classes: 2,
        record_kinds: 1,
    }
}

fn caps() -> Caps {
    Caps {
        reply: 16,
        units: 4,
        records: 4,
        fields: 4,
        arena: 16,
    }
}

fn sp(offset: u32, len: u32) -> Span {
    Span { offset, len }
}

#[test]
fn a_needed_count_above_its_hard_max_is_fault() {
    let mut o: ArriveOut = z();
    o.units_len = MAX_UNITS as u32 + 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Err(Fault::OverMax)
    );
    o.units_len = 5;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Ok(()),
        "a re-call"
    );
}

#[test]
fn failed_with_a_count_that_fits_is_fault() {
    let mut o: ArriveOut = z();
    o.units_len = 1;
    assert_eq!(
        check_arrive(Failed, &o, &[z()], 4, &bounds()),
        Err(Fault::WastedRecall)
    );
}

#[test]
fn an_arrival_index_past_its_list_or_unknown_need_is_fault() {
    let mut o: ArriveOut = z();
    o.op_class = 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Err(Fault::IndexOutOfRange)
    );
    let mut o: ArriveOut = z();
    o.dialect = 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Err(Fault::IndexOutOfRange)
    );
    let mut o: ArriveOut = z();
    o.principal_need = 3;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Err(Fault::UnknownCode)
    );
}

#[test]
fn a_unit_naming_no_billable_class_or_unknown_source_is_fault() {
    let mut o: ArriveOut = z();
    o.units_len = 1;
    let mut u: UnitCount = z();
    u.class = 2;
    assert_eq!(
        check_arrive(Ready, &o, &[u], 4, &bounds()),
        Err(Fault::IndexOutOfRange)
    );
    u.class = 1;
    u.source = 2;
    assert_eq!(
        check_arrive(Ready, &o, &[u], 4, &bounds()),
        Err(Fault::UnknownCode)
    );
}

#[test]
fn a_streamed_reply_never_exceeds_its_buffer() {
    let mut o: OnPieceOut = z();
    o.emitted = 17;
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[], &[]), &caps(), &bounds()),
        Err(Fault::OverCap)
    );
}

#[test]
fn on_piece_unknown_flags_or_more_are_fault() {
    let mut o: OnPieceOut = z();
    o.flags = 4;
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[], &[]), &caps(), &bounds()),
        Err(Fault::UnknownCode)
    );
    let mut o: OnPieceOut = z();
    o.more = 2;
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[], &[]), &caps(), &bounds()),
        Err(Fault::UnknownCode)
    );
}

#[test]
fn a_needed_arena_above_u32_max_is_fault() {
    let mut o: OnPieceOut = z();
    o.arena_len = u64::from(u32::MAX) + 1;
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[], &[]), &caps(), &bounds()),
        Err(Fault::OverMax)
    );
}

#[test]
fn an_absent_span_with_a_length_is_fault() {
    let mut o: OnPieceOut = z();
    o.fields_len = 1;
    let mut f: OutField = z();
    f.name = sp(SPAN_ABSENT, 1);
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[], &[f]), &caps(), &bounds()),
        Err(Fault::SpanNotAbsent)
    );
    f.name = sp(SPAN_ABSENT, 0);
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[], &[f]), &caps(), &bounds()),
        Ok(())
    );
}

#[test]
fn a_span_outside_the_arena_is_fault_with_checked_arithmetic() {
    let mut o: OnPieceOut = z();
    o.records_len = 1;
    o.arena_len = 4;
    let mut r: RecordWrite = z();
    r.op = RECORD_PUT;
    r.key = sp(2, 2);
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[r], &[]), &caps(), &bounds()),
        Ok(())
    );
    r.key = sp(3, 2);
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[r], &[]), &caps(), &bounds()),
        Err(Fault::SpanOutOfArena)
    );
    r.key = sp(u32::MAX - 1, u32::MAX);
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[r], &[]), &caps(), &bounds()),
        Err(Fault::SpanOutOfArena)
    );
}

#[test]
fn a_record_write_with_an_unknown_kind_or_op_is_fault() {
    let mut o: OnPieceOut = z();
    o.records_len = 1;
    let mut r: RecordWrite = z();
    r.op = 3;
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[r], &[]), &caps(), &bounds()),
        Err(Fault::UnknownCode)
    );
    r.op = RECORD_PUT;
    r.kind = 1;
    assert_eq!(
        check_on_piece(Ready, &o, (&[], &[r], &[]), &caps(), &bounds()),
        Err(Fault::IndexOutOfRange)
    );
}

#[test]
fn a_refusal_marker_is_known_and_its_reply_is_judged() {
    let mut o: RefusalOut = z();
    o.marker = 2;
    assert_eq!(
        check_refusal(Ready, &o, &[], &caps()),
        Err(Fault::UnknownCode)
    );
    let mut o: RefusalOut = z();
    o.emitted = 4;
    assert_eq!(
        check_refusal(Failed, &o, &[], &caps()),
        Err(Fault::WastedRecall)
    );
    o.emitted = 17;
    assert_eq!(check_refusal(Ready, &o, &[], &caps()), Ok(()), "a re-call");
}

#[test]
fn a_serve_reply_field_outside_the_arena_is_fault() {
    let mut o: ServeOut = z();
    o.fields_len = 1;
    o.arena_len = 1;
    let mut f: OutField = z();
    f.value = sp(0, 2);
    assert_eq!(
        check_serve(Ready, &o, &[f], &caps()),
        Err(Fault::SpanOutOfArena)
    );
}

#[test]
fn an_unwritten_or_unknown_cancel_disposition_is_fault() {
    assert_eq!(check_cancel(0), Err(Fault::UnknownCode));
    assert_eq!(check_cancel(4), Err(Fault::UnknownCode));
    assert_eq!(check_cancel(CANCEL_ABORTED), Ok(()));
}

fn snapshot() -> PlaneSnapshot {
    let mut s: PlaneSnapshot = z();
    s.size = std::mem::size_of::<PlaneSnapshot>() as u32;
    s.generation = 7;
    s
}

#[test]
fn a_snapshot_for_another_generation_or_size_is_fault() {
    assert_eq!(check_snapshot(&snapshot(), 7), Ok(()));
    assert_eq!(check_snapshot(&snapshot(), 8), Err(Fault::WrongSnapshot));
    let mut s = snapshot();
    s.size = 8;
    assert_eq!(check_snapshot(&s, 7), Err(Fault::WrongSnapshot));
}

#[test]
fn a_snapshot_list_counted_with_a_null_pointer_or_too_long_is_fault() {
    let mut s = snapshot();
    s.claims_len = 1;
    assert_eq!(check_snapshot(&s, 7), Err(Fault::NullWithCount));
    let mut s = snapshot();
    s.openapi.len = 1;
    assert_eq!(check_snapshot(&s, 7), Err(Fault::NullWithCount));
    let mut s = snapshot();
    s.admin_routes_len = MAX_ROUTES as usize + 1;
    assert_eq!(check_snapshot(&s, 7), Err(Fault::OverMax));
}

fn tail() -> PlaneTail {
    let mut t: PlaneTail = z();
    t.ingress = INGRESS_REQUEST_RESPONSE;
    t
}

#[test]
fn a_tail_with_unknown_bits_or_no_ingress_is_fault() {
    assert_eq!(check_tail(&tail()), Ok(()));
    let mut t = tail();
    t.ingress = 0;
    assert_eq!(check_tail(&t), Err(Fault::UnknownCode));
    let mut t = tail();
    t.flags = 2;
    assert_eq!(check_tail(&t), Err(Fault::UnknownCode));
    let mut t = tail();
    t.dispatch_shape = 2;
    assert_eq!(check_tail(&t), Err(Fault::UnknownCode));
}

#[test]
fn a_tail_list_counted_with_a_null_pointer_is_fault() {
    let mut t = tail();
    t.needs_len = 1;
    assert_eq!(check_tail(&t), Err(Fault::NullWithCount));
}

fn section(flags: u32) -> Section {
    let mut s: Section = z();
    s.flags = flags;
    s
}

#[test]
fn exactly_one_section_is_the_declaring_one() {
    assert_eq!(
        check_sections(&[section(SECTION_DECLARING), section(SECTION_REQUIRED)]),
        Ok(())
    );
    assert_eq!(
        check_sections(&[section(SECTION_REQUIRED)]),
        Err(Fault::NotExactlyOne)
    );
    assert_eq!(
        check_sections(&[section(SECTION_DECLARING), section(SECTION_DECLARING)]),
        Err(Fault::NotExactlyOne)
    );
    assert_eq!(
        check_sections(&[section(SECTION_DECLARING | 8)]),
        Err(Fault::UnknownCode)
    );
}
