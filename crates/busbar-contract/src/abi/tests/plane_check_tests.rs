// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the plane answer validators: one per rule and arm, each failing if its check is
//! removed.

use std::mem::zeroed;
use std::ptr::null;

use super::*;
use crate::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND};
use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready};
use crate::abi::mechanism::check::fault;
use crate::abi::plane::*;

fn z<T>() -> T {
    // SAFETY: every answer shape is plain C data (integers, raw pointers, floats); all-zero is a
    // valid value of each.
    unsafe { zeroed() }
}

fn f(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(fault(rule, field))
}

fn s(text: &'static str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
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

// ── arrive ──

#[test]
fn arrive_units_follow_m_sb() {
    let mut o: ArriveOut = z();
    o.units_needed = 5;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::NeededNotFailed, "arrive.units")
    );
    assert_eq!(
        check_arrive(Pending, &o, &[], 4, &bounds()),
        f(Rule::NeededNotFailed, "arrive.units")
    );
    assert_eq!(
        check_arrive(Failed, &o, &[], 4, &bounds()),
        Ok(()),
        "the short answer"
    );
    o.units_needed = 4;
    assert_eq!(
        check_arrive(Failed, &o, &[], 4, &bounds()),
        f(Rule::WastedRecall, "arrive.units")
    );
    o.units_needed = MAX_UNITS as u32 + 1;
    assert_eq!(
        check_arrive(Failed, &o, &[], 4, &bounds()),
        f(Rule::OverMax, "arrive.units")
    );
    let mut o: ArriveOut = z();
    o.units_written = 5;
    assert_eq!(
        check_arrive(Ready, &o, &[z(); 5], 4, &bounds()),
        f(Rule::OverCap, "arrive.units")
    );
}

#[test]
fn an_arrival_index_past_its_list_or_unknown_need_is_fault() {
    let mut o: ArriveOut = z();
    o.op_class = 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::IndexOutOfRange, "arrive.op_class")
    );
    let mut o: ArriveOut = z();
    o.dialect = 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::IndexOutOfRange, "arrive.dialect")
    );
    let mut o: ArriveOut = z();
    o.principal_need = 3;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::UnknownCode, "arrive.principal_need")
    );
}

#[test]
fn a_unit_naming_no_billable_class_or_unknown_source_is_fault() {
    let mut o: ArriveOut = z();
    o.units_written = 1;
    let mut u: UnitCount = z();
    u.class = 2;
    assert_eq!(
        check_arrive(Ready, &o, &[u], 4, &bounds()),
        f(Rule::IndexOutOfRange, "unit.class")
    );
    u.class = 1;
    u.source = 2;
    assert_eq!(
        check_arrive(Ready, &o, &[u], 4, &bounds()),
        f(Rule::UnknownCode, "unit.source")
    );
}

// ── on_piece ──

fn piece(o: &OnPieceOut, u: &[UnitCount], r: &[RecordWrite], fl: &[OutField]) -> Result<(), Fault> {
    check_on_piece(Ready, o, (u, r, fl), &caps(), &bounds())
}

#[test]
fn a_streamed_reply_never_exceeds_its_buffer() {
    let mut o: OnPieceOut = z();
    o.emitted = 17;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::OverCap, "on_piece.emitted")
    );
}

#[test]
fn on_piece_unknown_flags_or_more_are_fault() {
    let mut o: OnPieceOut = z();
    o.flags = 4;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::UnknownCode, "on_piece.flags")
    );
    let mut o: OnPieceOut = z();
    o.more = 2;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::UnknownCode, "on_piece.more")
    );
}

#[test]
fn more_needs_bytes_emitted_and_never_comes_with_done() {
    let mut o: OnPieceOut = z();
    o.more = 1;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.more_without_emitted")
    );
    o.emitted = 1;
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    o.flags = EMIT_DONE;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.more_with_done")
    );
}

#[test]
fn every_on_piece_buffer_follows_m_sb() {
    for (field, set) in [
        (
            "on_piece.units",
            (|o: &mut OnPieceOut| o.units_needed = 5) as fn(&mut OnPieceOut),
        ),
        ("on_piece.records", |o: &mut OnPieceOut| {
            o.records_needed = 5
        }),
        ("on_piece.fields", |o: &mut OnPieceOut| o.fields_needed = 5),
        ("on_piece.arena", |o: &mut OnPieceOut| o.arena_needed = 17),
    ] {
        let mut o: OnPieceOut = z();
        set(&mut o);
        assert_eq!(piece(&o, &[], &[], &[]), f(Rule::NeededNotFailed, field));
        assert_eq!(
            check_on_piece(Failed, &o, (&[], &[], &[]), &caps(), &bounds()),
            Ok(()),
            "{field}: the short answer"
        );
    }
    let mut o: OnPieceOut = z();
    o.arena_needed = u64::from(u32::MAX) + 1;
    assert_eq!(
        check_on_piece(Failed, &o, (&[], &[], &[]), &caps(), &bounds()),
        f(Rule::OverMax, "on_piece.arena")
    );
}

#[test]
fn a_short_on_piece_answer_that_emitted_is_fault() {
    let mut o: OnPieceOut = z();
    o.units_needed = 5;
    o.emitted = 1;
    assert_eq!(
        check_on_piece(Failed, &o, (&[], &[], &[]), &caps(), &bounds()),
        f(Rule::WrittenOnShort, "on_piece")
    );
}

#[test]
fn a_non_ready_on_piece_still_has_its_units_and_records_judged() {
    let mut o: OnPieceOut = z();
    o.units_written = 1;
    let mut u: UnitCount = z();
    u.class = 9;
    assert_eq!(
        check_on_piece(Failed, &o, (&[u], &[], &[]), &caps(), &bounds()),
        f(Rule::IndexOutOfRange, "unit.class")
    );
    let mut o: OnPieceOut = z();
    o.records_written = 1;
    let mut r: RecordWrite = z();
    r.op = 3;
    assert_eq!(
        check_on_piece(Pending, &o, (&[], &[r], &[]), &caps(), &bounds()),
        f(Rule::UnknownCode, "record.op")
    );
}

#[test]
fn an_absent_span_with_a_length_is_fault() {
    let mut o: OnPieceOut = z();
    o.fields_written = 1;
    let mut fl: OutField = z();
    fl.name = sp(SPAN_ABSENT, 1);
    assert_eq!(
        piece(&o, &[], &[], &[fl]),
        f(Rule::SpanNotAbsent, "field.name")
    );
    fl.name = sp(SPAN_ABSENT, 0);
    assert_eq!(piece(&o, &[], &[], &[fl]), Ok(()));
}

#[test]
fn a_span_outside_the_arena_is_fault_with_checked_arithmetic() {
    let mut o: OnPieceOut = z();
    o.records_written = 1;
    o.arena_written = 4;
    let mut r: RecordWrite = z();
    r.op = RECORD_PUT;
    r.key = sp(2, 2);
    assert_eq!(piece(&o, &[], &[r], &[]), Ok(()));
    r.key = sp(3, 2);
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::SpanOutOfBounds, "record.key")
    );
    r.key = sp(u32::MAX - 1, u32::MAX);
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::SpanOutOfBounds, "record.key")
    );
    r.key = sp(0, 0);
    r.value = sp(0, 5);
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::SpanOutOfBounds, "record.value")
    );
}

#[test]
fn a_record_write_with_an_unknown_kind_is_fault() {
    let mut o: OnPieceOut = z();
    o.records_written = 1;
    let mut r: RecordWrite = z();
    r.op = RECORD_PUT;
    r.kind = 1;
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::IndexOutOfRange, "record.kind")
    );
}

// ── refusal, serve, cancel ──

#[test]
fn a_refusal_marker_is_known_and_its_reply_follows_m_sb() {
    let mut o: RefusalOut = z();
    o.marker = 2;
    assert_eq!(
        check_refusal(Ready, &o, &[], &caps()),
        f(Rule::UnknownCode, "refusal.marker")
    );
    let mut o: RefusalOut = z();
    o.reply_needed = 17;
    assert_eq!(
        check_refusal(Ready, &o, &[], &caps()),
        f(Rule::NeededNotFailed, "refusal.reply")
    );
    assert_eq!(check_refusal(Failed, &o, &[], &caps()), Ok(()));
    o.reply_needed = 16;
    assert_eq!(
        check_refusal(Failed, &o, &[], &caps()),
        f(Rule::WastedRecall, "refusal")
    );
    let mut o: RefusalOut = z();
    o.fields_needed = 5;
    o.arena_written = 1;
    assert_eq!(
        check_refusal(Failed, &o, &[], &caps()),
        f(Rule::WrittenOnShort, "refusal")
    );
}

#[test]
fn a_serve_reply_follows_m_sb_and_its_fields_stay_in_the_arena() {
    let mut o: ServeOut = z();
    o.arena_needed = 17;
    assert_eq!(
        check_serve(Ready, &o, &[], &caps()),
        f(Rule::NeededNotFailed, "serve.arena")
    );
    let mut o: ServeOut = z();
    o.fields_written = 1;
    o.arena_written = 1;
    let mut fl: OutField = z();
    fl.value = sp(0, 2);
    assert_eq!(
        check_serve(Ready, &o, &[fl], &caps()),
        f(Rule::SpanOutOfBounds, "field.value")
    );
}

#[test]
fn an_unwritten_or_unknown_cancel_disposition_is_fault() {
    assert_eq!(check_cancel(0), f(Rule::UnknownCode, "cancel.disposition"));
    assert_eq!(check_cancel(4), f(Rule::UnknownCode, "cancel.disposition"));
    assert_eq!(check_cancel(CANCEL_ABORTED), Ok(()));
}

// ── snapshot ──

fn snapshot() -> PlaneSnapshot {
    let mut s: PlaneSnapshot = z();
    s.size = std::mem::size_of::<PlaneSnapshot>() as u32;
    s.generation = 7;
    s
}

#[test]
fn a_snapshot_for_another_generation_or_size_is_fault() {
    assert_eq!(check_snapshot(&snapshot(), 7), Ok(()));
    assert_eq!(
        check_snapshot(&snapshot(), 8),
        f(Rule::Foreign, "snapshot.generation")
    );
    let mut sn = snapshot();
    sn.size = 8;
    assert_eq!(check_snapshot(&sn, 7), f(Rule::Foreign, "snapshot.size"));
}

#[test]
fn a_snapshot_list_counted_with_a_null_pointer_or_too_long_is_fault() {
    let mut sn = snapshot();
    sn.claims_len = 1;
    assert_eq!(
        check_snapshot(&sn, 7),
        f(Rule::NullWithCount, "snapshot.claims")
    );
    let mut sn = snapshot();
    sn.admin_routes_len = 1;
    assert_eq!(
        check_snapshot(&sn, 7),
        f(Rule::NullWithCount, "snapshot.admin_routes")
    );
    let mut sn = snapshot();
    sn.openapi.len = 1;
    assert_eq!(
        check_snapshot(&sn, 7),
        f(Rule::NullWithCount, "snapshot.openapi")
    );
    let mut sn = snapshot();
    sn.claims_len = MAX_ROUTES as usize + 1;
    assert_eq!(check_snapshot(&sn, 7), f(Rule::OverMax, "snapshot.claims"));
    let mut sn = snapshot();
    sn.admin_routes_len = MAX_ROUTES as usize + 1;
    assert_eq!(
        check_snapshot(&sn, 7),
        f(Rule::OverMax, "snapshot.admin_routes")
    );
}

#[test]
fn every_snapshot_claim_and_route_is_named() {
    let c = Claim {
        verb: s("V"),
        target: s("/t"),
        carrier: s("c"),
    };
    assert_eq!(check_claims(&[c]), Ok(()));
    let mut bad = c;
    bad.carrier = z();
    assert_eq!(check_claims(&[bad]), f(Rule::Missing, "claim.carrier"));
    let r = AdminRoute {
        verb: s("V"),
        target: z(),
    };
    assert_eq!(
        check_admin_routes(&[r]),
        f(Rule::Missing, "admin_route.target")
    );
}

// ── tail ──

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
    assert_eq!(check_tail(&t), f(Rule::Missing, "tail.ingress"));
    let mut t = tail();
    t.ingress = INGRESS_REQUEST_RESPONSE | (1 << 5);
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.ingress"));
    let mut t = tail();
    t.flags = 2;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.flags"));
    let mut t = tail();
    t.dispatch_shape = 2;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.dispatch_shape"));
}

#[test]
fn a_tail_list_or_string_counted_with_a_null_pointer_is_fault() {
    let mut t = tail();
    t.needs_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.needs"));
    let mut t = tail();
    t.route_cost_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.route_cost"));
    let mut t = tail();
    t.label.len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.label"));
}

fn section(flags: u32) -> Section {
    Section {
        name: s("sec"),
        flags,
        _reserved: 0,
    }
}

#[test]
fn exactly_one_section_is_the_declaring_one() {
    assert_eq!(
        check_sections(&[section(SECTION_DECLARING), section(SECTION_REQUIRED)]),
        Ok(())
    );
    assert_eq!(
        check_sections(&[section(SECTION_REQUIRED)]),
        f(Rule::NotExactlyOne, "section.declaring")
    );
    assert_eq!(
        check_sections(&[section(SECTION_DECLARING), section(SECTION_DECLARING)]),
        f(Rule::NotExactlyOne, "section.declaring")
    );
    assert_eq!(
        check_sections(&[section(SECTION_DECLARING | 8)]),
        f(Rule::UnknownCode, "section.flags")
    );
    let mut unnamed = section(SECTION_DECLARING);
    unnamed.name = z();
    assert_eq!(check_sections(&[unnamed]), f(Rule::Missing, "section.name"));
}

#[test]
fn dialect_auth_names_a_dialect_and_a_style() {
    let d = DialectAuth {
        dialect: 0,
        _reserved: 0,
        style: s("st"),
    };
    assert_eq!(check_dialect_auth(&[d], 1), Ok(()));
    assert_eq!(
        check_dialect_auth(&[d], 0),
        f(Rule::IndexOutOfRange, "dialect_auth.dialect")
    );
    let mut bad = d;
    bad.style = z();
    assert_eq!(
        check_dialect_auth(&[bad], 1),
        f(Rule::Missing, "dialect_auth.style")
    );
}

#[test]
fn route_cost_names_a_class_with_a_finite_non_negative_weight() {
    let r = RouteCost {
        class: 0,
        _reserved: 0,
        weight: 0.5,
    };
    assert_eq!(check_route_cost(&[r], 1), Ok(()));
    assert_eq!(
        check_route_cost(&[r], 0),
        f(Rule::IndexOutOfRange, "route_cost.class")
    );
    for w in [f64::NAN, f64::INFINITY, -1.0] {
        let mut bad = r;
        bad.weight = w;
        assert_eq!(
            check_route_cost(&[bad], 1),
            f(Rule::NotFinite, "route_cost.weight")
        );
    }
}

#[test]
fn billable_classes_are_named() {
    let c = BillableClass {
        class: s("c"),
        family: z(),
    };
    assert_eq!(
        check_billable_classes(&[c]),
        f(Rule::Missing, "billable_class.family")
    );
}

#[test]
fn needs_have_a_known_direction_and_a_transport() {
    let mut n: Need = z();
    n.direction = DIRECTION_OUTBOUND;
    n.transport = s("t");
    assert_eq!(check_needs(&[n]), Ok(()));
    let mut bad = n;
    bad.direction = 3;
    assert_eq!(check_needs(&[bad]), f(Rule::UnknownCode, "need.direction"));
    let mut bad = n;
    bad.transport = z();
    assert_eq!(check_needs(&[bad]), f(Rule::Missing, "need.transport"));
    let mut bad = n;
    bad.details.ptr = null();
    bad.details.len = 1;
    assert_eq!(check_needs(&[bad]), f(Rule::NullWithCount, "need.details"));
}

#[test]
fn a_multi_buffer_short_answer_needs_one_buffer_over_its_cap() {
    let mut o: OnPieceOut = z();
    o.arena_needed = 17;
    o.fields_needed = 3;
    assert_eq!(
        check_on_piece(Failed, &o, (&[], &[], &[]), &caps(), &bounds()),
        Ok(()),
        "arena short, fields report their full size"
    );
    o.arena_needed = 16;
    assert_eq!(
        check_on_piece(Failed, &o, (&[], &[], &[]), &caps(), &bounds()),
        f(Rule::WastedRecall, "on_piece")
    );
    let mut r: ServeOut = z();
    r.reply_needed = 10;
    r.fields_needed = 2;
    assert_eq!(
        check_serve(Failed, &r, &[], &caps()),
        f(Rule::WastedRecall, "serve")
    );
    r.reply_needed = 40;
    assert_eq!(check_serve(Failed, &r, &[], &caps()), Ok(()));
}
