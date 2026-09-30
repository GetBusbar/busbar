// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the plane answer validators: one per rule and arm, each failing if its check is
//! removed.

use std::mem::zeroed;
use std::ptr::null;

use super::*;
use crate::abi::hook::{SignalEntry, SignalValue, SIGNAL_TAG_BOOL, SIGNAL_TAG_STR};
use crate::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_RESPONSE_HEADERS_MAX};
use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready, Refused};
use crate::abi::mechanism::check::{check_needs, fault};
use crate::abi::mechanism::door::{Section, SECTION_DECLARING, SECTION_REQUIRED};
use crate::abi::plane::*;
use crate::caps::ReasonCode;

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

/// RED: a refused arrival names the plane's own code and a 4xx status; any other answer names
/// neither.
#[test]
fn a_refused_arrival_names_its_code_and_a_caller_status() {
    let refused = |refusal, refusal_status| {
        let mut o: ArriveOut = z();
        o.refusal = refusal;
        o.refusal_status = refusal_status;
        o
    };
    assert_eq!(
        check_arrive(Refused, &refused(3, 404), &[], 4, &bounds()),
        Ok(())
    );
    assert_eq!(
        check_arrive(Refused, &refused(1, 400), &[], 4, &bounds()),
        Ok(())
    );
    assert_eq!(
        check_arrive(Refused, &refused(1, 499), &[], 4, &bounds()),
        Ok(())
    );
    // Zero on REFUSED: the plane could not render what it decided.
    assert_eq!(
        check_arrive(Refused, &refused(0, 400), &[], 4, &bounds()),
        f(Rule::Missing, "arrive.refusal")
    );
    // Out of range: a plane never mints a 5xx (the kernel's faults keep the table's status), and
    // a refusal is never a success.
    for status in [0, 200, 399, 500, 503, 600] {
        assert_eq!(
            check_arrive(Refused, &refused(1, status), &[], 4, &bounds()),
            f(Rule::UnknownCode, "arrive.refusal_status"),
            "{status}"
        );
    }
    // Nonzero on any other outcome.
    for outcome in [Ready, Failed, Pending] {
        for o in [refused(1, 0), refused(0, 400)] {
            assert_eq!(
                check_arrive(outcome, &o, &[], 4, &bounds()),
                f(Rule::Contradiction, "arrive.refusal"),
                "{outcome:?}"
            );
        }
    }
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

/// One cumulative count per class and source: a second count of one class is a contradiction,
/// refused (so the host never has to add two running totals, which could wrap).
#[test]
fn a_class_counted_twice_is_fault() {
    let mut o: ArriveOut = z();
    o.units_written = 2;
    let mut u: UnitCount = z();
    u.class = 1;
    u.source = UNITS_REPORTED;
    u.amount = u64::MAX;
    let mut v = u;
    v.amount = 2;
    assert_eq!(
        check_arrive(Ready, &o, &[u, v], 4, &bounds()),
        f(Rule::Contradiction, "unit.class")
    );
    v.source = UNITS_ESTIMATED;
    assert_eq!(check_arrive(Ready, &o, &[u, v], 4, &bounds()), Ok(()));
    v.source = UNITS_REPORTED;
    v.class = 0;
    assert_eq!(check_arrive(Ready, &o, &[u, v], 4, &bounds()), Ok(()));
}

/// THE CANCEL RULE's shape: an arrival is either a cancellable unit (`correlation`) or a cancel
/// (`cancels`), never both. Either alone is valid.
#[test]
fn an_arrival_that_cancels_carries_no_correlation_of_its_own() {
    let mut o: ArriveOut = z();
    o.correlation = 7;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Ok(()),
        "a cancellable unit"
    );
    let mut o: ArriveOut = z();
    o.cancels = 7;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Ok(()),
        "a cancel"
    );
    let mut o: ArriveOut = z();
    o.correlation = 7;
    o.cancels = 7;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.cancel_with_correlation")
    );
}

/// A REFUSED ARRIVAL'S WORDS are carried whole or not at all: up to `MAX_REFUSAL_TEXT` bytes pass,
/// one byte more is a FAULT (never cut), a length with no bytes is a FAULT, and a READY arrival's
/// head error is not judged here.
#[test]
fn a_refused_arrivals_text_is_bounded_and_never_cut() {
    let at_cap = "x".repeat(MAX_REFUSAL_TEXT as usize);
    let over = "x".repeat(MAX_REFUSAL_TEXT as usize + 1);
    let text = |t: &str| AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    };
    let mut o: ArriveOut = z();
    o.head.error = text(&at_cap);
    assert_eq!(check_arrive(Refused, &o, &[], 4, &bounds()), Ok(()), "at the cap");
    o.head.error = text(&over);
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::OverMax, "arrive.refusal_text")
    );
    o.head.error = AbiStr {
        ptr: null(),
        len: 3,
    };
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::NullWithCount, "arrive.refusal_text")
    );
    let mut o: ArriveOut = z();
    o.head.error = text(&over);
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()), "not judged on READY");
    let mut o: ArriveOut = z();
    o.head.error = s("Method `x` is not implemented by this server.");
    assert_eq!(check_arrive(Refused, &o, &[], 4, &bounds()), Ok(()));
}

/// Words that echo the largest field line a transport admits fit: an echoed field never overflows
/// the refusal text.
#[test]
fn a_refusal_echoing_the_largest_admitted_field_line_fits() {
    let echoed = format!(
        "unexpected field: {}",
        "h".repeat(LARGEST_ADMITTED_FIELD_LINE as usize)
    );
    assert!(echoed.len() as u64 > LARGEST_ADMITTED_FIELD_LINE);
    assert!(MAX_REFUSAL_TEXT >= LARGEST_ADMITTED_FIELD_LINE + 1024);
    let mut o: ArriveOut = z();
    o.head.error = AbiStr {
        ptr: echoed.as_ptr(),
        len: echoed.len(),
    };
    assert_eq!(check_arrive(Refused, &o, &[], 4, &bounds()), Ok(()));
}

/// The three refusal causes are distinct, and a rendering's status defaults to the kernel's.
#[test]
fn the_refusal_causes_are_distinct_and_status_zero_keeps_the_kernels() {
    assert_eq!(
        [REFUSAL_KERNEL, REFUSAL_GATE, REFUSAL_ARRIVE],
        [0, 1, 2],
        "the cause numbering is the ABI's"
    );
    let o: RefusalOut = z();
    assert_eq!(o.status, 0);
    assert_eq!(check_refusal(Ready, &o, &[], &caps()), Ok(()));
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
    o.flags = 1 << 8;
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

/// A text message is a whole message of at least one byte: PIECE_OUT_TEXT on an answer that
/// emits nothing, or one that asks for more, is refused.
#[test]
fn a_text_message_is_whole_and_not_empty() {
    let mut o: OnPieceOut = z();
    o.flags = PIECE_OUT_TEXT;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.text")
    );
    o.emitted = 3;
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    o.more = 1;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.text")
    );
}

/// THE CATALOGUE WATCH: `EMIT_WATCH_CATALOGUE` and `EMIT_UNWATCH_CATALOGUE` are known bits, each
/// valid alone, and an answer setting both is a contradiction.
#[test]
fn a_catalogue_watch_and_its_drop_are_known_and_never_together() {
    for flag in [EMIT_WATCH_CATALOGUE, EMIT_UNWATCH_CATALOGUE] {
        let mut o: OnPieceOut = z();
        o.flags = flag;
        assert_eq!(piece(&o, &[], &[], &[]), Ok(()), "flag {flag} alone");
    }
    let mut o: OnPieceOut = z();
    o.flags = EMIT_WATCH_CATALOGUE | EMIT_UNWATCH_CATALOGUE;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.watch_with_unwatch")
    );
}

/// The catalogue-moved tick is its own `OnPieceIn::flags` bit, distinct from every other piece bit,
/// and the watch bits are distinct from every other emit bit.
#[test]
fn the_catalogue_bits_share_no_bit_with_their_neighbours() {
    let piece_bits = [
        PIECE_END_OF_FRAME,
        PIECE_LAST,
        PIECE_HAS_STATUS,
        PIECE_CATALOGUE_MOVED,
    ];
    let emit_bits = [
        EMIT_TO_FAR_END,
        EMIT_DONE,
        EMIT_WATCH_CATALOGUE,
        EMIT_UNWATCH_CATALOGUE,
    ];
    for bits in [&piece_bits[..], &emit_bits[..]] {
        for (i, a) in bits.iter().enumerate() {
            assert_eq!(a.count_ones(), 1, "{a} is one bit");
            for b in &bits[i + 1..] {
                assert_eq!(a & b, 0, "{a} and {b} overlap");
            }
        }
    }
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

/// A record write is a put: the retired delete code (2) and every other is FAULT, never a write
/// the kernel would drop.
#[test]
fn a_record_write_that_is_not_a_put_is_fault() {
    let mut o: OnPieceOut = z();
    o.records_written = 1;
    let mut r: RecordWrite = z();
    for op in [0, 2, u32::MAX] {
        r.op = op;
        assert_eq!(piece(&o, &[], &[r], &[]), f(Rule::UnknownCode, "record.op"));
    }
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
    // The gate-rejected marker is the kernel's to set, never a plane's.
    o.marker = MARK_GATE_REJECTED;
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
    assert_eq!(
        check_cancel(Ready, 0),
        f(Rule::UnknownCode, "cancel.disposition")
    );
    assert_eq!(
        check_cancel(Ready, 4),
        f(Rule::UnknownCode, "cancel.disposition")
    );
    assert_eq!(check_cancel(Ready, CANCEL_ABORTED), Ok(()));
    // Another outcome answers no disposition: unwritten passes, a written one is FAULT.
    assert_eq!(check_cancel(Failed, 0), Ok(()));
    assert_eq!(check_cancel(Pending, 0), Ok(()));
    assert_eq!(
        check_cancel(Refused, CANCEL_ABORTED),
        f(Rule::Contradiction, "cancel.disposition")
    );
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

fn claim(verb: &'static str, target: &'static str, flags: u32) -> Claim {
    Claim {
        verb: s(verb),
        target: s(target),
        carrier: s("c"),
        flags,
        refusal_dialect: 0,
        _pad: 0,
    }
}

#[test]
fn a_claim_states_only_known_flags() {
    let open_exact = claim("V", "/t", CLAIM_OPEN | CLAIM_EXACT);
    assert_eq!(check_claims(&[open_exact], 1), Ok(()));
    // RED: a bit neither CLAIM_OPEN nor CLAIM_EXACT.
    let unknown = claim("V", "/t", CLAIM_EXACT << 1);
    assert_eq!(
        check_claims(&[unknown], 1),
        f(Rule::UnknownCode, "claim.flags")
    );
}

/// RED: a route's refusal dialect names a dialect the tail declares; a plane with none states 0.
#[test]
fn a_claims_refusal_dialect_is_a_declared_dialect() {
    let mut c = claim("POST", "/v1/x", 0);
    c.refusal_dialect = 5;
    assert_eq!(check_claims(&[c], 6), Ok(()));
    assert_eq!(
        check_claims(&[c], 5),
        f(Rule::IndexOutOfRange, "claim.refusal_dialect")
    );
    assert_eq!(
        check_claims(&[c], 0),
        f(Rule::IndexOutOfRange, "claim.refusal_dialect")
    );
    c.refusal_dialect = 0;
    assert_eq!(check_claims(&[c], 0), Ok(()), "no dialects: 0");
}

#[test]
fn every_snapshot_claim_and_route_is_named() {
    let c = claim("V", "/t", 0);
    assert_eq!(check_claims(&[c], 1), Ok(()));
    let mut bad = c;
    bad.carrier = z();
    assert_eq!(check_claims(&[bad], 1), f(Rule::Missing, "claim.carrier"));
    let r = AdminRoute {
        verb: s("V"),
        target: z(),
        flags: 0,
        _reserved: 0,
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
    t.flags = 4;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.flags"));
    let mut t = tail();
    t.dispatch_shape = 2;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.dispatch_shape"));
}

#[test]
fn a_tail_list_or_string_counted_with_a_null_pointer_is_fault() {
    let mut t = tail();
    t.record_kinds_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.record_kinds"));
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

/// Every fee unit is also a billable class, so the plane can report it as a count. RED: a fee
/// unit the classes do not list is refused.
#[test]
fn fee_units_are_billable_classes() {
    let c = BillableClass {
        class: s("per_request"),
        family: s("request"),
    };
    assert_eq!(check_fee_units(&[s("per_request")], &[c]), Ok(()));
    assert_eq!(check_fee_units(&[], &[]), Ok(()));
    assert_eq!(
        check_fee_units(&[s("per_session")], &[c]),
        f(Rule::Contradiction, "tail.fee_units")
    );
    assert_eq!(
        check_fee_units(&[z()], &[c]),
        f(Rule::Missing, "tail.fee_units")
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

/// A need's kept response head fields: lower-case tokens, bounded; a hop-by-hop or credential
/// field is refused at boot, so it never crosses to a plugin.
#[test]
fn a_need_keeps_only_declarable_response_fields() {
    let mut n: Need = z();
    n.direction = DIRECTION_OUTBOUND;
    n.transport = s("t");
    let kept = [
        s("x-session-id"),
        s("retry-after"),
        s("x-ratelimit-remaining"),
    ];
    n.keep_response_headers = kept.as_ptr();
    n.keep_response_headers_len = kept.len();
    assert_eq!(check_needs(&[n]), Ok(()));
    for name in [
        "authorization",
        "connection",
        "set-cookie",
        "transfer-encoding",
    ] {
        let bad = [s(name)];
        let mut b = n;
        b.keep_response_headers = bad.as_ptr();
        b.keep_response_headers_len = 1;
        assert_eq!(
            check_needs(&[b]),
            f(Rule::Foreign, "need.keep_response_headers"),
            "{name}"
        );
    }
    let upper = [s("Retry-After")];
    let mut b = n;
    b.keep_response_headers = upper.as_ptr();
    b.keep_response_headers_len = 1;
    assert_eq!(
        check_needs(&[b]),
        f(Rule::UnknownCode, "need.keep_response_headers")
    );
    let many: Vec<AbiStr> = (0..=KEEP_RESPONSE_HEADERS_MAX).map(|_| s("x")).collect();
    let mut b = n;
    b.keep_response_headers = many.as_ptr();
    b.keep_response_headers_len = many.len();
    assert_eq!(
        check_needs(&[b]),
        f(Rule::OverMax, "need.keep_response_headers")
    );
    let mut b = n;
    b.keep_response_headers = null();
    b.keep_response_headers_len = 1;
    assert_eq!(
        check_needs(&[b]),
        f(Rule::NullWithCount, "need.keep_response_headers")
    );
}

/// The need's egress class is one of the four THE DESIGN names, or the connector's default.
#[test]
fn a_need_names_a_known_egress_class() {
    use crate::abi::host::conn::connector::{
        EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_PROVIDER,
    };
    let mut n: Need = z();
    n.direction = DIRECTION_OUTBOUND;
    n.transport = s("t");
    for class in [
        EGRESS_DEFAULT,
        EGRESS_PROVIDER,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_OPEN_WEB,
        EGRESS_LOOPBACK_ALLOWED,
    ] {
        n.egress_class = class;
        assert_eq!(check_needs(&[n]), Ok(()), "class {class}");
    }
    n.egress_class = EGRESS_LOOPBACK_ALLOWED + 1;
    assert_eq!(check_needs(&[n]), f(Rule::UnknownCode, "need.egress_class"));
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

// ── the plane driver's additions: the ATTEMPT answer, the verdict, probes, public routes, chained
//    record framing, `project` and `drive` ──

#[test]
fn a_verdict_is_known() {
    let mut o: OnPieceOut = z();
    o.verdict = VERDICT_HARD;
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    o.verdict = VERDICT_HARD + 1;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::UnknownCode, "on_piece.verdict")
    );
}

#[test]
fn a_verdict_rides_only_a_ready_answer() {
    let mut o: OnPieceOut = z();
    o.verdict = VERDICT_RETRY;
    assert_eq!(
        check_on_piece(Pending, &o, (&[], &[], &[]), &caps(), &bounds()),
        f(Rule::Contradiction, "on_piece.verdict_not_ready")
    );
    o.verdict = VERDICT_NONE;
    assert_eq!(
        check_on_piece(Pending, &o, (&[], &[], &[]), &caps(), &bounds()),
        Ok(())
    );
}

fn attempt_answer() -> OnPieceOut {
    let mut o: OnPieceOut = z();
    o.flags = EMIT_TO_FAR_END;
    o.arena_written = 8;
    o.verb = sp(0, 4);
    o.target = sp(4, 4);
    o
}

#[test]
fn an_attempt_answer_names_its_verb_and_target_in_the_arena() {
    assert_eq!(piece(&attempt_answer(), &[], &[], &[]), Ok(()));
    let mut o = attempt_answer();
    o.verb = sp(6, 4);
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::SpanOutOfBounds, "on_piece.verb")
    );
    let mut o = attempt_answer();
    o.target = sp(u32::MAX - 1, 4);
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::SpanOutOfBounds, "on_piece.target")
    );
}

#[test]
fn a_verb_never_comes_without_a_target() {
    let mut o = attempt_answer();
    o.target = sp(0, 0);
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.verb_without_target")
    );
    let mut o = attempt_answer();
    o.verb = sp(0, 0);
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.verb_without_target")
    );
}

#[test]
fn a_request_goes_to_the_far_end() {
    let mut o = attempt_answer();
    o.flags = 0;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.request_not_to_far_end")
    );
}

#[test]
fn a_tail_may_declare_probes() {
    let mut t = tail();
    t.flags = TAIL_PROBES | TAIL_FALLBACK;
    assert_eq!(check_tail(&t), Ok(()));
    assert_eq!(CLAIM_PROBE, u32::MAX, "never a snapshot claim index");
}

#[test]
fn a_tail_counting_record_chains_over_a_null_pointer_is_fault() {
    let mut t = tail();
    t.record_chains_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.record_chains"));
}

#[test]
fn an_admin_route_flag_is_known() {
    let mut r = AdminRoute {
        verb: s("V"),
        target: s("/t"),
        flags: ROUTE_PUBLIC,
        _reserved: 0,
    };
    assert_eq!(check_admin_routes(&[r]), Ok(()));
    r.flags = ROUTE_PUBLIC << 1;
    assert_eq!(
        check_admin_routes(&[r]),
        f(Rule::UnknownCode, "admin_route.flags")
    );
}

fn chain(kind: u32) -> RecordChain {
    RecordChain {
        kind,
        framing: CHAIN_PIPE_SEPARATED,
        flags: CHAIN_DIGESTS_SCOPE,
        _reserved: 0,
    }
}

#[test]
fn a_record_chain_names_a_record_kind() {
    assert_eq!(check_record_chains(&[chain(0), chain(1)], 2), Ok(()));
    assert_eq!(
        check_record_chains(&[chain(2)], 2),
        f(Rule::IndexOutOfRange, "record_chain.kind")
    );
}

#[test]
fn a_record_chain_framing_is_known() {
    for framing in [0, CHAIN_PIPE_SEPARATED + 1] {
        let mut c = chain(0);
        c.framing = framing;
        assert_eq!(
            check_record_chains(&[c], 1),
            f(Rule::UnknownCode, "record_chain.framing")
        );
    }
    let mut c = chain(0);
    c.framing = CHAIN_LENGTH_PREFIXED;
    assert_eq!(check_record_chains(&[c], 1), Ok(()));
}

#[test]
fn a_record_chain_flag_is_known() {
    let mut c = chain(0);
    c.flags = CHAIN_DIGESTS_SCOPE << 1;
    assert_eq!(
        check_record_chains(&[c], 1),
        f(Rule::UnknownCode, "record_chain.flags")
    );
}

#[test]
fn a_record_kind_is_chained_at_most_once() {
    assert_eq!(
        check_record_chains(&[chain(1), chain(0), chain(1)], 2),
        f(Rule::Contradiction, "record_chain.kind_twice")
    );
}

// ── trust keys ──

const MECHANISMS: [PinMechanism; 2] = [
    PinMechanism {
        token: AbiStr {
            ptr: b"rooted".as_ptr(),
            len: 6,
        },
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: AbiStr {
            ptr: b"bare".as_ptr(),
            len: 4,
        },
        flags: 0,
        _reserved: 0,
    },
];

fn pin_key() -> TrustKey {
    TrustKey {
        key: s("pin"),
        role: TRUST_PIN,
        flags: PIN_FINGERPRINT,
        default: AbiStr {
            ptr: null(),
            len: 0,
        },
        mechanisms: MECHANISMS.as_ptr(),
        mechanisms_len: MECHANISMS.len(),
    }
}

fn duration_key(role: u32) -> TrustKey {
    TrustKey {
        key: s("ttl"),
        role,
        flags: 0,
        default: s("5s"),
        mechanisms: null(),
        mechanisms_len: 0,
    }
}

fn row(dialect: u32, reason: ReasonCode, status: u32) -> RefusalStatus {
    RefusalStatus {
        dialect,
        reason: reason_code(reason),
        status,
        _reserved: 0,
    }
}

#[test]
fn a_tail_counting_trust_keys_over_a_null_pointer_is_fault() {
    let mut t = tail();
    t.trust_keys_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.trust_keys"));
}

#[test]
fn well_formed_trust_keys_pass() {
    let keys = [
        pin_key(),
        duration_key(TRUST_REVERIFY_TTL),
        duration_key(TRUST_RECOVERY_BACKOFF),
    ];
    assert_eq!(check_trust_keys(&keys), Ok(()));
    assert_eq!(check_pin_mechanisms(&MECHANISMS), Ok(()));
}

#[test]
fn a_trust_key_is_named() {
    let mut k = pin_key();
    k.key = AbiStr {
        ptr: null(),
        len: 0,
    };
    assert_eq!(check_trust_keys(&[k]), f(Rule::Missing, "trust_key.key"));
}

#[test]
fn a_trust_key_role_is_known() {
    for role in [0, TRUST_RECOVERY_BACKOFF + 1] {
        assert_eq!(
            check_trust_keys(&[duration_key(role)]),
            f(Rule::UnknownCode, "trust_key.role")
        );
    }
}

#[test]
fn a_tail_counting_refusal_statuses_over_a_null_pointer_is_fault() {
    let mut t = tail();
    t.refusal_statuses_len = 1;
    assert_eq!(
        check_tail(&t),
        f(Rule::NullWithCount, "tail.refusal_statuses")
    );
}

#[test]
fn a_refusal_status_names_a_declared_dialect_or_every_dialect() {
    let rows = [
        row(0, ReasonCode::Unauthenticated, 403),
        row(REFUSAL_ANY_DIALECT, ReasonCode::Unauthenticated, 401),
    ];
    assert_eq!(check_refusal_statuses(&rows, 1), Ok(()));
    assert_eq!(
        check_refusal_statuses(&[row(1, ReasonCode::Unauthenticated, 403)], 1),
        f(Rule::IndexOutOfRange, "refusal_status.dialect")
    );
}

#[test]
fn a_refusal_status_names_a_reason_the_vocabulary_holds() {
    let mut r = row(0, ReasonCode::OverBudget, 400);
    r.reason = ReasonCode::ALL.len() as u32;
    assert_eq!(
        check_refusal_statuses(&[r], 1),
        f(Rule::UnknownCode, "refusal_status.reason")
    );
}

#[test]
fn a_refusal_status_is_a_client_or_server_error() {
    for status in [0, 200, 399, 600, 999] {
        assert_eq!(
            check_refusal_statuses(&[row(0, ReasonCode::OverBudget, status)], 1),
            f(Rule::UnknownCode, "refusal_status.status"),
            "{status}"
        );
    }
    for status in [400, 599] {
        assert_eq!(
            check_refusal_statuses(&[row(0, ReasonCode::OverBudget, status)], 1),
            Ok(())
        );
    }
}

#[test]
fn a_trust_key_default_is_never_counted_over_a_null_pointer() {
    let mut k = duration_key(TRUST_REVERIFY_TTL);
    k.default = AbiStr {
        ptr: null(),
        len: 2,
    };
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::NullWithCount, "trust_key.default")
    );
}

#[test]
fn a_trust_key_never_counts_mechanisms_over_a_null_pointer() {
    let mut k = pin_key();
    k.mechanisms = null();
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::NullWithCount, "trust_key.mechanisms")
    );
}

#[test]
fn a_pin_flag_is_known() {
    let mut k = pin_key();
    k.flags = PIN_FINGERPRINT << 1;
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::UnknownCode, "trust_key.flags")
    );
}

#[test]
fn a_pin_names_at_least_one_mechanism() {
    let mut k = pin_key();
    k.mechanisms_len = 0;
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::Missing, "trust_key.mechanisms")
    );
}

#[test]
fn a_pin_has_no_default() {
    let mut k = pin_key();
    k.default = s("x");
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::Contradiction, "trust_key.pin_default")
    );
}

#[test]
fn a_duration_key_carries_no_pin_flag() {
    let mut k = duration_key(TRUST_REVERIFY_TTL);
    k.flags = PIN_FINGERPRINT;
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::UnknownCode, "trust_key.duration_flags")
    );
}

#[test]
fn a_duration_key_names_no_mechanism() {
    let mut k = duration_key(TRUST_REVERIFY_TTL);
    k.mechanisms = MECHANISMS.as_ptr();
    k.mechanisms_len = 1;
    assert_eq!(
        check_trust_keys(&[k]),
        f(Rule::Contradiction, "trust_key.duration_mechanisms")
    );
}

#[test]
fn a_trust_role_is_declared_at_most_once() {
    let keys = [
        duration_key(TRUST_REVERIFY_TTL),
        pin_key(),
        duration_key(TRUST_REVERIFY_TTL),
    ];
    assert_eq!(
        check_trust_keys(&keys),
        f(Rule::Contradiction, "trust_key.role_twice")
    );
}

#[test]
fn a_pin_mechanism_is_named_with_known_flags() {
    let mut m = MECHANISMS[0];
    m.token = AbiStr {
        ptr: null(),
        len: 0,
    };
    assert_eq!(
        check_pin_mechanisms(&[m]),
        f(Rule::Missing, "pin_mechanism.token")
    );
    let mut m = MECHANISMS[0];
    m.flags = MECHANISM_ROOT << 1;
    assert_eq!(
        check_pin_mechanisms(&[m]),
        f(Rule::UnknownCode, "pin_mechanism.flags")
    );
}

#[test]
fn a_dialect_and_reason_are_stated_at_most_once() {
    let rows = [
        row(0, ReasonCode::OverBudget, 400),
        row(0, ReasonCode::RateLimited, 429),
        row(0, ReasonCode::OverBudget, 429),
    ];
    assert_eq!(
        check_refusal_statuses(&rows, 1),
        f(Rule::Contradiction, "refusal_status.twice")
    );
    let rows = [
        row(REFUSAL_ANY_DIALECT, ReasonCode::OverBudget, 400),
        row(REFUSAL_ANY_DIALECT, ReasonCode::OverBudget, 400),
    ];
    assert_eq!(
        check_refusal_statuses(&rows, 1),
        f(Rule::Contradiction, "refusal_status.twice")
    );
}

/// THE WIRE CODE TABLE, pinned whole: every number to its code and its word. Renumbering one
/// variant, reordering the table or giving a code another word is RED here.
const PINNED: &[(u32, RefusalCode, &str)] = &[
    (0, RefusalCode::InFlightCap, "in_flight_cap"),
    (1, RefusalCode::CursorBudget, "cursor_budget"),
    (2, RefusalCode::CredentialBudget, "credential_budget"),
    (3, RefusalCode::SessionBudget, "session_budget"),
    (4, RefusalCode::SpillBudget, "spill_budget"),
    (5, RefusalCode::ScratchExhausted, "scratch_exhausted"),
    (6, RefusalCode::RateLimited, "rate_limited"),
    (7, RefusalCode::BodyTooLarge, "body_too_large"),
    (8, RefusalCode::OpenSlotBusy, "open_slot_busy"),
    (9, RefusalCode::DecodeFailed, "decode_failed"),
    (10, RefusalCode::SchemeNotDeclared, "scheme_not_declared"),
    (11, RefusalCode::SessionUnbound, "session_unbound"),
    (12, RefusalCode::Unauthenticated, "unauthenticated"),
    (13, RefusalCode::ChallengeExhausted, "challenge_exhausted"),
    (14, RefusalCode::Revoked, "revoked"),
    (15, RefusalCode::ScopeDenied, "scope_denied"),
    (16, RefusalCode::PoolNotPermitted, "pool_not_permitted"),
    (17, RefusalCode::NoRate, "no_rate"),
    (18, RefusalCode::HookVeto, "hook_veto"),
    (19, RefusalCode::NoDestination, "no_destination"),
    (20, RefusalCode::OverBudget, "over_budget"),
    (21, RefusalCode::GroupFrozen, "group_frozen"),
    (22, RefusalCode::Unpriced, "unpriced"),
    (23, RefusalCode::OverdraftCeiling, "overdraft_ceiling"),
    (24, RefusalCode::StaleSlice, "stale_slice"),
    (
        25,
        RefusalCode::DurabilityUnavailable,
        "durability_unavailable",
    ),
    (26, RefusalCode::TierMismatch, "tier_mismatch"),
    (27, RefusalCode::Replayed, "replayed"),
    (28, RefusalCode::InFlight, "in_flight"),
    (
        29,
        RefusalCode::DestinationBudgetExhausted,
        "destination_budget_exhausted",
    ),
    (30, RefusalCode::BreakerOpen, "breaker_open"),
    (
        31,
        RefusalCode::DestinationUnreachable,
        "destination_unreachable",
    ),
    (32, RefusalCode::MeterDisputed, "meter_disputed"),
    (33, RefusalCode::HandoffMismatch, "handoff_mismatch"),
    (34, RefusalCode::PlanePanic, "plane_panic"),
    (35, RefusalCode::TaskLost, "task_lost"),
    (36, RefusalCode::Stalled, "stalled"),
    (37, RefusalCode::SecretPlaceholder, "secret_placeholder"),
    (38, RefusalCode::Drain, "drain"),
    (39, RefusalCode::Superseded, "superseded"),
    (40, RefusalCode::ClientGone, "client_gone"),
    (41, RefusalCode::DeadlineExceeded, "deadline_exceeded"),
];

#[test]
fn every_wire_refusal_code_is_pinned_to_its_number_and_word() {
    assert_eq!(
        RefusalCode::ALL.len(),
        PINNED.len(),
        "a wire code without a pin: append it"
    );
    for (i, (number, code, word)) in PINNED.iter().enumerate() {
        assert_eq!(code.code(), *number, "{word}: its number");
        assert_eq!(RefusalCode::ALL[i], *code, "{word}: its place");
        assert_eq!(RefusalCode::of(*number), Some(*code), "{word}: the reverse");
        if matches!(
            code,
            RefusalCode::OverdraftCeiling | RefusalCode::StaleSlice
        ) {
            // A kernel-only money verdict: pinned on the wire, never decoded from a plane.
            assert_eq!(reason_of(*number), None, "{word}: no plane carries it");
            continue;
        }
        let reason = reason_of(*number).expect("a pinned code names a reason");
        assert_eq!(reason.as_str(), *word, "code {number}");
        assert_eq!(reason_code(reason), *number);
    }
    assert_eq!(RefusalCode::of(PINNED.len() as u32), None);
    assert_eq!(reason_of(u32::MAX), None);
    // Every reason in the kernel's vocabulary has a wire code, and none shares one.
    for (i, r) in ReasonCode::ALL.iter().enumerate() {
        let c = reason_code(*r);
        assert!(
            ReasonCode::ALL[..i].iter().all(|o| reason_code(*o) != c),
            "{r:?}"
        );
    }
}

// ── project ──

struct Host {
    signals: [SignalEntry; 2],
    arena: [u8; 16],
}

fn host() -> Host {
    Host {
        signals: z(),
        arena: [0; 16],
    }
}

fn arena_str(h: &Host, offset: usize, len: usize) -> AbiStr {
    AbiStr {
        ptr: h.arena.as_ptr().wrapping_add(offset),
        len,
    }
}

fn view(h: &Host, written: usize) -> ProjectOut {
    let mut o: ProjectOut = z();
    o.view.signals = h.signals.as_ptr();
    o.view.signals_len = written;
    o.view.pool = arena_str(h, 0, 4);
    o.view.ingress_dialect = arena_str(h, 4, 4);
    o.body = sp(8, 8);
    o.arena_written = 16;
    o
}

fn project(outcome: Outcome, h: &Host, o: &ProjectOut) -> Result<(), Fault> {
    check_project(outcome, o, &h.signals, 2, (h.arena.as_ptr(), 16))
}

#[test]
fn a_projected_view_inside_the_hosts_buffers_is_green() {
    let h = host();
    assert_eq!(project(Ready, &h, &view(&h, 2)), Ok(()));
    let mut o = view(&h, 0);
    o.body = sp(SPAN_ABSENT, 0);
    assert_eq!(project(Ready, &h, &o), Ok(()), "no projected body");
}

#[test]
fn project_follows_the_multi_buffer_short_rule() {
    let h = host();
    let mut o: ProjectOut = z();
    o.signals_needed = 3;
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::NeededNotFailed, "project.signals")
    );
    assert_eq!(project(Failed, &h, &o), Ok(()), "the short answer");
    o.arena_needed = 16;
    assert_eq!(
        project(Failed, &h, &o),
        Ok(()),
        "one dimension short, the other fitting at its full size"
    );
    o.signals_needed = 2;
    assert_eq!(project(Failed, &h, &o), f(Rule::WastedRecall, "project"));
    let mut o: ProjectOut = z();
    o.signals_needed = MAX_SIGNALS as u32 + 1;
    assert_eq!(project(Failed, &h, &o), f(Rule::OverMax, "project.signals"));
    let mut o: ProjectOut = z();
    o.arena_needed = 17;
    o.arena_written = 1;
    assert_eq!(project(Failed, &h, &o), f(Rule::WrittenOnShort, "project"));
}

#[test]
fn projected_signals_are_the_hosts_buffer() {
    let h = host();
    let other: [SignalEntry; 2] = z();
    let mut o = view(&h, 1);
    o.view.signals = other.as_ptr();
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::Foreign, "project.view.signals")
    );
}

#[test]
fn projected_view_flags_are_known() {
    let h = host();
    let mut o = view(&h, 0);
    o.view.flags = 1 << 3;
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::UnknownCode, "project.view.flags")
    );
}

#[test]
fn projected_strings_lie_inside_the_arena_written() {
    let h = host();
    let mut o = view(&h, 0);
    o.view.pool = arena_str(&h, 12, 8);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.view.pool")
    );
    let mut o = view(&h, 0);
    o.view.pool = AbiStr {
        ptr: h.arena.as_ptr().wrapping_sub(4),
        len: 4,
    };
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.view.pool"),
        "a string before the arena"
    );
    let mut o = view(&h, 0);
    o.arena_written = 6;
    o.body = sp(SPAN_ABSENT, 0);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.view.ingress_dialect")
    );
}

#[test]
fn a_projected_body_lies_inside_the_arena_written() {
    let h = host();
    let mut o = view(&h, 0);
    o.body = sp(12, 8);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.body")
    );
    o.body = sp(SPAN_ABSENT, 1);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanNotAbsent, "project.body")
    );
}

#[test]
fn a_projected_signal_has_a_known_id_and_tag() {
    let mut h = host();
    h.signals[0].id = crate::abi::hook::signal::RESPONSE_TOKENS_OUT + 1;
    let o = view(&h, 1);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::UnknownCode, "project.signal.id")
    );
    let mut h = host();
    h.signals[1].tag = SIGNAL_TAG_BOOL + 1;
    let o = view(&h, 2);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::UnknownCode, "project.signal.tag")
    );
}

#[test]
fn a_projected_signal_value_is_valid_for_its_tag() {
    let mut h = host();
    h.signals[0].tag = SIGNAL_TAG_STR;
    h.signals[0].value = SignalValue {
        str_: arena_str(&h, 14, 4),
    };
    let o = view(&h, 1);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.signal.value")
    );
    let mut h = host();
    h.signals[0].tag = SIGNAL_TAG_BOOL;
    h.signals[0].value = SignalValue { boolean: 2 };
    let o = view(&h, 1);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::UnknownCode, "project.signal.value")
    );
    h.signals[0].value = SignalValue { boolean: 1 };
    let o = view(&h, 1);
    assert_eq!(project(Ready, &h, &o), Ok(()));
}

// ── drive ──

#[test]
fn drive_names_its_ready_sessions_under_the_short_buffer_rule() {
    let mut o: PlaneDriveOut = z();
    o.sessions_written = 4;
    assert_eq!(check_drive(Ready, &o, 4), Ok(()));
    assert_eq!(
        check_drive(Ready, &o, 3),
        f(Rule::OverCap, "drive.sessions")
    );
    let mut o: PlaneDriveOut = z();
    o.sessions_needed = 5;
    assert_eq!(check_drive(Failed, &o, 4), Ok(()), "the short answer");
    assert_eq!(
        check_drive(Ready, &o, 4),
        f(Rule::NeededNotFailed, "drive.sessions")
    );
    o.sessions_needed = 4;
    assert_eq!(
        check_drive(Failed, &o, 4),
        f(Rule::WastedRecall, "drive.sessions")
    );
    o.sessions_needed = MAX_SESSIONS as u32 + 1;
    assert_eq!(
        check_drive(Failed, &o, 4),
        f(Rule::OverMax, "drive.sessions")
    );
}

/// RED (ARCHITECT ruling 2026-10-01, a money invariant): the overdraft ceiling and a stale slice
/// are kernel-only money verdicts. A plane that names either code is answering malformed, never
/// carrying the verdict: its tail row is refused, and the code decodes to no reason.
#[test]
fn a_plane_naming_a_kernel_money_verdict_is_malformed_not_the_verdict() {
    for reason in [ReasonCode::OverdraftCeiling, ReasonCode::StaleSlice] {
        let code = reason_code(reason);
        assert_eq!(reason_of(code), None, "{reason:?} decodes from no plane");
        let row = RefusalStatus {
            dialect: REFUSAL_ANY_DIALECT,
            reason: code,
            status: 402,
            _reserved: 0,
        };
        assert_eq!(
            check_refusal_statuses(&[row], 1),
            f(Rule::UnknownCode, "refusal_status.reason"),
            "{reason:?}: a tail row naming it is malformed"
        );
    }
}
