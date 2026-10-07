// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the plane answer validators: one per rule and arm, each failing if its check is
//! removed.

use std::mem::zeroed;
use std::ptr::null;

use super::*;
use crate::abi::hook::{MessageView, SignalEntry, SignalValue, SIGNAL_TAG_BOOL, SIGNAL_TAG_STR};
use crate::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, KEEP_ALL_EXCEPT_DENIED, KEEP_NAMED, KEEP_RESPONSE_HEADERS_MAX,
};
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready, Refused};
use crate::abi::mechanism::call::{AbiStr, Blob, MAX_TEXT};
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
    // ONE BILLING COUNT per class: a floor beside a reported count of the same class is two bills
    // of one thing, refused; a floor beside an estimate is not.
    v.class = 1;
    v.source = UNITS_FLOOR;
    assert_eq!(
        check_arrive(Ready, &o, &[u, v], 4, &bounds()),
        f(Rule::Contradiction, "unit.class")
    );
    u.source = UNITS_ESTIMATED;
    assert_eq!(check_arrive(Ready, &o, &[u, v], 4, &bounds()), Ok(()));
}

/// THE USAGE FLOOR (Q24/Q28): a floor count is a known source and bills like a reported one; an
/// estimate never bills, and no other value is a source.
#[test]
fn a_floor_count_is_a_known_source_that_bills() {
    let mut o: ArriveOut = z();
    o.units_written = 1;
    let mut u: UnitCount = z();
    u.class = 1;
    u.source = UNITS_FLOOR;
    u.amount = 51;
    assert_eq!(check_arrive(Ready, &o, &[u], 4, &bounds()), Ok(()));
    assert!(units_bill(UNITS_FLOOR));
    assert!(units_bill(UNITS_REPORTED));
    assert!(!units_bill(UNITS_ESTIMATED));
    assert!(!units_bill(UNITS_FLOOR + 1));
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

/// THE POOL AN ARRIVAL NAMES (ARCHITECT Q-SW6, 2026-10-02): the entry name inside the plane's own
/// section, on a READY answer only. Absent is valid (the plane's single default entry); a length
/// with no bytes is FAULT, a failed arrival naming a pool is a contradiction, and a refused one may
/// name the entry its refusal is about (ARCHITECT Q-DEL-A2A-GATE).
#[test]
fn an_arrival_names_its_pool_only_when_ready_and_only_with_bytes() {
    let mut o: ArriveOut = z();
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()), "absent");
    o.pool = s("entry");
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()), "named");
    let long = "p".repeat(crate::abi::mechanism::call::MAX_TEXT + 1);
    o.pool = AbiStr {
        ptr: long.as_ptr(),
        len: long.len(),
    };
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::OverMax, "arrive.pool")
    );
    o.pool = AbiStr {
        ptr: null(),
        len: 5,
    };
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::NullWithCount, "arrive.pool")
    );
    // A REFUSED arrival may name the entry its refusal is about (rule 6, ARCHITECT
    // Q-DEL-A2A-GATE): held past the caller's grant, never charged.
    let mut o: ArriveOut = z();
    o.refusal = 3;
    o.refusal_status = 404;
    o.pool = s("entry");
    assert_eq!(check_arrive(Refused, &o, &[], 4, &bounds()), Ok(()));
    let mut o: ArriveOut = z();
    o.pool = s("entry");
    assert_eq!(
        check_arrive(Failed, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.pool")
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
    o.refusal = 1;
    o.refusal_status = 400;
    o.head.error = text(&at_cap);
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        Ok(()),
        "at the cap"
    );
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
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        Ok(()),
        "not judged on READY"
    );
    let mut o: ArriveOut = z();
    o.refusal = 1;
    o.refusal_status = 400;
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
    const {
        assert!(MAX_REFUSAL_TEXT >= LARGEST_ADMITTED_FIELD_LINE + 1024);
    }
    let mut o: ArriveOut = z();
    o.refusal = 1;
    o.refusal_status = 400;
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
    u.source = UNITS_FLOOR + 1;
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

/// RED (SEAM-4l additions): THE MESSAGE BOUNDARY is a known bit, valid on an answer toward the
/// caller with bytes or without, never on a request bound for the far end.
#[test]
fn a_message_boundary_ends_a_message_toward_the_caller_only() {
    let mut o: OnPieceOut = z();
    o.flags = EMIT_MESSAGE_END;
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()), "a boundary alone");
    o.emitted = 3;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        Ok(()),
        "with the message's last bytes"
    );
    o.flags |= EMIT_TO_FAR_END;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.message_end_to_far_end")
    );
}

/// RED (SEAM-4l additions): THE FINAL STATUS closes the reply (`EMIT_DONE`), its message and details
/// inside the arena written; its fields are zero unless it is flagged.
#[test]
fn a_final_status_closes_the_reply_inside_the_arena() {
    let at = |offset: u32, len: u32| crate::abi::mechanism::call::Span { offset, len };
    let mut o: OnPieceOut = z();
    o.flags = EMIT_DONE | EMIT_FINAL_STATUS;
    o.final_status = 5;
    o.arena_written = 10;
    o.final_message = at(0, 8);
    o.final_details = at(8, 2);
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    let mut open = o;
    open.flags = EMIT_FINAL_STATUS;
    assert_eq!(
        piece(&open, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.final_status_not_closing")
    );
    let mut far = o;
    far.flags |= EMIT_TO_FAR_END;
    assert_eq!(
        piece(&far, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.final_status_not_closing")
    );
    let mut outside = o;
    outside.final_details = at(9, 2);
    assert!(
        piece(&outside, &[], &[], &[]).is_err(),
        "details past the arena"
    );
    let mut unflagged = o;
    unflagged.flags = EMIT_DONE;
    assert_eq!(
        piece(&unflagged, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.final_status_unflagged")
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
        PIECE_FIELDS,
        PIECE_CATALOGUE_MOVED,
        PIECE_CUT,
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

/// THE CUT (ARCHITECT RULING U11 Q1 2026-10-06): `PIECE_CUT` is a known `OnPieceIn::flags` bit,
/// valid only on the far end's last piece; a cut on any other piece, a bit the contract does not
/// define and an unknown `from` are FAULT (RED arms).
#[test]
fn a_cut_is_known_and_only_ends_the_far_ends_answer() {
    assert_eq!(check_piece_in(FROM_FAR_END, PIECE_CUT | PIECE_LAST), Ok(()));
    assert_eq!(
        check_piece_in(FROM_FAR_END, PIECE_CUT | PIECE_LAST | PIECE_HAS_STATUS),
        Ok(()),
        "a cut head"
    );
    for flags in [
        0,
        PIECE_LAST,
        PIECE_END_OF_FRAME | PIECE_HAS_STATUS,
        PIECE_FIELDS,
        PIECE_CATALOGUE_MOVED,
    ] {
        assert_eq!(check_piece_in(FROM_FAR_END, flags), Ok(()), "{flags}");
    }
    assert_eq!(
        check_piece_in(FROM_FAR_END, PIECE_CUT),
        f(Rule::Contradiction, "on_piece_in.cut"),
        "a cut is the last piece"
    );
    for from in [FROM_CALLER, FROM_KERNEL] {
        assert_eq!(
            check_piece_in(from, PIECE_CUT | PIECE_LAST),
            f(Rule::Contradiction, "on_piece_in.cut"),
            "{from}: only the far end is cut"
        );
    }
    assert_eq!(
        check_piece_in(FROM_FAR_END, PIECE_CUT << 1),
        f(Rule::UnknownCode, "on_piece_in.flags")
    );
    assert_eq!(
        check_piece_in(3, PIECE_LAST),
        f(Rule::UnknownCode, "on_piece_in.from")
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
    r.op = 4;
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

/// SEAM-L(k), THE UNIT'S AUDIT RECORD: a [`RECORD_AUDIT`] write names the row's outcome where a
/// put names its kind (so it needs no record kind of the plane's: here a tail with none), its
/// action in `key` (never empty) and its resource in `value`, both inside the arena. RED: every
/// write but a put was FAULT, and its outcome was judged as a record kind.
#[test]
fn an_audit_record_names_its_outcome_and_action() {
    let mut o: OnPieceOut = z();
    o.records_written = 1;
    o.arena_written = 8;
    let mut r: RecordWrite = z();
    r.op = RECORD_AUDIT;
    r.key = sp(0, 4);
    r.value = sp(4, 4);
    let none = Bounds {
        record_kinds: 0,
        ..bounds()
    };
    for outcome in [AUDIT_APPLIED, AUDIT_REJECTED, AUDIT_DEGRADED] {
        r.kind = outcome;
        assert_eq!(
            check_on_piece(Ready, &o, (&[], &[r], &[]), &caps(), &none),
            Ok(()),
            "outcome {outcome}"
        );
    }
    for outcome in [AUDIT_NONE, AUDIT_DEGRADED + 1, u32::MAX] {
        r.kind = outcome;
        assert_eq!(
            piece(&o, &[], &[r], &[]),
            f(Rule::UnknownCode, "record.audit_outcome")
        );
    }
    r.kind = AUDIT_APPLIED;
    r.key = sp(0, 0);
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::Contradiction, "record.audit_without_action")
    );
    r.key = sp(6, 4);
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::SpanOutOfBounds, "record.key")
    );
    r.key = sp(0, 4);
    r.value = sp(6, 4);
    assert_eq!(
        piece(&o, &[], &[r], &[]),
        f(Rule::SpanOutOfBounds, "record.value")
    );
}

/// SEAM-L(j), THE UNIT'S LEDGER LANE: an answer may name the lane its units are priced under, in
/// the arena written, on any answer; none named is a zero length. RED: the answer had no lane.
#[test]
fn a_ledger_lane_rides_the_arena() {
    let mut o: OnPieceOut = z();
    o.arena_written = 8;
    o.lane = sp(2, 6);
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    o.lane = sp(4, 6);
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::SpanOutOfBounds, "on_piece.lane")
    );
    o.lane = sp(SPAN_ABSENT, 1);
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::SpanNotAbsent, "on_piece.lane")
    );
    o.lane = sp(0, 0);
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
}

/// SEAM-L(o), A REFUSAL'S RECORD WRITES: judged as an `on_piece` answer's, under the short-buffer
/// rule over the host's `records_buf`: an audit row inside the arena passes; a write past the cap,
/// an unknown op or a span outside the arena is FAULT. RED: a refusal had no record slot.
#[test]
fn a_refusals_record_writes_are_judged_as_an_answers() {
    let mut o: RefusalOut = z();
    o.records_written = 1;
    o.arena_written = 8;
    let mut r: RecordWrite = z();
    r.op = RECORD_AUDIT;
    r.kind = AUDIT_REJECTED;
    r.key = sp(0, 4);
    r.value = sp(4, 4);
    assert_eq!(check_refusal_records(Ready, &o, &[r], 1, &bounds()), Ok(()));
    assert_eq!(
        check_refusal_records(Ready, &o, &[r], 0, &bounds()),
        f(Rule::OverCap, "refusal.records")
    );
    let mut bad = r;
    bad.op = 4;
    assert_eq!(
        check_refusal_records(Ready, &o, &[bad], 1, &bounds()),
        f(Rule::UnknownCode, "record.op")
    );
    let mut bad = r;
    bad.value = sp(6, 4);
    assert_eq!(
        check_refusal_records(Ready, &o, &[bad], 1, &bounds()),
        f(Rule::SpanOutOfBounds, "record.value")
    );
    let none: RefusalOut = z();
    assert_eq!(
        check_refusal_records(Ready, &none, &[], 0, &bounds()),
        Ok(())
    );
}

/// SEAM-L(t), A SERVED REQUEST'S RECORD WRITES: judged as an answer's: a put of a declared kind
/// inside the arena passes; a short buffer is a short answer; a kind past the tail is FAULT. RED: a
/// served request had no record slot.
#[test]
fn a_served_requests_record_writes_are_judged_as_an_answers() {
    let mut o: ServeOut = z();
    o.records_written = 1;
    o.arena_written = 8;
    let mut r: RecordWrite = z();
    r.op = RECORD_PUT;
    r.key = sp(0, 4);
    r.value = sp(4, 4);
    assert_eq!(check_serve_records(Ready, &o, &[r], 1, &bounds()), Ok(()));
    let mut bad = r;
    bad.kind = 1;
    assert_eq!(
        check_serve_records(Ready, &o, &[bad], 1, &bounds()),
        f(Rule::IndexOutOfRange, "record.kind")
    );
    let mut short: ServeOut = z();
    short.records_needed = 2;
    assert_eq!(
        check_serve_records(Failed, &short, &[], 1, &bounds()),
        Ok(())
    );
    assert_eq!(
        check_serve_records(Ready, &short, &[], 1, &bounds()),
        f(Rule::NeededNotFailed, "serve.records")
    );
}

/// SEAM-L(r), A CANCEL'S RECORD WRITES: never re-called, so they fit the host's buffers or the
/// answer is FAULT; each is judged as an answer's; a `cancel` that is not READY writes none. RED: a
/// cancel had no record slot.
#[test]
fn a_cancels_record_writes_fit_and_are_judged_as_an_answers() {
    let mut o: PlaneCancelOut = z();
    o.records_written = 1;
    o.arena_written = 8;
    let mut r: RecordWrite = z();
    r.op = RECORD_AUDIT;
    r.kind = AUDIT_APPLIED;
    r.key = sp(0, 4);
    r.value = sp(4, 4);
    assert_eq!(
        check_cancel_records(Ready, &o, &[r], (1, 8), &bounds()),
        Ok(())
    );
    assert_eq!(
        check_cancel_records(Ready, &o, &[r], (0, 8), &bounds()),
        f(Rule::OverCap, "cancel.records")
    );
    assert_eq!(
        check_cancel_records(Ready, &o, &[r], (1, 4), &bounds()),
        f(Rule::OverCap, "cancel.arena")
    );
    assert_eq!(
        check_cancel_records(Failed, &o, &[r], (1, 8), &bounds()),
        f(Rule::Contradiction, "cancel.records_not_ready")
    );
    let mut bad = r;
    bad.op = 4;
    assert_eq!(
        check_cancel_records(Ready, &o, &[bad], (1, 8), &bounds()),
        f(Rule::UnknownCode, "record.op")
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
fn a_serve_audit_is_one_of_the_three() {
    let mut o: ServeOut = z();
    for a in [AUDIT_NONE, AUDIT_APPLIED, AUDIT_REJECTED] {
        o.audit = a;
        assert_eq!(check_serve(Ready, &o, &[], &caps()), Ok(()));
    }
    o.audit = AUDIT_REJECTED + 1;
    assert_eq!(
        check_serve(Ready, &o, &[], &caps()),
        f(Rule::UnknownCode, "serve.audit")
    );
}

/// THE LISTING RENDER'S `in` (ARCHITECT RULING D, 2026-10-07): a listing is one JSON payload under
/// the blob rule on route `u32::MAX`; every other `serve` carries no listing and names a route.
/// One RED arm per rule.
#[test]
fn a_serve_in_listing_is_json_on_the_listing_route_alone() {
    use crate::abi::mechanism::call::{BLOB_JSON, BLOB_JSONL, BLOB_OCTETS};
    let names = br#"["pool-a","model-a0"]"#;
    let json = Blob {
        ptr: names.as_ptr(),
        len: names.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    // GREEN: an admin route with no listing; a listing on the listing route.
    assert_eq!(check_serve_in(0, &Blob::ABSENT), Ok(()));
    assert_eq!(check_serve_in(u32::MAX, &json), Ok(()));
    // An empty list is still a listing.
    let empty = b"[]";
    let none_listed = Blob {
        ptr: empty.as_ptr(),
        len: empty.len(),
        ..json
    };
    assert_eq!(check_serve_in(u32::MAX, &none_listed), Ok(()));
    // RED: the listing route with no listing.
    assert_eq!(
        check_serve_in(u32::MAX, &Blob::ABSENT),
        f(Rule::Missing, "serve_in.listing")
    );
    // RED: a listing that names an admin route.
    assert_eq!(
        check_serve_in(0, &json),
        f(Rule::Contradiction, "serve_in.route")
    );
    // RED: an absent listing that still points at bytes.
    let stray = Blob {
        fmt: BLOB_ABSENT,
        ..json
    };
    assert_eq!(
        check_serve_in(0, &stray),
        f(Rule::Contradiction, "serve_in.listing")
    );
    // RED: a format other than JSON.
    for fmt in [BLOB_JSONL, BLOB_OCTETS, 99] {
        assert_eq!(
            check_serve_in(u32::MAX, &Blob { fmt, ..json }),
            f(Rule::UnknownCode, "serve_in.listing.fmt")
        );
    }
    // RED: a counted listing behind NULL.
    let null_bytes = Blob {
        ptr: null(),
        ..json
    };
    assert_eq!(
        check_serve_in(u32::MAX, &null_bytes),
        f(Rule::NullWithCount, "serve_in.listing.ptr")
    );
}

/// A listing's bytes read as the kernel's names, in order; anything but a JSON array of strings is
/// FAULT (RED arms).
#[test]
fn a_serve_in_listing_reads_as_an_array_of_names() {
    assert_eq!(
        listing_names(br#"["pool-a","model-a0"]"#),
        Ok(vec!["pool-a".to_string(), "model-a0".to_string()])
    );
    assert_eq!(listing_names(b"[]"), Ok(Vec::new()));
    for bad in [&b"{}"[..], b"[1]", b"\"pool-a\"", b"", b"[\"a\""] {
        assert_eq!(
            listing_names(bad).map(|_| ()),
            f(Rule::Contradiction, "serve_in.listing.names"),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// THE PUBLIC ROUTE'S AUTH SCHEME (ARCHITECT Q2 webhook receiver, 2026-10-06): a public route may
/// name the scheme its callers are verified under; a scheme on an admin route, one counted with no
/// bytes and one past the text bound are FAULT (RED arms).
#[test]
fn a_public_routes_style_is_bounded_text_on_a_public_route_alone() {
    let style = "webhook-signature";
    let mut r = AdminRoute {
        verb: s("POST"),
        target: s("/webhooks/sender"),
        flags: ROUTE_PUBLIC,
        _reserved: 0,
        audit_verb: z(),
        style: s(style),
    };
    assert_eq!(check_admin_routes(&[r]), Ok(()));
    r.flags = 0;
    assert_eq!(
        check_admin_routes(&[r]),
        f(Rule::Contradiction, "admin_route.style"),
        "an admin route is the admin chain's"
    );
    r.flags = ROUTE_PUBLIC;
    r.style = AbiStr {
        ptr: null(),
        len: 3,
    };
    assert_eq!(
        check_admin_routes(&[r]),
        f(Rule::NullWithCount, "admin_route.style")
    );
    let long = "s".repeat(MAX_TEXT + 1);
    r.style = AbiStr {
        ptr: long.as_ptr(),
        len: long.len(),
    };
    assert_eq!(
        check_admin_routes(&[r]),
        f(Rule::OverMax, "admin_route.style")
    );
}

#[test]
fn an_admin_route_audit_verb_is_text_or_empty() {
    let mut r = AdminRoute {
        verb: s("POST"),
        target: s("/t"),
        flags: 0,
        _reserved: 0,
        audit_verb: s("connect"),
        style: z(),
    };
    assert_eq!(check_admin_routes(&[r]), Ok(()));
    r.audit_verb = z();
    assert_eq!(check_admin_routes(&[r]), Ok(()));
    r.audit_verb.len = 1;
    assert_eq!(
        check_admin_routes(&[r]),
        f(Rule::NullWithCount, "admin_route.audit_verb")
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
        inbound_style: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        path_form: 0,
        _form_reserved: 0,
    }
}

/// A CLAIM'S PATH FORM IS THE ONE ROUTE VOCABULARY'S (spec, the design's connections): `0` leaves the
/// flags to decide; any `abi::transport` form stands alone; a number outside it, or a form beside a
/// target flag, is refused.
#[test]
fn a_claims_path_form_is_the_one_route_vocabularys() {
    use crate::abi::transport::route::{PATH_CONTAINS, PATH_EXACT, PATH_SUFFIX};
    for form in [0, PATH_EXACT, PATH_SUFFIX, PATH_CONTAINS] {
        let mut c = claim("V", "/v1/messages", 0);
        c.path_form = form;
        assert_eq!(check_claims(&[c], 1), Ok(()), "form {form}");
    }
    let mut c = claim("V", "/v1/messages", 0);
    c.path_form = PATH_CONTAINS + 1;
    assert_eq!(
        check_claims(&[c], 1),
        f(Rule::UnknownCode, "claim.path_form")
    );
    for flag in [CLAIM_EXACT, CLAIM_PATTERN] {
        let mut c = claim("V", "/v1/messages", flag);
        c.path_form = PATH_SUFFIX;
        assert_eq!(
            check_claims(&[c], 1),
            f(Rule::Contradiction, "claim.path_form"),
            "flag {flag}"
        );
    }
}

/// THE INBOUND STYLE A CLAIM STATES (spec, the design's connections): absent, or a string; a length
/// with a NULL pointer is refused, as every other string of the snapshot is.
#[test]
fn a_claims_inbound_style_is_absent_or_a_string() {
    let mut c = claim("V", "/t", CLAIM_EXACT);
    assert_eq!(check_claims(&[c], 1), Ok(()));
    c.inbound_style = s(STYLE_REQUEST_SIGNATURE);
    assert_eq!(check_claims(&[c], 1), Ok(()));
    c.inbound_style = AbiStr {
        ptr: std::ptr::null(),
        len: 3,
    };
    assert_eq!(
        check_claims(&[c], 1),
        f(Rule::NullWithCount, "claim.inbound_style")
    );
}

#[test]
fn a_claim_states_only_known_flags() {
    let open_exact = claim("V", "/t", CLAIM_OPEN | CLAIM_EXACT);
    assert_eq!(check_claims(&[open_exact], 1), Ok(()));
    // RED: a bit none of CLAIM_OPEN, CLAIM_EXACT, CLAIM_PATTERN.
    let unknown = claim("V", "/t", CLAIM_PATTERN << 1);
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

/// A test keeps a pattern's segments for the process.
fn kept(segments: Vec<crate::grammar::PathSeg>) -> &'static [crate::grammar::PathSeg] {
    Box::leak(segments.into_boxed_slice())
}

#[test]
fn a_pattern_claim_is_never_also_exact() {
    let pattern = claim("V", "/t/{id}", CLAIM_OPEN | CLAIM_PATTERN);
    assert_eq!(check_claims(&[pattern], 1), Ok(()));
    let both = claim("V", "/t/{id}", CLAIM_EXACT | CLAIM_PATTERN);
    assert_eq!(
        check_claims(&[both], 1),
        f(Rule::Contradiction, "claim.flags")
    );
    assert_eq!(
        claim_selector("/t/{id}", CLAIM_EXACT | CLAIM_PATTERN, kept).map(|_| ()),
        f(Rule::Contradiction, "claim.flags")
    );
}

#[test]
fn a_pattern_target_parses_into_literals_and_one_level_placeholders() {
    use crate::grammar::PathSeg::{Lit, Var};
    assert_eq!(
        claim_pattern("/v1/tasks/{id}/configs/{config_id}"),
        Ok(vec![Lit("v1"), Lit("tasks"), Var, Lit("configs"), Var])
    );
    for bad in [
        "t/{id}", "/t//{id}", "/t/{}", "/t/{id", "/t/id}", "/t/{i}d}", "/t/{id}/",
    ] {
        assert_eq!(
            claim_pattern(bad).map(|_| ()),
            f(Rule::Contradiction, "claim.pattern"),
            "{bad}"
        );
    }
    assert_eq!(
        claim_pattern("/t/id").map(|_| ()),
        f(Rule::Missing, "claim.pattern")
    );
}

/// RED: a malformed pattern is refused AT BIND, by the same grammar the selector reads, so a bad
/// claim never waits for its first route.
#[test]
fn a_malformed_pattern_is_refused_at_bind_by_the_selectors_grammar() {
    for bad in [
        "t/{id}", "/t//{id}", "/t/{}", "/t/{id", "/t/id}", "/t/{i}d}", "/t/{id}/",
    ] {
        let at_bind = check_claim_target(bad, CLAIM_PATTERN);
        assert_eq!(at_bind, f(Rule::Contradiction, "claim.pattern"), "{bad}");
        assert_eq!(
            at_bind,
            claim_selector(bad, CLAIM_PATTERN, kept).map(|_| ()),
            "{bad}"
        );
    }
    assert_eq!(
        check_claim_target("/t/id", CLAIM_PATTERN),
        f(Rule::Missing, "claim.pattern")
    );
    assert_eq!(
        check_claim_target("/t/{id}", CLAIM_EXACT | CLAIM_PATTERN),
        f(Rule::Contradiction, "claim.flags")
    );
    assert_eq!(check_claim_target("/t/{id}", CLAIM_PATTERN), Ok(()));
    assert_eq!(check_claim_target("/t/{id}", CLAIM_EXACT), Ok(()));
}

#[test]
fn a_claim_reads_as_the_grammars_selector_by_its_flags() {
    use crate::grammar::{PathSeg, Selector};
    assert_eq!(
        claim_selector("/t", CLAIM_EXACT, kept),
        Ok(Selector::ExactPath("/t"))
    );
    assert_eq!(
        claim_selector("/t", CLAIM_OPEN, kept),
        Ok(Selector::PrefixOneLevel("/t"))
    );
    assert_eq!(
        claim_selector("/t/{id}", CLAIM_PATTERN, kept),
        Ok(Selector::PathPattern(&[PathSeg::Lit("t"), PathSeg::Var]))
    );
}

/// RED: a placeholder claims ONE level, non-empty, with no `/`.
#[test]
fn a_pattern_claims_one_level_only() {
    let Ok(crate::grammar::Selector::PathPattern(p)) =
        claim_selector("/v1/tasks/{id}", CLAIM_PATTERN, kept)
    else {
        panic!("a pattern claim reads as a segment pattern");
    };
    assert!(crate::grammar::pattern_matches(p, "/v1/tasks/t1"));
    assert!(!crate::grammar::pattern_matches(p, "/v1/tasks/t1/x"));
    assert!(!crate::grammar::pattern_matches(p, "/v1/tasks/"));
    assert!(!crate::grammar::pattern_matches(p, "/v1/tasks"));
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
        audit_verb: z(),
        style: z(),
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
    // The first bit past the last one a tail may state (`TAIL_HOOKS_GATED`, bit 2, is known).
    let mut t = tail();
    t.flags = TAIL_HOOKS_GATED << 1;
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
        params: Blob::ABSENT,
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
    ); // The style's parameters: a JSON object, a counted blob never NULL.
    const PARAMS: &[u8] = br#"{"service":"s"}"#;
    let mut with = d;
    with.params = Blob {
        ptr: PARAMS.as_ptr(),
        len: PARAMS.len(),
        fmt: crate::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    };
    assert_eq!(check_dialect_auth(&[with], 1), Ok(()));
    let mut octets = with;
    octets.params.fmt = crate::abi::mechanism::call::BLOB_OCTETS;
    assert_eq!(
        check_dialect_auth(&[octets], 1),
        f(Rule::Contradiction, "dialect_auth.params.fmt")
    );
    let mut dangling = with;
    dangling.params.ptr = null();
    assert_eq!(
        check_dialect_auth(&[dangling], 1),
        f(Rule::NullWithCount, "dialect_auth.params")
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

/// RED for the keep mode (OWNER ruling 2026-10-02, dialect fidelity F2): a need keeps either the
/// fields it names or every field but the ones it denies, never both lists, and no other mode.
/// Denied names are lower-case tokens, bounded; denying a credential name is allowed.
#[test]
fn a_need_keeps_named_fields_or_all_but_denied_ones_and_nothing_else() {
    let mut n: Need = z();
    n.direction = DIRECTION_OUTBOUND;
    n.transport = s("t");
    n.keep_mode = KEEP_ALL_EXCEPT_DENIED;
    let denied = [
        s("openai-organization"),
        s("openai-project"),
        s("set-cookie"),
    ];
    n.deny_response_headers = denied.as_ptr();
    n.deny_response_headers_len = denied.len();
    assert_eq!(check_needs(&[n]), Ok(()));
    let mut none = n;
    none.deny_response_headers = null();
    none.deny_response_headers_len = 0;
    assert_eq!(check_needs(&[none]), Ok(()), "an empty deny list");

    let kept = [s("retry-after")];
    let mut both = n;
    both.keep_response_headers = kept.as_ptr();
    both.keep_response_headers_len = 1;
    assert_eq!(
        check_needs(&[both]),
        f(Rule::Contradiction, "need.keep_response_headers")
    );
    let mut named = both;
    named.keep_mode = KEEP_NAMED;
    assert_eq!(
        check_needs(&[named]),
        f(Rule::Contradiction, "need.deny_response_headers")
    );
    let mut unknown = none;
    unknown.keep_mode = 2;
    assert_eq!(
        check_needs(&[unknown]),
        f(Rule::UnknownCode, "need.keep_mode")
    );
    let mut padded = none;
    padded._reserved = 1;
    assert_eq!(
        check_needs(&[padded]),
        f(Rule::UnknownCode, "need._reserved")
    );

    let upper = [s("OpenAI-Project")];
    let mut b = n;
    b.deny_response_headers = upper.as_ptr();
    b.deny_response_headers_len = 1;
    assert_eq!(
        check_needs(&[b]),
        f(Rule::UnknownCode, "need.deny_response_headers")
    );
    let many: Vec<AbiStr> = (0..=KEEP_RESPONSE_HEADERS_MAX).map(|_| s("x")).collect();
    let mut b = n;
    b.deny_response_headers = many.as_ptr();
    b.deny_response_headers_len = many.len();
    assert_eq!(
        check_needs(&[b]),
        f(Rule::OverMax, "need.deny_response_headers")
    );
    let mut b = n;
    b.deny_response_headers = null();
    b.deny_response_headers_len = 1;
    assert_eq!(
        check_needs(&[b]),
        f(Rule::NullWithCount, "need.deny_response_headers")
    );
}

/// What crosses under each mode: the named fields (never a `NEVER_KEPT` one), or every field but
/// hop-by-hop, the connection's nominees, the re-derived framing and the plugin's denied names.
#[test]
fn a_response_field_crosses_by_the_needs_mode() {
    use crate::abi::host::conn::connector::keeps_response_field as keeps;
    let none: [&[u8]; 0] = [];
    assert!(keeps(
        KEEP_NAMED,
        &["retry-after"],
        &[],
        "retry-after",
        none
    ));
    assert!(!keeps(
        KEEP_NAMED,
        &["retry-after"],
        &[],
        "x-request-id",
        none
    ));
    assert!(!keeps(KEEP_NAMED, &["set-cookie"], &[], "set-cookie", none));
    let denied = ["openai-project"];
    for kept in [
        "x-request-id",
        "retry-after",
        "content-type",
        "anthropic-ratelimit-requests-limit",
    ] {
        assert!(
            keeps(KEEP_ALL_EXCEPT_DENIED, &[], &denied, kept, none),
            "{kept}"
        );
    }
    for stripped in [
        "openai-project",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
    ] {
        assert!(
            !keeps(KEEP_ALL_EXCEPT_DENIED, &[], &denied, stripped, none),
            "{stripped}"
        );
    }
    let nominated: [&[u8]; 1] = [b"x-hop, close"];
    assert!(!keeps(KEEP_ALL_EXCEPT_DENIED, &[], &[], "x-hop", nominated));
    assert!(
        !keeps(7, &["x"], &[], "x", none),
        "an unknown mode keeps nothing"
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

/// THE BREAKER FAULT READING (ARCHITECT 2026-10-05): one vocabulary with the transport's
/// (`FAULT_*`), separate from the verdict. RED arms: past `FAULT_HARD`, on an answer that is not
/// READY, and its padding not zero.
#[test]
fn a_fault_reading_is_the_transports_vocabulary_on_a_ready_answer() {
    use crate::abi::transport::{FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT};
    let mut o: OnPieceOut = z();
    for reading in [FAULT_NONE, FAULT_CALLER, FAULT_TRANSIENT, FAULT_HARD] {
        o.fault = reading;
        assert_eq!(piece(&o, &[], &[], &[]), Ok(()), "{reading}");
    }
    // Separate from the verdict: a retried answer that is the caller's own fault.
    o.verdict = VERDICT_RETRY;
    o.fault = FAULT_CALLER;
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    o.verdict = 0;
    o.fault = FAULT_HARD + 1;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::UnknownCode, "on_piece.fault")
    );
    o.fault = FAULT_TRANSIENT;
    assert_eq!(
        check_on_piece(Pending, &o, (&[], &[], &[]), &caps(), &bounds()),
        f(Rule::Contradiction, "on_piece.fault_not_ready")
    );
    o.fault = FAULT_NONE;
    o._fault_reserved = [0, 1, 0];
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.fault_reserved")
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

/// MULTI-NEED (ARCHITECT Q-L5B-NEEDS 2026-10-03): a far request may name the need it rides; a need
/// named on an answer that sends nothing to the far end contradicts it.
#[test]
fn a_named_need_rides_only_a_far_request() {
    let mut o = attempt_answer();
    o.need = 5;
    assert_eq!(piece(&o, &[], &[], &[]), Ok(()));
    let mut o: OnPieceOut = z();
    o.need = 1;
    assert_eq!(
        piece(&o, &[], &[], &[]),
        f(Rule::Contradiction, "on_piece.need_not_to_far_end")
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

/// A tail may state the gate-first hook order (`TAIL_HOOKS_GATED`); a flag past the known ones is
/// still unknown.
#[test]
fn a_tail_may_declare_the_gate_first_hook_order() {
    let mut t = tail();
    t.flags = TAIL_HOOKS_GATED;
    assert_eq!(check_tail(&t), Ok(()));
    t.flags = TAIL_HOOKS_GATED << 1;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.flags"));
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
        audit_verb: z(),
        style: z(),
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
fn a_tail_caller_credential_refusal_is_absent_or_a_sentence() {
    assert_eq!(check_tail(&tail()), Ok(()));
    let mut t = tail();
    t.caller_credential_refusal = s("refused here");
    assert_eq!(check_tail(&t), Ok(()));
    let mut t = tail();
    t.caller_credential_refusal = s("");
    assert_eq!(
        check_tail(&t),
        f(Rule::Missing, "tail.caller_credential_refusal")
    );
    let mut t = tail();
    t.caller_credential_refusal.len = 1;
    assert_eq!(
        check_tail(&t),
        f(Rule::NullWithCount, "tail.caller_credential_refusal")
    );
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

/// RED (SEAM-4f): a registration's private reach is a trust key of its own role: a boolean the
/// host reads, so it carries no flags, no mechanisms and no default (absent reads `false`).
#[test]
fn a_private_reach_key_carries_no_default_flags_or_mechanisms() {
    let reach = TrustKey {
        default: AbiStr {
            ptr: null(),
            len: 0,
        },
        ..duration_key(TRUST_PRIVATE_REACH)
    };
    assert_eq!(check_trust_keys(&[pin_key(), reach]), Ok(()));
    assert_eq!(
        check_trust_keys(&[duration_key(TRUST_PRIVATE_REACH)]),
        f(Rule::Contradiction, "trust_key.reach_default")
    );
    assert_eq!(
        check_trust_keys(&[TrustKey { flags: 1, ..reach }]),
        f(Rule::UnknownCode, "trust_key.duration_flags")
    );
    assert_eq!(
        check_trust_keys(&[TrustKey {
            mechanisms: MECHANISMS.as_ptr(),
            mechanisms_len: MECHANISMS.len(),
            ..reach
        }]),
        f(Rule::Contradiction, "trust_key.duration_mechanisms")
    );
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
    for role in [0, TRUST_PRIVATE_REACH + 1] {
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
    // The next number past the wire table (its codes are append-only, not dense).
    r.reason = RefusalCode::ALL
        .iter()
        .map(|c| c.code())
        .max()
        .expect("codes")
        + 1;
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
    m.flags = MECHANISM_PEER_KEY << 1;
    assert_eq!(
        check_pin_mechanisms(&[m]),
        f(Rule::UnknownCode, "pin_mechanism.flags")
    );
    // A far-end key pin is a root; the no-root spelling carrying one contradicts itself.
    let mut m = MECHANISMS[0];
    m.flags = MECHANISM_PEER_KEY;
    assert_eq!(
        check_pin_mechanisms(&[m]),
        f(Rule::Contradiction, "pin_mechanism.flags")
    );
    let mut m = MECHANISMS[0];
    m.flags = MECHANISM_ROOT | MECHANISM_PEER_KEY;
    assert_eq!(check_pin_mechanisms(&[m]), Ok(()));
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
    (43, RefusalCode::NoRoute, "no_route"),
    (44, RefusalCode::WrongMethod, "wrong_method"),
    (45, RefusalCode::HandlerPanic, "handler_panic"),
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
    // The next number past the table names no code (the table is append-only, not dense).
    let next = PINNED.iter().map(|(n, ..)| *n).max().expect("pins") + 1;
    assert_eq!(RefusalCode::of(next), None);
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
    messages: [MessageView; 2],
    arena: [u8; 16],
}

fn host() -> Host {
    Host {
        signals: z(),
        messages: z(),
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
    project_as(outcome, h, o, false)
}

/// [`project`], for a call that carried a rewrite (`rewrite`) or not.
fn project_as(outcome: Outcome, h: &Host, o: &ProjectOut, rewrite: bool) -> Result<(), Fault> {
    check_project(
        outcome,
        o,
        &ProjectHost {
            signals: &h.signals,
            signals_cap: 2,
            messages: &h.messages,
            messages_cap: 2,
            arena: (h.arena.as_ptr(), 16),
            rewrite,
        },
    )
}

/// A view whose prompt holds `turns` turns at the host's `messages_buf`, each naming arena bytes.
fn prompted(h: &mut Host, turns: usize) -> ProjectOut {
    for m in h.messages.iter_mut().take(turns) {
        *m = MessageView {
            role: AbiStr {
                ptr: h.arena.as_ptr(),
                len: 4,
            },
            text: AbiStr {
                ptr: h.arena.as_ptr().wrapping_add(4),
                len: 4,
            },
        };
    }
    let mut o = view(h, 0);
    o.prompt.system = arena_str(h, 0, 4);
    o.prompt.messages = h.messages.as_ptr();
    o.prompt.message_count = turns as u64;
    o.prompt.messages_len = turns;
    o.end_user = arena_str(h, 4, 4);
    o
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

/// THE SESSION (ARCHITECT RULING 2026-10-03, Q-FOLD-A2A-2-PROJECT-POOL session half): absent, or
/// flagless octets inside the arena written; anything else is FAULT, naming the field.
#[test]
fn a_projected_session_is_absent_or_octets_inside_the_arena_written() {
    use crate::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS};
    let h = host();
    let octets = |offset: usize, len: usize| Blob {
        ptr: h.arena.as_ptr().wrapping_add(offset),
        len,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let with = |b: Blob| {
        let mut o = view(&h, 0);
        o.view.session = b;
        o
    };
    assert_eq!(project(Ready, &h, &view(&h, 0)), Ok(()), "no session");
    assert_eq!(project(Ready, &h, &with(octets(8, 8))), Ok(()));
    assert_eq!(
        project(Ready, &h, &with(octets(12, 8))),
        f(Rule::SpanOutOfBounds, "project.view.session")
    );
    let before = Blob {
        ptr: h.arena.as_ptr().wrapping_sub(4),
        ..octets(0, 4)
    };
    assert_eq!(
        project(Ready, &h, &with(before)),
        f(Rule::SpanOutOfBounds, "project.view.session"),
        "a session before the arena"
    );
    assert_eq!(
        project(
            Ready,
            &h,
            &with(Blob {
                fmt: BLOB_JSON,
                ..octets(8, 4)
            })
        ),
        f(Rule::UnknownCode, "project.view.session")
    );
    assert_eq!(
        project(
            Ready,
            &h,
            &with(Blob {
                flags: 1,
                ..octets(8, 4)
            })
        ),
        f(Rule::UnknownCode, "project.view.session")
    );
    assert_eq!(
        project(
            Ready,
            &h,
            &with(Blob {
                ptr: std::ptr::null(),
                ..octets(0, 4)
            })
        ),
        f(Rule::NullWithCount, "project.view.session")
    );
    assert_eq!(
        project(
            Ready,
            &h,
            &with(Blob {
                fmt: BLOB_ABSENT,
                ..octets(8, 4)
            })
        ),
        f(Rule::Contradiction, "project.view.session"),
        "an absent session that names bytes"
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

#[test]
fn a_prompt_view_and_end_user_inside_the_hosts_buffers_are_green() {
    let mut h = host();
    let o = prompted(&mut h, 2);
    assert_eq!(project(Ready, &h, &o), Ok(()));
}

#[test]
fn projected_turns_follow_the_multi_buffer_short_rule() {
    let h = host();
    let mut o: ProjectOut = z();
    o.messages_needed = 3;
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::NeededNotFailed, "project.messages")
    );
    assert_eq!(project(Failed, &h, &o), Ok(()), "the short answer");
    o.messages_needed = MAX_TURNS as u32 + 1;
    assert_eq!(
        project(Failed, &h, &o),
        f(Rule::OverMax, "project.messages")
    );
    let mut h = host();
    let mut o = prompted(&mut h, 2);
    o.prompt.message_count = 3;
    o.prompt.messages_len = 3;
    assert_eq!(project(Ready, &h, &o), f(Rule::OverCap, "project.messages"));
}

#[test]
fn a_prompt_views_turn_count_and_its_list_length_agree() {
    let mut h = host();
    let mut o = prompted(&mut h, 2);
    o.prompt.messages_len = 1;
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::Contradiction, "project.prompt.messages_len")
    );
}

#[test]
fn projected_turns_are_the_hosts_buffer() {
    let mut h = host();
    let other: [MessageView; 2] = z();
    let mut o = prompted(&mut h, 1);
    o.prompt.messages = other.as_ptr();
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::Foreign, "project.prompt.messages")
    );
}

#[test]
fn a_projected_turn_and_the_prompt_strings_lie_inside_the_arena_written() {
    let mut h = host();
    let mut o = prompted(&mut h, 1);
    h.messages[0].role = arena_str(&h, 12, 8);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.message.role")
    );
    let mut h = host();
    o = prompted(&mut h, 1);
    h.messages[0].text = arena_str(&h, 14, 4);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.message.text")
    );
    let mut h = host();
    let mut o = prompted(&mut h, 0);
    o.prompt.system = arena_str(&h, 12, 8);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.prompt.system")
    );
    let mut o = prompted(&mut h, 0);
    o.end_user = arena_str(&h, 12, 8);
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::SpanOutOfBounds, "project.end_user")
    );
}

#[test]
fn the_prompt_view_carries_no_body_of_the_planes() {
    let h = host();
    let mut o = view(&h, 0);
    o.prompt.body = crate::abi::mechanism::call::Blob {
        ptr: h.arena.as_ptr(),
        len: 4,
        fmt: crate::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::Foreign, "project.prompt.body")
    );
}

#[test]
fn a_rewritten_body_answers_only_a_rewrite_and_lies_inside_the_arena_written() {
    let h = host();
    let mut o = view(&h, 0);
    o.rewritten = sp(8, 8);
    assert_eq!(
        project_as(Ready, &h, &o, true),
        Ok(()),
        "the rewrite applied"
    );
    assert_eq!(
        project(Ready, &h, &o),
        f(Rule::Contradiction, "project.rewritten_without_rewrite")
    );
    o.rewritten = sp(SPAN_ABSENT, 0);
    assert_eq!(project(Ready, &h, &o), Ok(()), "no rewrite, none applied");
    assert_eq!(
        project_as(Ready, &h, &o, true),
        Ok(()),
        "a rewrite the plane could not apply"
    );
    o.rewritten = sp(12, 8);
    assert_eq!(
        project_as(Ready, &h, &o, true),
        f(Rule::SpanOutOfBounds, "project.rewritten")
    );
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

/// THE ROUTE FLAGS (ARCHITECT round 4 Q-L3B-SURFACES (h) `ROUTE_ONCE`; round 5 Q-L3B-K6-HTTP (a)
/// `ROUTE_SESSION`): a READY arrival may state either or both, whatever it routes over; a bit the
/// contract does not define is FAULT, and an answer that admits nothing states none.
#[test]
fn an_arrivals_route_flags_are_once_and_session() {
    for flags in [
        ROUTE_ONCE,
        ROUTE_SESSION,
        ROUTE_STREAM,
        ROUTE_ONCE | ROUTE_SESSION,
        ROUTE_ONCE | ROUTE_STREAM,
        ROUTE_ONCE | ROUTE_SESSION | ROUTE_STREAM,
    ] {
        let mut o: ArriveOut = z();
        o.route = ROUTE_LOCAL;
        o.route_flags = flags;
        assert_eq!(
            check_arrive(Ready, &o, &[], 4, &bounds()),
            Ok(()),
            "{flags}"
        );
    }
    let mut o: ArriveOut = z();
    o.route = ROUTE_LOCAL;
    o.route_flags = ROUTE_COUNTED << 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::UnknownCode, "arrive.route_flags")
    );
    let mut o: ArriveOut = z();
    o.refusal = 3;
    o.refusal_status = 404;
    o.route_flags = ROUTE_SESSION;
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.pool"),
        "a refused arrival opens no session"
    );
}

/// THE COUNTED REFUSAL (ARCHITECT RULING U11 Q3 2026-10-06; abi/plane "A refused arrival", rule
/// 7): a REFUSED arrival whose dialect read the request states `ROUTE_COUNTED`, alone, whether or
/// not it names an entry; an admitted unit never states it, an answer that is neither admitted nor
/// refused states no route flag, and a refusal stating any other route bit is FAULT (RED arms).
#[test]
fn a_refused_arrival_alone_may_be_counted() {
    let mut o: ArriveOut = z();
    o.refusal = 7;
    o.refusal_status = 404;
    o.route_flags = ROUTE_COUNTED;
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        Ok(()),
        "a refusal its dialect read"
    );
    let mut about = o;
    about.refusal_status = 503;
    about.route = ROUTE_DIRECT;
    about.pool = s("planner");
    assert_eq!(
        check_arrive(Refused, &about, &[], 4, &bounds()),
        Ok(()),
        "a counted refusal about an entry"
    );
    about.route_flags = ROUTE_COUNTED | ROUTE_ONCE;
    assert_eq!(
        check_arrive(Refused, &about, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.route_flags"),
        "a refusal about an entry states no other route bit"
    );
    for other in [ROUTE_ONCE, ROUTE_SESSION, ROUTE_STREAM, ROUTE_COUNTED << 1] {
        let mut o = o;
        o.route_flags = ROUTE_COUNTED | other;
        assert_eq!(
            check_arrive(Refused, &o, &[], 4, &bounds()),
            f(Rule::Contradiction, "arrive.pool"),
            "{other}: a refusal states the counted bit alone"
        );
    }
    let mut o: ArriveOut = z();
    o.route = ROUTE_LOCAL;
    o.route_flags = ROUTE_COUNTED;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.route_flags"),
        "an admitted unit is never a counted refusal"
    );
    for outcome in [Pending, Failed] {
        let mut o: ArriveOut = z();
        o.units_needed = u32::from(outcome == Failed);
        o.route_flags = ROUTE_COUNTED;
        assert_eq!(
            check_arrive(outcome, &o, &[], 0, &bounds()),
            f(Rule::Contradiction, "arrive.pool"),
            "{outcome:?}"
        );
    }
    for bit in [ROUTE_ONCE, ROUTE_SESSION, ROUTE_STREAM] {
        assert_eq!(ROUTE_COUNTED & bit, 0, "{bit} and the counted bit overlap");
    }
    assert_eq!(ROUTE_COUNTED.count_ones(), 1);
}

/// THE STICKY-ROUTING KEY (ARCHITECT Q1 ArriveOut, 2026-10-05): a READY arrival may state an
/// opaque key, bounded like every plane text; a key counted with no bytes is FAULT, and an answer
/// that admits nothing states none (RED arms).
#[test]
fn an_arrivals_affinity_is_an_admitted_units_own_bounded_key() {
    let key = b"session-7";
    let mut o: ArriveOut = z();
    o.route = ROUTE_LOCAL;
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()), "none");
    o.affinity = AbiStr {
        ptr: key.as_ptr(),
        len: key.len(),
    };
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()), "a key");
    o.affinity = AbiStr {
        ptr: std::ptr::null(),
        len: 3,
    };
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::NullWithCount, "arrive.affinity")
    );
    let long = vec![b'k'; MAX_TEXT + 1];
    o.affinity = AbiStr {
        ptr: long.as_ptr(),
        len: long.len(),
    };
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::OverMax, "arrive.affinity")
    );
    for outcome in [Pending, Failed] {
        let mut o: ArriveOut = z();
        o.units_needed = u32::from(outcome == Failed);
        o.affinity = AbiStr {
            ptr: key.as_ptr(),
            len: key.len(),
        };
        assert_eq!(
            check_arrive(outcome, &o, &[], 0, &bounds()),
            f(Rule::Contradiction, "arrive.affinity"),
            "{outcome:?}"
        );
    }
    let mut o: ArriveOut = z();
    o.refusal = 3;
    o.refusal_status = 404;
    o.affinity = AbiStr {
        ptr: key.as_ptr(),
        len: key.len(),
    };
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.affinity"),
        "a refused arrival routes nowhere"
    );
}

/// THE ROUTE CLASS (ARCHITECT Q-SW6 amended by Q-FL3, 2026-10-02, Q-L3B-LOCAL and Q-DEL-A2A-SELECT):
/// a READY arrival names whether its entry is a pool or a model routed directly, that the plane
/// answers it itself, or that the kernel routes it by the principal's scope (both naming no entry); any other class is FAULT, and an answer that admits nothing names the default
/// class only.
#[test]
fn an_arrivals_route_class_is_pool_or_direct() {
    for class in [ROUTE_POOL, ROUTE_DIRECT] {
        let mut o: ArriveOut = z();
        o.route = class;
        o.pool = s("entry");
        assert_eq!(
            check_arrive(Ready, &o, &[], 4, &bounds()),
            Ok(()),
            "{class}"
        );
    }
    // A unit the plane answers itself names no entry (ARCHITECT Q-L3B-LOCAL).
    let mut o: ArriveOut = z();
    o.route = ROUTE_LOCAL;
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()));
    o.pool = s("entry");
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.pool"),
        "a local unit names no entry"
    );
    // A unit routed by scope names no entry: the kernel picks the one member the principal's
    // sealed set reaches (ARCHITECT Q-DEL-A2A-SELECT).
    let mut o: ArriveOut = z();
    o.route = ROUTE_SCOPE;
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()));
    // It may name its candidate entries (ARCHITECT Q-DEL-A2A-SCOPE-TRUST).
    o.pool = s("a, b");
    assert_eq!(check_arrive(Ready, &o, &[], 4, &bounds()), Ok(()));
    let mut o: ArriveOut = z();
    o.route = ROUTE_SCOPE + 1;
    assert_eq!(
        check_arrive(Ready, &o, &[], 4, &bounds()),
        f(Rule::UnknownCode, "arrive.route")
    );
    let mut o: ArriveOut = z();
    o.refusal = 3;
    o.refusal_status = 404;
    o.route = ROUTE_DIRECT;
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::Contradiction, "arrive.pool")
    );
}

/// A REFUSAL ABOUT AN ENTRY (ARCHITECT Q-DEL-A2A-GATE, abi/plane "A refused arrival" rule 6): a
/// REFUSED arrival may name the entry its refusal concerns, with its class, operation class and
/// dialect, and then wear a 5xx; one naming no entry stays a 4xx; a named entry with a class the
/// rule does not admit, or an operation class the plane does not have, is FAULT.
#[test]
fn a_refused_arrival_may_name_the_entry_it_is_about() {
    let about = |route: u8, status: u32| {
        let mut o: ArriveOut = z();
        o.refusal = 7;
        o.refusal_status = status;
        o.route = route;
        o.pool = s("planner");
        o
    };
    assert_eq!(
        check_arrive(Refused, &about(ROUTE_DIRECT, 503), &[], 4, &bounds()),
        Ok(())
    );
    assert_eq!(
        check_arrive(Refused, &about(ROUTE_POOL, 403), &[], 4, &bounds()),
        Ok(())
    );
    assert_eq!(
        check_arrive(Refused, &about(ROUTE_SCOPE, 503), &[], 4, &bounds()),
        f(Rule::UnknownCode, "arrive.route")
    );
    let mut o = about(ROUTE_DIRECT, 503);
    o.op_class = 99;
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::IndexOutOfRange, "arrive.op_class")
    );
    let mut o: ArriveOut = z();
    o.refusal = 7;
    o.refusal_status = 503;
    assert_eq!(
        check_arrive(Refused, &o, &[], 4, &bounds()),
        f(Rule::UnknownCode, "arrive.refusal_status"),
        "a refusal about no entry is the caller's: a 4xx"
    );
}
