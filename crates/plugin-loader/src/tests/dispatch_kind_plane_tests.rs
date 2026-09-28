// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane kind's adapter: each checked op answers GREEN and RED through `Kind::check`, a count
//! one past the host's cap is FAULT before any slice exists, a foreign `in` is FAULT, every slot
//! has a name, and the short answers are recognised.

use std::mem::{size_of, zeroed};
use std::ptr::{null, NonNull};

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut, GenIn, RefreshIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, PlaneSnapshot, RecordWrite, RefusalIn, RefusalOut, ServeIn, ServeOut, Span,
    UnitCount, CANCEL_ABORTED, CANCEL_OK_PARTIAL, EMIT_DONE, PRINCIPAL_REQUIRED, RECORD_PUT, SLOTS,
    UNITS_REPORTED,
};

use crate::dispatch::kinds::plane::Plane;
use crate::dispatch::{Answer, Kind};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data (integers, raw pointers); all-zero is a valid
    // value of each.
    unsafe { zeroed() }
}

fn f(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(fault(rule, field))
}

/// An answer of `slot` over the test's own `in` and `out`.
fn answer<I, O>(s: u32, outcome: Outcome, i: &I, o: &O) -> Answer {
    // SAFETY: `i` and `o` are live for the answer's use in each test and nobody writes them.
    unsafe {
        Answer::new(
            s,
            outcome,
            std::ptr::from_ref(i).cast(),
            size_of::<I>(),
            std::ptr::from_ref(o).cast(),
            size_of::<O>(),
        )
    }
}

fn unit() -> UnitCount {
    UnitCount {
        class: 0,
        source: UNITS_REPORTED,
        amount: 10,
    }
}

fn span(offset: u32, len: u32) -> Span {
    Span { offset, len }
}

fn field() -> OutField {
    OutField {
        name: span(0, 2),
        value: span(2, 2),
    }
}

// ── arrive ──

#[test]
fn arrive_green_units_within_the_hosts_cap() {
    let mut units = [unit(); 4];
    let mut i: ArriveIn = z();
    i.units_buf = units.as_mut_ptr();
    i.units_cap = units.len();
    let mut o: ArriveOut = z();
    o.units_written = 2;
    o.principal_need = PRINCIPAL_REQUIRED;
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        Ok(())
    );
}

#[test]
fn arrive_red_an_unknown_source_and_principal_need() {
    let mut units = [unit(); 4];
    units[0].source = 9;
    let mut i: ArriveIn = z();
    i.units_buf = units.as_mut_ptr();
    i.units_cap = units.len();
    let mut o: ArriveOut = z();
    o.units_written = 1;
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        f(Rule::UnknownCode, "unit.source")
    );
    let mut good = [unit(); 4];
    i.units_buf = good.as_mut_ptr();
    o.principal_need = 7;
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        f(Rule::UnknownCode, "arrive.principal_need")
    );
}

#[test]
fn arrive_units_one_past_the_cap_fault_before_any_slice() {
    let mut i: ArriveIn = z();
    i.units_buf = NonNull::<UnitCount>::dangling().as_ptr();
    i.units_cap = 4;
    let mut o: ArriveOut = z();
    o.units_written = 5;
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        f(Rule::OverCap, "arrive.units")
    );
}

#[test]
fn arrive_units_counted_over_a_null_buffer_fault() {
    let mut i: ArriveIn = z();
    i.units_cap = 4;
    let mut o: ArriveOut = z();
    o.units_written = 1;
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        f(Rule::NullWithCount, "arrive.units")
    );
}

// ── on_piece ──

fn piece_in(
    units: &mut [UnitCount],
    records: &mut [RecordWrite],
    fields: &mut [OutField],
) -> OnPieceIn {
    let mut i: OnPieceIn = z();
    i.reply_cap = 16;
    i.units_buf = units.as_mut_ptr();
    i.units_cap = units.len();
    i.records_buf = records.as_mut_ptr();
    i.records_cap = records.len();
    i.fields_buf = fields.as_mut_ptr();
    i.fields_cap = fields.len();
    i.arena_cap = 16;
    i
}

fn record() -> RecordWrite {
    RecordWrite {
        kind: 0,
        op: RECORD_PUT,
        key: span(4, 2),
        value: span(6, 2),
    }
}

#[test]
fn on_piece_green_every_buffer_within_its_cap() {
    let (mut u, mut r, mut fl) = ([unit(); 2], [record(); 2], [field(); 2]);
    let i = piece_in(&mut u, &mut r, &mut fl);
    let mut o: OnPieceOut = z();
    o.emitted = 3;
    o.flags = EMIT_DONE;
    o.units_written = 1;
    o.records_written = 1;
    o.fields_written = 1;
    o.arena_written = 8;
    assert_eq!(
        Plane::check(&answer(slot::ON_PIECE, Outcome::Ready, &i, &o)),
        Ok(())
    );
}

#[test]
fn on_piece_red_more_without_emitted_and_a_record_outside_the_arena() {
    let (mut u, mut r, mut fl) = ([unit(); 2], [record(); 2], [field(); 2]);
    let i = piece_in(&mut u, &mut r, &mut fl);
    let mut o: OnPieceOut = z();
    o.more = 1;
    assert_eq!(
        Plane::check(&answer(slot::ON_PIECE, Outcome::Ready, &i, &o)),
        f(Rule::Contradiction, "on_piece.more_without_emitted")
    );
    o.more = 0;
    o.records_written = 1;
    o.arena_written = 4;
    assert_eq!(
        Plane::check(&answer(slot::ON_PIECE, Outcome::Ready, &i, &o)),
        f(Rule::SpanOutOfBounds, "record.key")
    );
}

#[test]
fn on_piece_counts_one_past_each_cap_fault_before_any_slice() {
    let dangling = |cap: usize| {
        let mut i: OnPieceIn = z();
        i.units_buf = NonNull::dangling().as_ptr();
        i.units_cap = cap;
        i.records_buf = NonNull::dangling().as_ptr();
        i.records_cap = cap;
        i.fields_buf = NonNull::dangling().as_ptr();
        i.fields_cap = cap;
        i
    };
    let i = dangling(2);
    for (which, field) in [
        (0, "on_piece.units"),
        (1, "on_piece.records"),
        (2, "on_piece.fields"),
    ] {
        let mut o: OnPieceOut = z();
        match which {
            0 => o.units_written = 3,
            1 => o.records_written = 3,
            _ => o.fields_written = 3,
        }
        assert_eq!(
            Plane::check(&answer(slot::ON_PIECE, Outcome::Ready, &i, &o)),
            f(Rule::OverCap, field)
        );
    }
}

// ── refusal ──

fn refusal_in(fields: &mut [OutField]) -> RefusalIn {
    let mut i: RefusalIn = z();
    i.reply_cap = 16;
    i.fields_buf = fields.as_mut_ptr();
    i.fields_cap = fields.len();
    i.arena_cap = 16;
    i
}

#[test]
fn refusal_green_and_red() {
    let mut fl = [field(); 2];
    let i = refusal_in(&mut fl);
    let mut o: RefusalOut = z();
    o.reply_written = 8;
    o.fields_written = 1;
    o.arena_written = 4;
    assert_eq!(
        Plane::check(&answer(slot::REFUSAL, Outcome::Ready, &i, &o)),
        Ok(())
    );
    o.marker = 2;
    assert_eq!(
        Plane::check(&answer(slot::REFUSAL, Outcome::Ready, &i, &o)),
        f(Rule::UnknownCode, "refusal.marker")
    );
}

#[test]
fn refusal_fields_one_past_the_cap_fault_before_any_slice() {
    let mut i: RefusalIn = z();
    i.fields_buf = NonNull::dangling().as_ptr();
    i.fields_cap = 2;
    let mut o: RefusalOut = z();
    o.fields_written = 3;
    assert_eq!(
        Plane::check(&answer(slot::REFUSAL, Outcome::Ready, &i, &o)),
        f(Rule::OverCap, "refusal.fields")
    );
}

// ── serve ──

fn serve_in(fields: &mut [OutField]) -> ServeIn {
    let mut i: ServeIn = z();
    i.reply_cap = 16;
    i.fields_buf = fields.as_mut_ptr();
    i.fields_cap = fields.len();
    i.arena_cap = 16;
    i
}

#[test]
fn serve_green_and_red() {
    let mut fl = [field(); 2];
    let i = serve_in(&mut fl);
    let mut o: ServeOut = z();
    o.status = 200;
    o.reply_written = 4;
    o.fields_written = 1;
    o.arena_written = 4;
    assert_eq!(
        Plane::check(&answer(slot::SERVE, Outcome::Ready, &i, &o)),
        Ok(())
    );
    o.arena_written = 3;
    assert_eq!(
        Plane::check(&answer(slot::SERVE, Outcome::Ready, &i, &o)),
        f(Rule::SpanOutOfBounds, "field.value")
    );
    o.arena_written = 4;
    o.reply_written = 17;
    assert_eq!(
        Plane::check(&answer(slot::SERVE, Outcome::Ready, &i, &o)),
        f(Rule::OverCap, "serve.reply")
    );
}

#[test]
fn serve_fields_one_past_the_cap_fault_before_any_slice() {
    let mut i: ServeIn = z();
    i.fields_buf = NonNull::dangling().as_ptr();
    i.fields_cap = 2;
    let mut o: ServeOut = z();
    o.fields_written = 3;
    assert_eq!(
        Plane::check(&answer(slot::SERVE, Outcome::Ready, &i, &o)),
        f(Rule::OverCap, "serve.fields")
    );
}

// ── open, refresh: the generation snapshot ──

fn snap(generation: u64) -> PlaneSnapshot {
    let mut s: PlaneSnapshot = z();
    s.size = size_of::<PlaneSnapshot>() as u32;
    s.generation = generation;
    s
}

#[test]
fn open_green_and_red_on_its_snapshot() {
    let mut i: PlaneOpenIn = z();
    i.open.generation = 7;
    let good = snap(7);
    let mut o: PlaneOpenOut = z();
    o.snapshot = &good;
    assert_eq!(
        Plane::check(&answer(life::OPEN, Outcome::Ready, &i, &o)),
        Ok(())
    );
    let other = snap(8);
    o.snapshot = &other;
    assert_eq!(
        Plane::check(&answer(life::OPEN, Outcome::Ready, &i, &o)),
        f(Rule::Foreign, "snapshot.generation")
    );
    let mut small = snap(7);
    small.size = 8;
    o.snapshot = &small;
    assert_eq!(
        Plane::check(&answer(life::OPEN, Outcome::Ready, &i, &o)),
        f(Rule::Foreign, "snapshot.size")
    );
    o.snapshot = null();
    assert_eq!(
        Plane::check(&answer(life::OPEN, Outcome::Ready, &i, &o)),
        f(Rule::Missing, "open.snapshot")
    );
    assert_eq!(
        Plane::check(&answer(life::OPEN, Outcome::Failed, &i, &o)),
        Ok(()),
        "a FAILED open carries no snapshot"
    );
}

#[test]
fn refresh_green_and_red_on_its_snapshot() {
    let mut i: RefreshIn = z();
    i.generation = 3;
    let good = snap(3);
    let mut o: PlaneRefreshOut = z();
    o.snapshot = &good;
    assert_eq!(
        Plane::check(&answer(life::REFRESH, Outcome::Ready, &i, &o)),
        Ok(())
    );
    let mut listed = snap(3);
    listed.claims_len = 1;
    o.snapshot = &listed;
    assert_eq!(
        Plane::check(&answer(life::REFRESH, Outcome::Ready, &i, &o)),
        f(Rule::NullWithCount, "snapshot.claims")
    );
}

// ── cancel, hydrate, start ──

#[test]
fn cancel_green_and_red_on_its_disposition() {
    let i: InHead = z();
    let mut o: CancelOut = z();
    for d in [CANCEL_OK_PARTIAL, CANCEL_ABORTED] {
        o.disposition = d;
        assert_eq!(
            Plane::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
            Ok(())
        );
    }
    for d in [0, CANCEL_ABORTED + 1] {
        o.disposition = d;
        assert_eq!(
            Plane::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
            f(Rule::UnknownCode, "cancel.disposition")
        );
    }
}

#[test]
fn hydrate_and_start_have_no_per_answer_rule() {
    let i: GenIn = z();
    let o: OutHead = z();
    for s in [slot::HYDRATE, slot::START] {
        for outcome in [Outcome::Ready, Outcome::Failed] {
            assert_eq!(Plane::check(&answer(s, outcome, &i, &o)), Ok(()));
            assert!(!Plane::short(&answer(s, outcome, &i, &o)));
        }
    }
}

// ── foreign sizes ──

#[test]
fn an_in_smaller_than_the_ops_struct_is_foreign() {
    let i: InHead = z();
    for (s, out_size) in [
        (slot::ARRIVE, size_of::<ArriveOut>()),
        (slot::ON_PIECE, size_of::<OnPieceOut>()),
        (slot::REFUSAL, size_of::<RefusalOut>()),
        (slot::SERVE, size_of::<ServeOut>()),
    ] {
        let o = [0u64; 64];
        assert!(size_of::<[u64; 64]>() >= out_size);
        assert_eq!(
            Plane::check(&answer(s, Outcome::Ready, &i, &o)),
            f(Rule::Foreign, "in"),
            "slot {s}"
        );
    }
}

#[test]
fn an_out_smaller_than_the_ops_struct_is_foreign() {
    let mut units = [unit(); 1];
    let mut i: ArriveIn = z();
    i.units_buf = units.as_mut_ptr();
    i.units_cap = 1;
    let o: OutHead = z();
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        f(Rule::Foreign, "out")
    );
}

// ── names, identity, short ──

#[test]
fn every_slot_has_a_name() {
    for s in 0..SLOTS {
        assert_ne!(Plane::op_name(s), "op", "slot {s}");
    }
    assert_eq!(Plane::op_name(slot::ON_PIECE), "on_piece");
}

#[test]
fn the_kind_is_plane_and_times_out_failed() {
    assert_eq!(Plane::CODE, KindCode::Plane);
    assert_eq!(Plane::TIMEOUT, Outcome::Failed);
}

#[test]
fn a_failed_answer_with_a_need_above_the_cap_is_short() {
    let mut i: ArriveIn = z();
    i.units_buf = NonNull::dangling().as_ptr();
    i.units_cap = 4;
    let mut o: ArriveOut = z();
    o.units_needed = 5;
    let a = answer(slot::ARRIVE, Outcome::Failed, &i, &o);
    assert_eq!(Plane::check(&a), Ok(()));
    assert!(Plane::short(&a));
    o.units_needed = 0;
    assert!(!Plane::short(&answer(
        slot::ARRIVE,
        Outcome::Failed,
        &i,
        &o
    )));

    let (mut u, mut r, mut fl) = ([unit(); 1], [record(); 1], [field(); 1]);
    let pi = piece_in(&mut u, &mut r, &mut fl);
    let mut po: OnPieceOut = z();
    po.arena_needed = 64;
    let a = answer(slot::ON_PIECE, Outcome::Failed, &pi, &po);
    assert_eq!(Plane::check(&a), Ok(()));
    assert!(Plane::short(&a));

    let mut fl = [field(); 1];
    let si = serve_in(&mut fl);
    let mut so: ServeOut = z();
    so.reply_needed = 64;
    let a = answer(slot::SERVE, Outcome::Failed, &si, &so);
    assert_eq!(Plane::check(&a), Ok(()));
    assert!(Plane::short(&a));
    assert!(!Plane::short(&answer(
        slot::SERVE,
        Outcome::Ready,
        &si,
        &so
    )));

    let ri = refusal_in(&mut fl);
    let mut ro: RefusalOut = z();
    ro.fields_needed = 9;
    let a = answer(slot::REFUSAL, Outcome::Failed, &ri, &ro);
    assert_eq!(Plane::check(&a), Ok(()));
    assert!(Plane::short(&a));
}
