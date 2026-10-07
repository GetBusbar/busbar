// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane kind's adapter: each checked op answers GREEN and RED through `Kind::check`, a count
//! one past the host's cap is FAULT before any slice exists, a foreign `in` is FAULT, every slot
//! has a name, and the short answers are recognised.

use std::mem::{size_of, zeroed};
use std::ptr::{null, NonNull};
use std::sync::LazyLock;

use crate::dispatch::kinds::plane::PlaneFacts;
use busbar_contract::abi::hook::SignalEntry;
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome, Span};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::Bounds;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, PlaneSnapshot, ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut,
    ServeIn, ServeOut, UnitCount, CANCEL_ABORTED, CANCEL_OK_PARTIAL, EMIT_DONE, PRINCIPAL_REQUIRED,
    RECORD_PUT, SLOTS, UNITS_REPORTED,
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
/// The tail bounds every answer here is judged against: four entries in each tail list.
static FACTS: LazyLock<PlaneFacts> = LazyLock::new(|| PlaneFacts {
    bounds: Bounds {
        op_classes: 4,
        dialects: 4,
        billable_classes: 4,
        record_kinds: 4,
    },
    refusal_statuses: Vec::new(),
    declared: Default::default(),
    served: Default::default(),
});

fn answer<'a, I, O>(s: u32, outcome: Outcome, i: &I, o: &O) -> Answer<'a> {
    bare(s, outcome, i, o).with_context(Some(&*FACTS))
}

/// An answer judged with no tail at all.
fn bare<'a, I, O>(s: u32, outcome: Outcome, i: &I, o: &O) -> Answer<'a> {
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
    // One count per class: a class counted twice in one report is refused.
    units[1].class = 1;
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

/// RED, THE APPEND RULE AT THE HOST: a plugin built before `PlaneSnapshot::listed` was appended
/// publishes a snapshot whose `size` ends before it. The host accepts it and reads its list as none,
/// never the bytes past that `size` (here garbage: a count over a dangling pointer).
#[test]
fn a_snapshot_from_before_listed_reads_as_listing_none() {
    let mut i: PlaneOpenIn = z();
    i.open.generation = 7;
    let mut older = snap(7);
    older.size = std::mem::offset_of!(PlaneSnapshot, listed) as u32;
    older.listed = NonNull::<AbiStr>::dangling().as_ptr();
    older.listed_len = 5;
    let mut o: PlaneOpenOut = z();
    o.snapshot = &older;
    assert_eq!(
        Plane::check(&answer(life::OPEN, Outcome::Ready, &i, &o)),
        Ok(()),
        "a snapshot of the size before the append is this host's to read"
    );
    let copied = crate::dispatch::kinds::plane::copy_snapshot(&older, 4)
        .expect("the older snapshot is copied");
    assert!(copied.listed.is_empty(), "{:?}", copied.listed);
    let names = [AbiStr {
        ptr: b"listed-one".as_ptr(),
        len: 10,
    }];
    let mut newer = snap(7);
    newer.listed = names.as_ptr();
    newer.listed_len = 1;
    let copied = crate::dispatch::kinds::plane::copy_snapshot(&newer, 4).expect("copied");
    assert_eq!(copied.listed, vec!["listed-one".to_string()]);
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
    let i: busbar_contract::abi::plane::PlaneCancelIn = z();
    let mut o: busbar_contract::abi::plane::PlaneCancelOut = z();
    for d in [CANCEL_OK_PARTIAL, CANCEL_ABORTED] {
        o.cancel.disposition = d;
        assert_eq!(
            Plane::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
            Ok(())
        );
    }
    for d in [0, CANCEL_ABORTED + 1] {
        o.cancel.disposition = d;
        assert_eq!(
            Plane::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
            f(Rule::UnknownCode, "cancel.disposition")
        );
    }
    // SEAM-L(r): a write counted past the host's record buffer is FAULT.
    o.cancel.disposition = CANCEL_ABORTED;
    o.records_written = 1;
    assert_eq!(
        Plane::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
        f(Rule::OverCap, "cancel.records")
    );
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

// ── project ──

fn project_in(signals: &mut [SignalEntry], arena: &mut [u8]) -> ProjectIn {
    let mut i: ProjectIn = z();
    i.signals_buf = signals.as_mut_ptr();
    i.signals_cap = signals.len();
    i.arena_buf = arena.as_mut_ptr();
    i.arena_cap = arena.len();
    i
}

#[test]
fn project_green_a_view_inside_the_hosts_buffers() {
    let mut signals: [SignalEntry; 2] = z();
    let mut arena = [0u8; 16];
    let i = project_in(&mut signals, &mut arena);
    let mut o: ProjectOut = z();
    o.view.signals = i.signals_buf.cast_const();
    o.view.signals_len = 1;
    o.view.pool = AbiStr {
        ptr: i.arena_buf.cast_const(),
        len: 4,
    };
    o.body = span(4, 8);
    o.arena_written = 12;
    assert_eq!(
        Plane::check(&answer(slot::PROJECT, Outcome::Ready, &i, &o)),
        Ok(())
    );
}

#[test]
fn project_red_signals_past_the_cap_and_a_string_outside_the_arena() {
    let mut signals: [SignalEntry; 2] = z();
    let mut arena = [0u8; 16];
    let i = project_in(&mut signals, &mut arena);
    let mut o: ProjectOut = z();
    o.view.signals = i.signals_buf.cast_const();
    o.view.signals_len = 3;
    assert_eq!(
        Plane::check(&answer(slot::PROJECT, Outcome::Ready, &i, &o)),
        f(Rule::OverCap, "project.signals")
    );
    let mut o: ProjectOut = z();
    o.view.pool = AbiStr {
        ptr: i.arena_buf.cast_const().wrapping_add(12),
        len: 8,
    };
    o.arena_written = 16;
    assert_eq!(
        Plane::check(&answer(slot::PROJECT, Outcome::Ready, &i, &o)),
        f(Rule::SpanOutOfBounds, "project.view.pool")
    );
}

#[test]
fn a_short_project_answer_is_recognised() {
    let mut signals: [SignalEntry; 2] = z();
    let mut arena = [0u8; 16];
    let i = project_in(&mut signals, &mut arena);
    let mut o: ProjectOut = z();
    o.arena_needed = 64;
    let a = answer(slot::PROJECT, Outcome::Failed, &i, &o);
    assert_eq!(Plane::check(&a), Ok(()));
    assert!(Plane::short(&a));
    o.arena_needed = 0;
    assert!(!Plane::short(&answer(
        slot::PROJECT,
        Outcome::Failed,
        &i,
        &o
    )));
    // A prompt with more turns than the host's buffer holds is a short answer too.
    o.messages_needed = 3;
    let a = answer(slot::PROJECT, Outcome::Failed, &i, &o);
    assert_eq!(Plane::check(&a), Ok(()));
    assert!(Plane::short(&a), "short on the prompt turns");
}

#[test]
fn project_red_a_rewritten_body_for_a_call_that_carried_no_rewrite() {
    let mut signals: [SignalEntry; 2] = z();
    let mut arena = [0u8; 16];
    let mut i = project_in(&mut signals, &mut arena);
    let mut o: ProjectOut = z();
    o.rewritten = span(0, 8);
    o.arena_written = 8;
    assert_eq!(
        Plane::check(&answer(slot::PROJECT, Outcome::Ready, &i, &o)),
        f(Rule::Contradiction, "project.rewritten_without_rewrite")
    );
    let rewrite = b"{}";
    i.rewrite = busbar_contract::abi::mechanism::call::Blob {
        ptr: rewrite.as_ptr(),
        len: rewrite.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
    assert_eq!(
        Plane::check(&answer(slot::PROJECT, Outcome::Ready, &i, &o)),
        Ok(()),
        "the same answer to a call that carried one"
    );
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
        (slot::PROJECT, size_of::<ProjectOut>()),
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

#[test]
fn red_a_tail_index_past_its_list_is_fault_at_the_crossing() {
    // A billable class past the tail's four: FAULT at the crossing.
    let mut units = [UnitCount { class: 4, ..unit() }; 1];
    let mut i: ArriveIn = z();
    i.units_buf = units.as_mut_ptr();
    i.units_cap = units.len();
    let mut o: ArriveOut = z();
    o.units_written = 1;
    o.principal_need = PRINCIPAL_REQUIRED;
    let broke = Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(broke.rule, Rule::IndexOutOfRange);
    // The GREEN twin: the last class in the list.
    let mut last = [UnitCount { class: 3, ..unit() }; 1];
    i.units_buf = last.as_mut_ptr();
    assert_eq!(
        Plane::check(&answer(slot::ARRIVE, Outcome::Ready, &i, &o)),
        Ok(())
    );
    // Without the instance's tail bounds the answer cannot be judged: FAULT.
    assert_eq!(
        Plane::check(&bare(slot::ARRIVE, Outcome::Ready, &i, &o)),
        f(Rule::Missing, "plane.tail")
    );
}

#[test]
fn red_a_plane_without_a_whole_tail_does_not_bind() {
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    let mut st: Statement = z();
    assert!(Plane::context(&st).is_err(), "no tail");
    let short = KindTailHead {
        size: 8,
        _reserved: 0,
    };
    st.kind_tail = &short;
    assert!(
        Plane::context(&st).is_err(),
        "a tail shorter than this host's"
    );
}

/// The tail's trust keys are judged per ELEMENT at bind: a pin naming no mechanism, and a mechanism
/// with no token, each refuse the load; a whole key binds.
#[test]
fn red_a_tail_trust_key_that_breaks_its_element_rule_does_not_bind() {
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::plane::{
        PinMechanism, PlaneTail, TrustKey, INGRESS_REQUEST_RESPONSE, MECHANISM_ROOT, SHAPE_WHOLE,
        TRUST_PIN,
    };
    fn abi(s: &'static str) -> AbiStr {
        busbar_contract::abi::sdk::door::abi_str(s)
    }
    fn bind(keys: &[TrustKey]) -> Result<(), String> {
        let mut t: PlaneTail = z();
        t.head = KindTailHead {
            size: size_of::<PlaneTail>() as u32,
            _reserved: 0,
        };
        t.ingress = INGRESS_REQUEST_RESPONSE;
        t.dispatch_shape = SHAPE_WHOLE;
        t.trust_keys = keys.as_ptr();
        t.trust_keys_len = keys.len();
        let sections = [busbar_contract::abi::mechanism::door::Section {
            name: abi("door"),
            flags: busbar_contract::abi::mechanism::door::SECTION_DECLARING,
            _reserved: 0,
        }];
        let mut st: Statement = z();
        st.kind_tail = std::ptr::from_ref(&t).cast();
        st.sections = sections.as_ptr();
        st.sections_len = sections.len();
        Plane::context(&st).map(|_| ())
    }
    let good = [PinMechanism {
        token: abi("sealed_key"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    }];
    let pin = |mechs: &[PinMechanism]| TrustKey {
        key: abi("anchor"),
        role: TRUST_PIN,
        flags: 0,
        default: z(),
        mechanisms: mechs.as_ptr(),
        mechanisms_len: mechs.len(),
    };
    assert_eq!(bind(&[pin(&good)]), Ok(()));
    // A pin with no mechanisms: refused by the key's own rule.
    assert!(bind(&[pin(&[])]).is_err());
    // A mechanism with no token: refused by the per-mechanism rule, which `check_tail` never ran.
    let nameless = [PinMechanism {
        token: z(),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    }];
    let err = bind(&[pin(&nameless)]).unwrap_err();
    assert!(err.contains("pin_mechanism.token"), "{err}");
}

/// RED: the tail's refusal statuses are judged at bind. A row the validator refuses refuses the
/// load; the rows that pass are the instance's, for the kernel's driver.
#[test]
fn red_a_tail_whose_refusal_statuses_break_a_rule_does_not_bind() {
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::plane::{
        reason_code, PlaneTail, RefusalStatus, INGRESS_REQUEST_RESPONSE,
    };
    use busbar_contract::caps::ReasonCode;
    let rows = |status: u32| -> &'static [RefusalStatus] {
        Box::leak(Box::new([RefusalStatus {
            dialect: 0,
            reason: reason_code(ReasonCode::OverBudget),
            status,
            _reserved: 0,
        }]))
    };
    let dialects: &'static [busbar_contract::abi::mechanism::call::AbiStr] =
        Box::leak(Box::new([busbar_contract::abi::mechanism::call::AbiStr {
            ptr: b"plain".as_ptr(),
            len: 5,
        }]));
    let bind = |rows: &'static [RefusalStatus]| {
        let mut tail: PlaneTail = z();
        tail.head = KindTailHead {
            size: size_of::<PlaneTail>() as u32,
            _reserved: 0,
        };
        tail.ingress = INGRESS_REQUEST_RESPONSE;
        tail.dialects = dialects.as_ptr();
        tail.dialects_len = 1;
        tail.refusal_statuses = rows.as_ptr();
        tail.refusal_statuses_len = rows.len();
        let tail: &'static PlaneTail = Box::leak(Box::new(tail));
        let sections: &'static [busbar_contract::abi::mechanism::door::Section] =
            Box::leak(Box::new([busbar_contract::abi::mechanism::door::Section {
                name: busbar_contract::abi::mechanism::call::AbiStr {
                    ptr: b"door".as_ptr(),
                    len: 4,
                },
                flags: busbar_contract::abi::mechanism::door::SECTION_DECLARING,
                _reserved: 0,
            }]));
        let mut st: Statement = z();
        st.kind_tail = &tail.head;
        st.sections = sections.as_ptr();
        st.sections_len = sections.len();
        Plane::context(&st)
    };
    let facts = bind(rows(400)).expect("a valid row binds");
    let facts = facts
        .expect("a plane has a context")
        .downcast::<PlaneFacts>()
        .expect("the plane's facts");
    assert_eq!(facts.refusal_statuses, rows(400).to_vec());
    let refused = bind(rows(200)).expect_err("a status outside 400-599 refuses the load");
    assert!(refused.contains("refusal_status.status"), "{refused}");
}

/// RED (ARCHITECT Q-L5-FEE (C)): the tail's fee units are judged at bind. A fee unit that is one of
/// the tail's billable classes binds; one no class lists refuses the load (the plane could never
/// report it, so its fee would be refunded on every unit), and so does a class with no family.
#[test]
fn red_a_tail_whose_fee_unit_is_no_billable_class_does_not_bind() {
    use busbar_contract::abi::mechanism::door::{
        KindTailHead, Section, Statement, SECTION_DECLARING,
    };
    use busbar_contract::abi::plane::{BillableClass, PlaneTail, INGRESS_DUPLEX_SESSION};
    fn s(text: &'static str) -> AbiStr {
        AbiStr {
            ptr: text.as_ptr(),
            len: text.len(),
        }
    }
    let bind = |classes: &'static [BillableClass], fees: &'static [AbiStr]| {
        let mut tail: PlaneTail = z();
        tail.head = KindTailHead {
            size: size_of::<PlaneTail>() as u32,
            _reserved: 0,
        };
        tail.ingress = INGRESS_DUPLEX_SESSION;
        tail.billable_classes = classes.as_ptr();
        tail.billable_classes_len = classes.len();
        tail.fee_units = fees.as_ptr();
        tail.fee_units_len = fees.len();
        let tail: &'static PlaneTail = Box::leak(Box::new(tail));
        let sections: &'static [Section] = Box::leak(Box::new([Section {
            name: s("door"),
            flags: SECTION_DECLARING,
            _reserved: 0,
        }]));
        let mut st: Statement = z();
        st.kind_tail = &tail.head;
        st.sections = sections.as_ptr();
        st.sections_len = sections.len();
        Plane::context(&st).map(|_| ())
    };
    let class = |name: &'static str, family: &'static str| BillableClass {
        class: s(name),
        family: s(family),
    };
    let classes: &'static [BillableClass] = Box::leak(Box::new([
        class("tool_calls", "count"),
        class("per_session", "count"),
    ]));
    let fee: &'static [AbiStr] = Box::leak(Box::new([s("per_session")]));
    assert_eq!(
        bind(classes, fee),
        Ok(()),
        "a fee unit that is a class binds"
    );
    assert_eq!(bind(&[], &[]), Ok(()), "no fee unit, nothing to judge");
    let unlisted: &'static [BillableClass] = Box::leak(Box::new([class("tool_calls", "count")]));
    let refused = bind(unlisted, fee).expect_err("a fee unit no class lists refuses the load");
    assert!(refused.contains("tail.fee_units"), "{refused}");
    let familyless: &'static [BillableClass] = Box::leak(Box::new([BillableClass {
        class: s("per_session"),
        family: z(),
    }]));
    let refused = bind(familyless, fee).expect_err("a class with no family refuses the load");
    assert!(refused.contains("billable_class.family"), "{refused}");
}
