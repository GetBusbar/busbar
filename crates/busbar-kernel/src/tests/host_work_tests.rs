// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WORK FAMILY (`work.open` / `work.find` / `work.settle` / `work.resume`), as the kernel
//! serves it: durable handles over the store's typed records, the anti-enumeration scoped lookup,
//! the bound that refuses at admission, retention swept on submit, and a handle found again after
//! a restart.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::service::{self as svc, MAX_WORK_RECORD, WORK_LIVE, WORK_SETTLED};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_contract::records::VirtualKey;
use busbar_contract::services::{Caller, HostServices, Later, Ran, Stored};

use super::*;
use crate::governance::MemoryStore;
use crate::host_records::RecordRows;
use crate::host_services::{InstanceFacts, KernelServices, Offload, NOT_A_KIND};
use crate::host_units::UnitRecord;

struct Mem(Arc<MemoryStore>);

impl RecordRows for Mem {
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        self.0.record_put(schema, key, value)
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        self.0.record_get(schema, key)
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        self.0.record_scan(schema, prefix, limit)
    }
}

/// Runs every job at once, on the caller's thread.
struct Inline;

impl Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

const KIND: RecordSchemaId = RecordSchemaId::new("job");

fn caller(instance: &str) -> Caller {
    Caller {
        instance: Arc::from(instance),
        plugin: Arc::from("the-plugin"),
        kind: KindCode::Plane,
    }
}

fn key(id: &str) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: id.into(),
        name: id.into(),
        enabled: true,
        ..VirtualKey::default()
    })
}

struct Rig {
    s: KernelServices,
    store: Arc<MemoryStore>,
    clock: Arc<AtomicU64>,
}

/// Services over `store` (a restart is a second rig over the same store), "inst" and "other"
/// admitted, units 1 and 2 in flight as principal "alice", unit 3 as "bob".
fn rig_over(store: Arc<MemoryStore>, bounds: WorkBounds) -> Rig {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let c = Arc::clone(&clock);
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&store))), store.clone())
        .with_pool(Arc::new(Inline))
        .with_work_bounds(bounds)
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    for label in ["inst", "other"] {
        s.admit(
            label,
            InstanceFacts {
                record_kinds: vec![KIND],
                ..InstanceFacts::default()
            },
        )
        .unwrap();
    }
    for (unit, who) in [(1, "alice"), (2, "alice"), (3, "bob")] {
        s.units().admitted(
            unit,
            UnitRecord {
                principal: Some(key(who)),
                depth: 0,
            },
        );
    }
    Rig { s, store, clock }
}

fn rig() -> Rig {
    rig_over(Arc::new(MemoryStore::new()), WorkBounds::default())
}

fn run(f: impl FnOnce(Later) -> Ran) -> Stored {
    let slot: Arc<Mutex<Option<Stored>>> = Arc::default();
    let mine = Arc::clone(&slot);
    match f(Box::new(move |s| *mine.lock().unwrap() = Some(s))) {
        Ran::Now(s) => s,
        Ran::Later => slot.lock().unwrap().take().expect("the later was answered"),
    }
}

/// Open a handle as unit `unit` of "inst": its handle and reference.
fn open(r: &Rig, unit: u64, record: &[u8]) -> (u64, Vec<u8>) {
    let s = run(|l| r.s.work_open(&caller("inst"), Some(unit), "job", record, l));
    assert_eq!((s.outcome, s.error), (Outcome::Ready, ""), "opened");
    assert!(s.value >= 1, "a handle is never 0");
    assert_eq!(s.spans.len(), 1);
    let k = s.spans[0].key;
    let reference = s.bytes[k.offset as usize..(k.offset + k.len) as usize].to_vec();
    (s.value, reference)
}

fn find(r: &Rig, instance: &str, unit: u64, reference: &[u8]) -> Stored {
    run(|l| r.s.work_find(&caller(instance), Some(unit), reference, l))
}

/// Settle `handle` as `instance`, from a crossing serving `unit`.
fn settle(r: &Rig, instance: &str, unit: Option<u64>, handle: u64, record: &[u8]) -> Stored {
    run(|l| r.s.work_settle(&caller(instance), unit, handle, record, l))
}

/// The state byte and record a found or resumed answer carries.
fn state_and_record(s: &Stored) -> (u8, Vec<u8>) {
    let sp = s.spans[0];
    let at = |o: u32, n: u32| s.bytes[o as usize..(o + n) as usize].to_vec();
    (
        at(sp.key.offset, sp.key.len)[0],
        at(sp.value.offset, sp.value.len),
    )
}

#[test]
fn an_opened_handle_is_found_by_its_reference_under_its_principal() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"rec-1");
    assert_eq!(reference.len(), svc::WORK_REFERENCE_LEN);
    assert!(reference
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    // Another unit of the same principal finds it.
    let found = find(&r, "inst", 2, &reference);
    assert_eq!((found.outcome, found.value), (Outcome::Ready, handle));
    assert_eq!(state_and_record(&found), (WORK_LIVE, b"rec-1".to_vec()));
    // Two opens mint two references.
    let (_, second) = open(&r, 1, b"rec-2");
    assert_ne!(second, reference);
}

#[test]
fn every_denial_of_a_lookup_answers_alike() {
    let r = rig();
    let (_, reference) = open(&r, 1, b"rec");
    let denied = [
        // Another principal's handle.
        find(&r, "inst", 3, &reference),
        // Another instance's lookup of it.
        find(&r, "other", 1, &reference),
        // A reference no one opened.
        find(&r, "inst", 1, b"0123456789abcdef0123456789abcdef"),
        // A malformed one, and an uppercase spelling of a real one.
        find(&r, "inst", 1, b"not-a-reference"),
        find(&r, "inst", 1, reference.to_ascii_uppercase().as_slice()),
    ];
    for d in &denied {
        assert_eq!(*d, Stored::ready(svc::ABSENT), "every denial is one answer");
    }
}

#[test]
fn a_settled_handle_answers_its_final_record_and_settles_once() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"working");
    let s = settle(&r, "inst", Some(1), handle, b"done");
    assert_eq!((s.outcome, s.value), (Outcome::Ready, 0));
    let found = find(&r, "inst", 2, &reference);
    assert_eq!(found.value, handle);
    assert_eq!(state_and_record(&found), (WORK_SETTLED, b"done".to_vec()));
    let again = settle(&r, "inst", Some(1), handle, b"again");
    assert_eq!(
        (again.outcome, again.error),
        (Outcome::Refused, refusal::SETTLED)
    );
    // Another instance cannot settle it.
    let (h2, _) = open(&r, 1, b"x");
    let theirs = settle(&r, "other", Some(1), h2, b"y");
    assert_eq!(
        (theirs.outcome, theirs.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
}

#[test]
fn the_bound_refuses_an_open_and_never_evicts_a_live_handle() {
    let r = rig_over(
        Arc::new(MemoryStore::new()),
        WorkBounds {
            max_live: 2,
            retain_ms: 1_000,
        },
    );
    let (h1, r1) = open(&r, 1, b"a");
    let (_, r2) = open(&r, 1, b"b");
    let third = run(|l| r.s.work_open(&caller("inst"), Some(1), "job", b"c", l));
    assert_eq!(
        (third.outcome, third.error),
        (Outcome::Refused, refusal::AT_BOUND)
    );
    // Both live handles are still there.
    assert_eq!(find(&r, "inst", 1, &r1).value, h1);
    assert_ne!(find(&r, "inst", 1, &r2).value, svc::ABSENT);
    // The bound is per instance.
    let elsewhere = run(|l| r.s.work_open(&caller("other"), Some(1), "job", b"c", l));
    assert_eq!(elsewhere.outcome, Outcome::Ready);
    // A settled handle no longer counts against it.
    let _ = settle(&r, "inst", Some(1), h1, b"done");
    let _ = open(&r, 1, b"c");
}

#[test]
fn retention_bounds_only_settled_handles_and_the_sweep_runs_on_submit() {
    let r = rig_over(
        Arc::new(MemoryStore::new()),
        WorkBounds {
            max_live: 16,
            retain_ms: 1_000,
        },
    );
    let (settled, sref) = open(&r, 1, b"a");
    let (live, lref) = open(&r, 1, b"b");
    let _ = settle(&r, "inst", Some(1), settled, b"done");
    r.clock.fetch_add(1_000, Ordering::SeqCst);
    // Past its retention the settled handle is absent; the live one is not.
    assert_eq!(find(&r, "inst", 1, &sref), Stored::ready(svc::ABSENT));
    assert_eq!(find(&r, "inst", 1, &lref).value, live);
    // A read swept nothing: the row is still in the store.
    let row = |reference: &[u8]| {
        let reference = parse_reference(reference).unwrap();
        r.store
            .record_get(WORK_SCHEMA, &work_key("inst", &reference))
            .unwrap()
            .map(|v| v.as_slice().to_vec())
            .unwrap_or_default()
    };
    assert!(!row(&sref).is_empty());
    // A submit sweeps it, from the book and the store.
    let held = r.s.work().held();
    let _ = open(&r, 1, b"c");
    assert_eq!(r.s.work().held(), held, "one swept, one opened");
    assert!(row(&sref).is_empty(), "the swept row is struck");
    assert!(!row(&lref).is_empty(), "a live row is never struck");
}

#[test]
fn a_handle_is_found_and_resumed_after_a_restart() {
    let store = Arc::new(MemoryStore::new());
    let bounds = WorkBounds {
        max_live: 2,
        retain_ms: 1_000,
    };
    let before = rig_over(Arc::clone(&store), bounds);
    let (_, reference) = open(&before, 1, b"park");
    let (_, other) = open(&before, 1, b"park-2");
    drop(before);
    // A new process over the same store.
    let after = rig_over(Arc::clone(&store), bounds);
    let found = find(&after, "inst", 2, &reference);
    assert_eq!(found.outcome, Outcome::Ready);
    assert_ne!(found.value, svc::ABSENT);
    assert_eq!(state_and_record(&found), (WORK_LIVE, b"park".to_vec()));
    // Resume binds it to the continuation unit, of the principal it recorded.
    let resumed = run(|l| {
        after
            .s
            .work_resume(&caller("inst"), Some(2), found.value, l)
    });
    assert_eq!((resumed.outcome, resumed.value), (Outcome::Ready, 0));
    assert_eq!(state_and_record(&resumed), (WORK_LIVE, b"park".to_vec()));
    // The earlier process's live handles count against the bound.
    let refused = run(|l| after.s.work_open(&caller("inst"), Some(1), "job", b"z", l));
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Refused, refusal::AT_BOUND)
    );
    // Settled after the restart, it reads settled in a third process.
    let _ = settle(&after, "inst", Some(2), found.value, b"done");
    let third = rig_over(store, bounds);
    let again = find(&third, "inst", 1, &reference);
    assert_eq!(state_and_record(&again), (WORK_SETTLED, b"done".to_vec()));
    assert_ne!(find(&third, "inst", 1, &other).value, svc::ABSENT);
}

#[test]
fn resume_is_refused_to_another_principal() {
    let r = rig();
    let (handle, _) = open(&r, 1, b"mine");
    let s = run(|l| r.s.work_resume(&caller("inst"), Some(3), handle, l));
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
    let s = run(|l| r.s.work_resume(&caller("other"), Some(1), handle, l));
    assert_eq!(
        (s.outcome, s.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
}

/// THE SETTLE IS SCOPED WHILE THE HANDLE'S UNIT RUNS (ARCHITECT 2026-10-07 K4-11 (B)): while the
/// unit that opened or resumed a handle is in flight, only its principal settles it; another
/// principal, or a crossing serving no unit, is refused exactly as a handle nobody holds is.
#[test]
fn settle_of_a_live_handle_is_refused_to_another_principal() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"working");
    let nobodys = settle(&r, "inst", Some(3), 999, b"swept");
    assert_eq!(
        (nobodys.outcome, nobodys.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
    // Bob, while alice's unit 1 runs; and a crossing that serves no unit.
    assert_eq!(settle(&r, "inst", Some(3), handle, b"swept"), nobodys);
    assert_eq!(settle(&r, "inst", None, handle, b"swept"), nobodys);
    // Another instance, even as alice.
    assert_eq!(settle(&r, "other", Some(1), handle, b"swept"), nobodys);
    // Nothing moved: the handle is live with alice's record.
    assert_eq!(
        state_and_record(&find(&r, "inst", 2, &reference)),
        (WORK_LIVE, b"working".to_vec())
    );
    // A handle resumed by a unit still in flight is that unit's, though its opener ended.
    let (resumed, _) = open(&r, 1, b"parked");
    let bound = run(|l| r.s.work_resume(&caller("inst"), Some(2), resumed, l));
    assert_eq!(bound.outcome, Outcome::Ready);
    r.s.units().ended(1);
    assert_eq!(settle(&r, "inst", Some(3), resumed, b"swept"), nobodys);
    // The owner settles its own live handle, from another of its units.
    let mine = settle(&r, "inst", Some(2), handle, b"done");
    assert_eq!((mine.outcome, mine.value), (Outcome::Ready, 0));
    assert_eq!(
        state_and_record(&find(&r, "inst", 2, &reference)),
        (WORK_SETTLED, b"done".to_vec())
    );
}

/// THE SWEEP KEEPS WORKING: once every unit a handle was opened or resumed by has ended (or
/// lapsed: its end removes it from the unit table all the same), the instance settles it from
/// whatever unit's crossing runs the sweep, whoever that unit's principal is.
#[test]
fn a_sweep_settles_a_handle_whose_units_have_ended() {
    let r = rig();
    let (opened, oref) = open(&r, 1, b"abandoned");
    let (resumed, rref) = open(&r, 1, b"parked");
    let bound = run(|l| r.s.work_resume(&caller("inst"), Some(2), resumed, l));
    assert_eq!(bound.outcome, Outcome::Ready);
    r.s.units().ended(1);
    r.s.units().ended(2);
    // Bob's unit runs the sweep.
    let swept = settle(&r, "inst", Some(3), opened, b"cancelled");
    assert_eq!((swept.outcome, swept.value), (Outcome::Ready, 0));
    let swept = settle(&r, "inst", Some(3), resumed, b"lapsed");
    assert_eq!((swept.outcome, swept.value), (Outcome::Ready, 0));
    // Alice, in a new unit, reads what the sweep wrote; it settles once.
    r.s.units().admitted(
        4,
        UnitRecord {
            principal: Some(key("alice")),
            depth: 0,
        },
    );
    assert_eq!(
        state_and_record(&find(&r, "inst", 4, &oref)),
        (WORK_SETTLED, b"cancelled".to_vec())
    );
    assert_eq!(
        state_and_record(&find(&r, "inst", 4, &rref)),
        (WORK_SETTLED, b"lapsed".to_vec())
    );
    let again = settle(&r, "inst", Some(3), opened, b"again");
    assert_eq!(
        (again.outcome, again.error),
        (Outcome::Refused, refusal::SETTLED)
    );
    // Still only the instance's own.
    let (theirs, _) = open(&r, 4, b"x");
    r.s.units().ended(4);
    let refused = settle(&r, "other", Some(3), theirs, b"y");
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
}

/// THE KERNEL JUDGES LAPSE, NEVER THE PLANE: a plane's own deadline passing and the record it
/// settles with saying "lapsed" move nothing while the handle's unit is in flight.
#[test]
fn a_plane_claiming_lapsed_cannot_settle_a_live_handle() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"asked");
    // A day on: past any deadline the plane keeps, and past retention.
    r.clock.fetch_add(86_400_000, Ordering::SeqCst);
    let claimed = settle(&r, "inst", Some(3), handle, b"lapsed");
    assert_eq!(
        (claimed.outcome, claimed.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
    assert_eq!(
        state_and_record(&find(&r, "inst", 2, &reference)),
        (WORK_LIVE, b"asked".to_vec())
    );
    // The store holds it live too.
    let row = r
        .store
        .record_get(
            WORK_SCHEMA,
            &work_key("inst", &parse_reference(&reference).unwrap()),
        )
        .unwrap()
        .unwrap();
    let held = Work::read(
        &Arc::from("inst"),
        parse_reference(&reference).unwrap(),
        row.as_slice(),
    );
    assert!(held.is_some_and(|w| w.live && w.record == b"asked"));
}

#[test]
fn an_open_is_refused_before_anything_is_written() {
    let r = rig();
    let refused = |s: Stored, why: &str| assert_eq!((s.outcome, s.error), (Outcome::Refused, why));
    refused(
        run(|l| {
            r.s.work_open(&caller("inst"), Some(1), "undeclared", b"r", l)
        }),
        NOT_A_KIND,
    );
    refused(
        run(|l| {
            r.s.work_open(
                &caller("inst"),
                Some(1),
                "job",
                &[0; MAX_WORK_RECORD + 1],
                l,
            )
        }),
        refusal::TOO_LONG,
    );
    // No unit in flight, or no unit at all.
    refused(
        run(|l| r.s.work_open(&caller("inst"), Some(99), "job", b"r", l)),
        refusal::NO_UNIT,
    );
    refused(
        run(|l| r.s.work_open(&caller("inst"), None, "job", b"r", l)),
        refusal::NO_UNIT,
    );
    refused(
        run(|l| r.s.work_find(&caller("inst"), None, b"r", l)),
        refusal::NO_UNIT,
    );
    assert_eq!(r.s.work().held(), 0);
    // The longest record round-trips through its row.
    let (_, reference) = open(&r, 1, &[7; MAX_WORK_RECORD]);
    assert_eq!(
        state_and_record(&find(&r, "inst", 1, &reference)).1,
        vec![7; MAX_WORK_RECORD]
    );
}

#[test]
fn a_row_round_trips_and_a_tombstone_reads_as_nothing() {
    let instance: Arc<str> = Arc::from("inst");
    let w = Work {
        instance: Arc::clone(&instance),
        reference: [9; 16],
        kind: "job".into(),
        owner: owner_of(Some("alice")),
        live: false,
        opened_ms: 5,
        settled_ms: 6,
        record: b"rec".to_vec(),
        bound: None,
        opened_by: None,
    };
    let row = w.row().unwrap();
    assert!(row.as_slice().len() <= busbar_contract::bounded::MAX_RECORD_BYTES);
    assert_eq!(Work::read(&instance, [9; 16], row.as_slice()), Some(w));
    assert_eq!(Work::read(&instance, [9; 16], &[]), None);
    assert_ne!(owner_of(Some("alice")), owner_of(None));
    assert_ne!(owner_of(Some("")), owner_of(None));
}

#[test]
fn a_sections_work_bounds_fall_back_to_the_hosts_key_by_key() {
    let host = WorkBounds {
        max_live: 9,
        retain_ms: 5_000,
    };
    let of = |yaml: &str| {
        let v: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        WorkBounds::of_section("p", &v, host)
    };
    assert_eq!(of("entry: {}"), Ok(host), "no work: is the host's whole");
    assert_eq!(
        of("work: {max_live: 2, retain_s: 60}"),
        Ok(WorkBounds {
            max_live: 2,
            retain_ms: 60_000
        })
    );
    assert_eq!(
        of("work: {retain_s: 0}"),
        Ok(WorkBounds {
            max_live: 9,
            retain_ms: 0
        })
    );
    for bad in [
        "work: [1]",
        "work: {max_live: 0}",
        "work: {max_live: -3}",
        "work: {max_live: 1.5}",
        "work: {retain_s: soon}",
        "work: {retain_s: 18446744073709551615}",
        "work: {live: 1}",
    ] {
        let refused = of(bad).expect_err(bad);
        assert!(refused.starts_with("`p.work`"), "{bad}: {refused}");
    }
}
