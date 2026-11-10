// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

trait ReadyAdmission {
    fn admit_ready(
        &self,
        instance: &str,
        facts: crate::host_services::InstanceFacts,
    ) -> Result<(), crate::host_services::AdmitRefused>;
}
impl ReadyAdmission for crate::host_services::KernelServices {
    fn admit_ready(
        &self,
        instance: &str,
        facts: crate::host_services::InstanceFacts,
    ) -> Result<(), crate::host_services::AdmitRefused> {
        futures::FutureExt::now_or_never(self.admit(instance, facts))
            .expect("in-memory fixture admission finishes in one poll")
    }
}
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::service::{self as svc, MAX_WORK_RECORD, WORK_LIVE, WORK_SETTLED};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::records::VirtualKey;
use busbar_contract::services::{HostServices, Later, Ran, Stored};

use super::*;
use crate::persistence::{facade::CoreStore, scoped::ScopedStore};
use busbar_contract::persistence::{self as native, PersistenceBackend};

fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    futures::executor::block_on(future)
}

// Native work jobs can schedule a write job while they are running. Each inline rendezvous
// gets its own executor so that nested scheduling preserves the old fixture's callback order.
fn finish(job: crate::host_services::AsyncJob) {
    if let Err(panic) = std::thread::spawn(move || ready(job)).join() {
        std::panic::resume_unwind(panic);
    }
}
fn core() -> Arc<CoreStore> {
    ready(crate::real_store::core())
}
fn scoped(store: &Arc<CoreStore>) -> ScopedStore {
    ScopedStore::host_private(store.clone(), "inst", [WORK_SCHEMA.as_str().into()]).unwrap()
}
fn read_row(store: &Arc<CoreStore>, reference: &[u8]) -> Option<Vec<u8>> {
    ready(scoped(store).get(WORK_SCHEMA.as_str(), reference))
        .unwrap()
        .map(|value| value.expose(&crate::seal::lend()).clone())
}
fn write_row(store: &Arc<CoreStore>, reference: &[u8], value: Vec<u8>) {
    assert!(matches!(
        ready(scoped(store).put(
            WORK_SCHEMA.as_str(),
            reference,
            busbar_contract::Secret::new(value)
        ))
        .unwrap(),
        crate::persistence::scoped::Outcome::Applied
    ));
}

use crate::host_services::tests::caller;
use crate::host_services::{InstanceFacts, KernelServices, Offload, NOT_A_KIND, POOL_REFUSED};
use crate::host_units::UnitRecord;

struct Inline;

impl Offload for Inline {
    fn run_async(&self, job: crate::host_services::AsyncJob) {
        self.run(Box::new(move || finish(job)));
    }
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

/// Runs every job at once while open; once shut, drops every job unrun, as a pool past its bound
/// does.
#[derive(Default)]
struct Gate(AtomicBool);

impl Offload for Gate {
    fn run_async(&self, job: crate::host_services::AsyncJob) {
        self.run(Box::new(move || finish(job)));
    }
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        if !self.0.load(Ordering::SeqCst) {
            job();
        }
    }
}

const KIND: RecordSchemaId = RecordSchemaId::new("job");

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
    store: Arc<CoreStore>,
    clock: Arc<AtomicU64>,
}

fn rig_over(store: Arc<CoreStore>, bounds: WorkBounds) -> Rig {
    rig_with_core(store, bounds)
}
fn rig_with_backend(
    store: Arc<CoreStore>,
    bounds: WorkBounds,
    backend: Arc<dyn PersistenceBackend>,
) -> Rig {
    let attached = ready(crate::real_store::core_over(backend));
    let mut rig = rig_with_core(attached, bounds);
    rig.store = store;
    rig
}
fn rig_with_core(store: Arc<CoreStore>, bounds: WorkBounds) -> Rig {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let c = Arc::clone(&clock);
    let s = KernelServices::new()
        .with_pool(Arc::new(Inline))
        .with_work_bounds(bounds)
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    assert!(s.attach_persistence(store.clone()));
    for label in ["inst", "other"] {
        s.admit_ready(
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
    rig_over(core(), WorkBounds::default())
}

fn run(f: impl FnOnce(Later) -> Ran) -> Stored {
    let slot: Arc<Mutex<Option<Stored>>> = Arc::default();
    let mine = Arc::clone(&slot);
    match f(Box::new(move |s| *mine.lock().unwrap() = Some(s))) {
        Ran::Now(s) => s,
        Ran::Later => slot.lock().unwrap().take().expect("the later was answered"),
    }
}

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

fn settle(r: &Rig, instance: &str, unit: Option<u64>, handle: u64, record: &[u8]) -> Stored {
    run(|l| r.s.work_settle(&caller(instance), unit, handle, record, l))
}

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

    let found = find(&r, "inst", 2, &reference);
    assert_eq!((found.outcome, found.value), (Outcome::Ready, handle));
    assert_eq!(state_and_record(&found), (WORK_LIVE, b"rec-1".to_vec()));

    let (_, second) = open(&r, 1, b"rec-2");
    assert_ne!(second, reference);
}

#[test]
fn every_denial_of_a_lookup_answers_alike() {
    let r = rig();
    let (_, reference) = open(&r, 1, b"rec");
    let denied = [
        find(&r, "inst", 3, &reference),
        find(&r, "other", 1, &reference),
        find(&r, "inst", 1, b"0123456789abcdef0123456789abcdef"),
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
        core(),
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

    assert_eq!(find(&r, "inst", 1, &r1).value, h1);
    assert_ne!(find(&r, "inst", 1, &r2).value, svc::ABSENT);

    let elsewhere = run(|l| r.s.work_open(&caller("other"), Some(1), "job", b"c", l));
    assert_eq!(elsewhere.outcome, Outcome::Ready);

    let _ = settle(&r, "inst", Some(1), h1, b"done");
    let _ = open(&r, 1, b"c");
}

#[test]
fn retention_bounds_only_settled_handles_and_the_sweep_runs_on_submit() {
    let r = rig_over(
        core(),
        WorkBounds {
            max_live: 16,
            retain_ms: 1_000,
        },
    );
    let (settled, sref) = open(&r, 1, b"a");
    let (live, lref) = open(&r, 1, b"b");
    let _ = settle(&r, "inst", Some(1), settled, b"done");
    r.clock.fetch_add(1_000, Ordering::SeqCst);

    assert_eq!(find(&r, "inst", 1, &sref), Stored::ready(svc::ABSENT));
    assert_eq!(find(&r, "inst", 1, &lref).value, live);

    let row = |reference: &[u8]| {
        let reference = parse_reference(reference).unwrap();
        read_row(&r.store, &reference).unwrap_or_default()
    };
    assert!(!row(&sref).is_empty());

    let held = r.s.work().held();
    let _ = open(&r, 1, b"c");
    assert_eq!(r.s.work().held(), held, "one swept, one opened");
    assert!(row(&sref).is_empty(), "the swept row is struck");
    assert!(!row(&lref).is_empty(), "a live row is never struck");
}

#[test]
fn a_sweep_removes_the_swept_rows_from_the_store() {
    let r = rig_over(
        core(),
        WorkBounds {
            max_live: 16,
            retain_ms: 1_000,
        },
    );
    let rows = || {
        let mut cursor = None;
        let mut count = 0;
        loop {
            let page =
                ready(scoped(&r.store).page(WORK_SCHEMA.as_str(), &[], cursor.as_ref())).unwrap();
            count += page
                .rows
                .iter()
                .filter(|(_, value)| !value.expose(&crate::seal::lend()).is_empty())
                .count();
            cursor = page.next;
            if cursor.is_none() {
                return count;
            }
        }
    };
    let (a, _) = open(&r, 1, b"a");
    let (b, _) = open(&r, 1, b"b");
    let _ = open(&r, 1, b"live");
    let _ = settle(&r, "inst", Some(1), a, b"done");
    let _ = settle(&r, "inst", Some(1), b, b"done");
    assert_eq!(rows(), 3, "three handles, three rows");
    r.clock.fetch_add(1_000, Ordering::SeqCst);

    let _ = open(&r, 1, b"c");
    assert_eq!(rows(), 2, "two swept rows removed, one row opened");
}

#[test]
fn a_handle_is_found_and_resumed_after_a_restart() {
    let store = core();
    let bounds = WorkBounds {
        max_live: 2,
        retain_ms: 1_000,
    };
    let before = rig_over(Arc::clone(&store), bounds);
    let (_, reference) = open(&before, 1, b"park");
    let (_, other) = open(&before, 1, b"park-2");
    drop(before);

    let after = rig_over(Arc::clone(&store), bounds);
    let found = find(&after, "inst", 2, &reference);
    assert_eq!(found.outcome, Outcome::Ready);
    assert_ne!(found.value, svc::ABSENT);
    assert_eq!(state_and_record(&found), (WORK_LIVE, b"park".to_vec()));

    let resumed = run(|l| {
        after
            .s
            .work_resume(&caller("inst"), Some(2), found.value, l)
    });
    assert_eq!((resumed.outcome, resumed.value), (Outcome::Ready, 0));
    assert_eq!(state_and_record(&resumed), (WORK_LIVE, b"park".to_vec()));

    let _ = open(&after, 1, b"y");
    let _ = open(&after, 1, b"z");
    let refused = run(|l| after.s.work_open(&caller("inst"), Some(1), "job", b"!", l));
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Refused, refusal::AT_BOUND)
    );

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

#[test]
fn settle_of_a_live_handle_is_refused_to_another_principal() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"working");
    let nobodys = settle(&r, "inst", Some(3), 999, b"swept");
    assert_eq!(
        (nobodys.outcome, nobodys.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );

    assert_eq!(settle(&r, "inst", Some(3), handle, b"swept"), nobodys);
    assert_eq!(settle(&r, "inst", None, handle, b"swept"), nobodys);

    assert_eq!(settle(&r, "other", Some(1), handle, b"swept"), nobodys);

    assert_eq!(
        state_and_record(&find(&r, "inst", 2, &reference)),
        (WORK_LIVE, b"working".to_vec())
    );

    let (resumed, _) = open(&r, 1, b"parked");
    let bound = run(|l| r.s.work_resume(&caller("inst"), Some(2), resumed, l));
    assert_eq!(bound.outcome, Outcome::Ready);
    r.s.units().ended(1);
    assert_eq!(settle(&r, "inst", Some(3), resumed, b"swept"), nobodys);

    let mine = settle(&r, "inst", Some(2), handle, b"done");
    assert_eq!((mine.outcome, mine.value), (Outcome::Ready, 0));
    assert_eq!(
        state_and_record(&find(&r, "inst", 2, &reference)),
        (WORK_SETTLED, b"done".to_vec())
    );
}

#[test]
fn a_sweep_settles_a_handle_whose_units_have_ended() {
    let r = rig();
    let (opened, oref) = open(&r, 1, b"abandoned");
    let (resumed, rref) = open(&r, 1, b"parked");
    let bound = run(|l| r.s.work_resume(&caller("inst"), Some(2), resumed, l));
    assert_eq!(bound.outcome, Outcome::Ready);
    r.s.units().ended(1);
    r.s.units().ended(2);

    let swept = settle(&r, "inst", Some(3), opened, b"cancelled");
    assert_eq!((swept.outcome, swept.value), (Outcome::Ready, 0));
    let swept = settle(&r, "inst", Some(3), resumed, b"lapsed");
    assert_eq!((swept.outcome, swept.value), (Outcome::Ready, 0));

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

    let (theirs, _) = open(&r, 4, b"x");
    r.s.units().ended(4);
    let refused = settle(&r, "other", Some(3), theirs, b"y");
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
}

#[test]
fn the_owners_find_scopes_the_settle_of_a_handle_read_from_the_store() {
    let store = core();
    let before = rig_over(Arc::clone(&store), WorkBounds::default());
    let (_, reference) = open(&before, 1, b"park");
    drop(before);

    let after = rig_over(store, WorkBounds::default());
    let found = find(&after, "inst", 2, &reference);
    assert_eq!(state_and_record(&found), (WORK_LIVE, b"park".to_vec()));
    let refused = settle(&after, "inst", Some(3), found.value, b"swept");
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );

    assert_eq!(
        find(&after, "inst", 3, &reference),
        Stored::ready(svc::ABSENT)
    );
    after.s.units().ended(2);
    let swept = settle(&after, "inst", Some(3), found.value, b"swept");
    assert_eq!((swept.outcome, swept.value), (Outcome::Ready, 0));

    let r = rig();
    let (handle, reference) = open(&r, 1, b"working");
    let bound = run(|l| r.s.work_resume(&caller("inst"), Some(2), handle, l));
    assert_eq!(bound.outcome, Outcome::Ready);
    r.s.units().admitted(
        4,
        UnitRecord {
            principal: Some(key("alice")),
            depth: 0,
        },
    );
    assert_eq!(find(&r, "inst", 4, &reference).value, handle);
    r.s.units().ended(4);
    r.s.units().ended(1);
    let refused = settle(&r, "inst", Some(3), handle, b"swept");
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Refused, refusal::NOT_A_HANDLE)
    );
}

#[test]
fn a_plane_claiming_lapsed_cannot_settle_a_live_handle() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"asked");

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

    let row = read_row(&r.store, &parse_reference(&reference).unwrap()).unwrap();
    let held = Work::read(
        &Arc::from("inst"),
        parse_reference(&reference).unwrap(),
        row.as_slice(),
    );
    assert!(held.is_some_and(|w| w.live && w.record == b"asked"));
}

#[test]
fn a_settle_the_pool_refuses_leaves_the_handle_live_in_the_book_and_the_store() {
    let gate = Arc::new(Gate::default());
    let r = rig();
    let s = r.s.with_pool(Arc::clone(&gate) as Arc<dyn Offload>);
    let r = Rig { s, ..r };
    let (handle, reference) = open(&r, 1, b"working");
    gate.0.store(true, Ordering::SeqCst);
    let refused = settle(&r, "inst", Some(1), handle, b"done");
    assert_eq!(
        (refused.outcome, refused.error),
        (Outcome::Failed, POOL_REFUSED)
    );
    let booked = r.s.work().get("inst", handle).expect("still held");
    assert!(
        booked.live && booked.record == b"working",
        "the book holds it live"
    );
    let row = read_row(&r.store, &parse_reference(&reference).unwrap()).unwrap();
    let stored = Work::read(&Arc::from("inst"), booked.reference, row.as_slice()).unwrap();
    assert!(
        stored.live && stored.record == b"working",
        "the store holds it live"
    );

    gate.0.store(false, Ordering::SeqCst);
    let landed = settle(&r, "inst", Some(1), handle, b"done");
    assert_eq!((landed.outcome, landed.value), (Outcome::Ready, 0));
    assert_eq!(
        state_and_record(&find(&r, "inst", 2, &reference)),
        (WORK_SETTLED, b"done".to_vec())
    );
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
        recovery: None,
    };
    let row = w.row().unwrap();
    assert!(row.as_slice().len() <= busbar_contract::bounded::MAX_RECORD_BYTES);
    assert_eq!(Work::read(&instance, [9; 16], row.as_slice()), Some(w));
    assert_eq!(Work::read(&instance, [9; 16], &[]), None);
    assert_ne!(owner_of(Some("alice")), owner_of(None));
    assert_ne!(owner_of(Some("")), owner_of(None));
}

fn recovery_principal(r: &Rig) -> Arc<VirtualKey> {
    r.s.set_recovery_scheduler_ready(true);
    let key = Arc::new(VirtualKey {
        id: "alice".into(),
        generation_hash: "binding:alice:1".into(),
        enabled: true,
        created_at: 10,
        ..VirtualKey::default()
    });
    r.s.units().admitted(
        1,
        UnitRecord {
            principal: Some(key.clone()),
            depth: 0,
        },
    );
    r.s.attach_standing(Arc::new(|key, _| Some(key.clone())));
    key
}

#[test]
fn recovery_work_reopens_only_durable_original_owner_and_settles_normally() {
    let r = rig();
    let key = recovery_principal(&r);
    ready(r.store.identity().put_key(&key)).unwrap();
    let record = busbar_contract::abi::sdk::recovery::poll_record("/jobs/42").unwrap();
    let (_, reference) = open(&r, 1, &record);
    let restarted = rig_over(r.store.clone(), WorkBounds::default());
    let gov = ready(crate::governance::GovState::new_with_core(
        r.store.clone(),
        None,
        None,
    ))
    .unwrap();
    let work = ready(restarted.s.recovery_work(&caller("inst"))).unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].target(), "/jobs/42");
    assert_eq!(work[0].reference().as_bytes(), reference);
    assert_eq!(work[0].restore(&gov, 1000).unwrap().id, "alice");
    assert!(ready(restarted.s.recovery_work(&caller("other")))
        .unwrap()
        .is_empty());
    assert!(
        ready(restarted.s.recovery_work(&caller("inst")))
            .unwrap()
            .is_empty(),
        "exclusive host owner"
    );
    drop(work);
    gov.set_signing_key(Some(
        crate::governance::signing::TokenSigner::from_secret_bytes(&[9; 32], "new"),
    ));
    let work = ready(restarted.s.recovery_work(&caller("inst"))).unwrap();
    assert!(
        work[0].restore(&gov, 1000).is_some(),
        "signer rotation does not revoke original binding"
    );
    let found = find(&restarted, "inst", 1, &reference);
    assert_eq!(found.outcome, Outcome::Ready);
    assert_eq!(
        settle(&restarted, "inst", Some(1), found.value, b"done").outcome,
        Outcome::Ready
    );
    drop(work);
    assert!(ready(restarted.s.recovery_work(&caller("inst")))
        .unwrap()
        .is_empty());
    assert_eq!(
        state_and_record(&find(&restarted, "inst", 1, &reference)),
        (WORK_SETTLED, b"done".to_vec())
    );
}

#[test]
fn recovery_work_refuses_missing_standing_and_reissued_or_disabled_identity() {
    let r = rig();
    assert!(!r.s.supports_unit_recovery(&caller("inst"), 1));
    let record = busbar_contract::abi::sdk::recovery::poll_record("/jobs/42").unwrap();
    assert_eq!(
        run(|later| r
            .s
            .work_open(&caller("inst"), Some(1), "job", &record, later))
        .outcome,
        Outcome::Refused
    );
    let key = recovery_principal(&r);
    assert!(r.s.supports_unit_recovery(&caller("inst"), 1));
    assert!(!r.s.supports_unit_recovery(&caller("other"), 999));
    ready(r.store.identity().put_key(&key)).unwrap();
    open(&r, 1, &record);
    let work = ready(r.s.recovery_work(&caller("inst"))).unwrap();
    for mutate in [0, 1, 2, 3] {
        let mut changed = (*key).clone();
        match mutate {
            0 => changed.enabled = false,
            1 => changed.generation_hash = "replacement".into(),
            2 => changed.created_at += 1,
            _ => changed.expires_at = Some(500),
        }
        ready(r.store.identity().put_key(&changed)).unwrap();
        let gov = ready(crate::governance::GovState::new_with_core(
            r.store.clone(),
            None,
            None,
        ))
        .unwrap();
        assert!(work[0].restore(&gov, 1000).is_none());
    }
}

#[test]
fn recovery_capability_is_absent_for_external_identity_without_verified_expiry() {
    let r = rig();
    recovery_principal(&r);
    let bindings = [(
        "idp".into(),
        [("reader".into(), crate::config::RoleBindingCfg::default())].into(),
    )]
    .into();
    let mut key = crate::governance::synthesize_bound_key(
        "idp",
        &crate::auth::Principal {
            id: "external".into(),
            name: None,
            roles: vec!["reader".into()],
            ttl_secs: Some(900),
        },
        &bindings,
    )
    .unwrap();
    r.s.units().admitted(
        1,
        UnitRecord {
            principal: Some(key.clone()),
            depth: 0,
        },
    );
    assert!(
        !r.s.supports_unit_recovery(&caller("inst"), 1),
        "cache TTL must not enable recovery"
    );
    Arc::make_mut(&mut key).expires_at = Some(1100);
    r.s.units().admitted(
        1,
        UnitRecord {
            principal: Some(key),
            depth: 0,
        },
    );
    assert!(r.s.supports_unit_recovery(&caller("inst"), 1));
    r.clock.store(1_100_000, Ordering::SeqCst);
    assert!(!r.s.supports_unit_recovery(&caller("inst"), 1));
}

#[test]
fn durable_caller_binding_survives_rekey_restart_and_remains_owner_scoped() {
    let r = rig();
    let old = crate::auth::CallerRefKey::derive(b"old signer").caller_ref("alice");
    let new = crate::auth::CallerRefKey::derive(b"new signer").caller_ref("alice");
    assert_ne!(old, new);
    assert_eq!(
        ready(r.s.resolve_caller_reference(&caller("inst"), "alice", &old)).unwrap(),
        old
    );
    let restarted = rig_over(r.store.clone(), WorkBounds::default());
    assert_eq!(
        ready(
            restarted
                .s
                .resolve_caller_reference(&caller("inst"), "alice", &new)
        )
        .unwrap(),
        old
    );
    assert_eq!(
        ready(
            restarted
                .s
                .resolve_caller_reference(&caller("other"), "alice", &new)
        )
        .unwrap(),
        new
    );
    let bob = crate::auth::CallerRefKey::derive(b"new signer").caller_ref("bob");
    assert_eq!(
        ready(
            restarted
                .s
                .resolve_caller_reference(&caller("inst"), "bob", &bob)
        )
        .unwrap(),
        bob
    );
    assert!(ready(
        restarted
            .s
            .resolve_caller_reference(&caller("unadmitted"), "alice", &new)
    )
    .is_err());
}

#[test]
fn recovery_work_scan_keeps_later_items_when_batches_are_bounded() {
    let r = rig();
    recovery_principal(&r);
    for id in 0..12 {
        open(
            &r,
            1,
            &busbar_contract::abi::sdk::recovery::poll_record(&format!("/jobs/{id}")).unwrap(),
        );
    }
    let first = ready(r.s.recovery_work(&caller("inst"))).unwrap();
    let second = ready(r.s.recovery_work(&caller("inst"))).unwrap();
    assert_eq!((first.len(), second.len()), (8, 4));
    let references: std::collections::HashSet<_> =
        first.iter().chain(&second).map(|w| w.reference()).collect();
    assert_eq!(references.len(), 12);
    assert!(ready(r.s.recovery_work(&caller("inst")))
        .unwrap()
        .is_empty());
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

#[test]
fn inspection_reads_actual_work_times_and_current_retention_without_inventing_live_expiry() {
    use busbar_contract::abi::mechanism::inspection::{
        InspectionObservation, InspectionQuery, WorkObservation,
    };
    let r = rig();
    let (handle, reference) = open(&r, 1, b"work");
    let query = InspectionQuery::Work { reference };
    r.clock.store(1_000_100, Ordering::SeqCst);
    assert_eq!(
        r.s.inspect(&caller("inst"), Some(2), &query),
        Ok(InspectionObservation::Work(WorkObservation {
            observed_ms: 1_000_100,
            opened_ms: 1_000_000,
            retain_ms: 300_000,
            settled_ms: None,
        }))
    );
    assert_eq!(
        settle(&r, "inst", Some(1), handle, b"done").outcome,
        Outcome::Ready
    );
    r.s.bound_work(
        "inst",
        WorkBounds {
            max_live: 17,
            retain_ms: 700,
        },
    );
    r.clock.store(1_000_200, Ordering::SeqCst);
    assert_eq!(
        r.s.inspect(&caller("inst"), Some(2), &query),
        Ok(InspectionObservation::Work(WorkObservation {
            observed_ms: 1_000_200,
            opened_ms: 1_000_000,
            retain_ms: 700,
            settled_ms: Some(1_000_100),
        }))
    );

    r.s.bound_work(
        "inst",
        WorkBounds {
            max_live: 17,
            retain_ms: 0,
        },
    );
    assert_eq!(
        r.s.inspect(&caller("inst"), Some(2), &query),
        Err(busbar_contract::abi::mechanism::inspection::InspectionError::NotFound)
    );
}

#[test]
fn inspection_work_denials_collapse_and_only_an_actual_find_imports_durable_work() {
    use busbar_contract::abi::mechanism::inspection::{InspectionError, InspectionQuery};
    let r = rig();
    let (handle, reference) = open(&r, 1, b"private");
    let query = InspectionQuery::Work {
        reference: reference.clone(),
    };
    for (instance, unit) in [("inst", 3), ("other", 1)] {
        assert_eq!(
            r.s.inspect(&caller(instance), Some(unit), &query),
            Err(InspectionError::NotFound)
        );
    }
    for unit in [None, Some(999)] {
        assert_eq!(
            r.s.inspect(&caller("inst"), unit, &query),
            Err(InspectionError::Refused)
        );
    }
    assert_eq!(
        r.s.inspect(&caller("unknown"), Some(1), &query),
        Err(InspectionError::Refused)
    );
    let restarted = rig_over(Arc::clone(&r.store), WorkBounds::default());
    assert_eq!(
        restarted.s.inspect(&caller("inst"), Some(1), &query),
        Err(InspectionError::NotFound)
    );
    assert_ne!(find(&restarted, "inst", 1, &reference).value, svc::ABSENT);
    assert!(restarted
        .s
        .inspect(&caller("inst"), Some(1), &query)
        .is_ok());
    assert_eq!(
        settle(&r, "inst", Some(1), handle, b"done").outcome,
        Outcome::Ready
    );
    r.clock.fetch_add(300_000, Ordering::SeqCst);
    assert_eq!(
        r.s.inspect(&caller("inst"), Some(1), &query),
        Err(InspectionError::NotFound)
    );
    assert_eq!(
        r.s.inspect(
            &caller("inst"),
            Some(1),
            &InspectionQuery::Work {
                reference: b"bad".to_vec()
            }
        ),
        Err(InspectionError::NotFound)
    );
}

#[test]
fn inspection_carriers_are_instance_owned_point_in_time_observations_without_callbacks() {
    use busbar_contract::abi::mechanism::inspection::{
        InspectionObservation, InspectionQuery, SessionObservation,
    };
    let r = rig();
    let me = caller("inst");
    let sink: crate::host_services::CarrierSink =
        Arc::new(|_| panic!("inspection must not call the sink"));
    let alice = r.s.open_carrier_session(&me, "alice", Arc::clone(&sink));
    let bob = r.s.open_carrier_session(&me, "bob", Arc::clone(&sink));
    let foreign = r.s.open_carrier_session(&caller("other"), "alice", sink);
    let query = InspectionQuery::CarrierSessions {
        sessions: vec![alice, bob, foreign, u64::MAX],
    };
    let observation = |live| {
        Ok(InspectionObservation::CarrierSessions(vec![
            SessionObservation {
                session: alice,
                live,
            },
            SessionObservation {
                session: bob,
                live: true,
            },
            SessionObservation {
                session: foreign,
                live: false,
            },
            SessionObservation {
                session: u64::MAX,
                live: false,
            },
        ]))
    };

    let earlier = r.s.inspect(&me, None, &query);
    assert_eq!(earlier, observation(true));
    let replacement = r.s.inspect(&caller("inst"), None, &query).unwrap();
    let InspectionObservation::CarrierSessions(replacement) = replacement else {
        panic!("carrier observation");
    };
    assert!(
        replacement.iter().all(|row| !row.live),
        "reopened caller inherits no sessions"
    );
    r.s.close_carrier_session(alice);
    assert_eq!(r.s.inspect(&me, None, &query), observation(false));
    assert_eq!(
        earlier,
        observation(true),
        "the old observation is a copied fact, not a lease"
    );
}

/// One exact queued crossing; independent later jobs still run so an open can race its settlement.
#[derive(Default)]
struct HoldNext {
    armed: AtomicBool,
    job: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Offload for HoldNext {
    fn run_async(&self, job: crate::host_services::AsyncJob) {
        self.run(Box::new(move || finish(job)));
    }
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        if self.armed.swap(false, Ordering::SeqCst) {
            assert!(self.job.lock().unwrap().replace(job).is_none());
        } else {
            job();
        }
    }
}

type AttemptWitness = Arc<Mutex<Vec<(native::AttemptId, [u8; 32])>>>;
struct SettlementBackend {
    attempts: AttemptWitness,
    store: Arc<CoreStore>,
    mode: Arc<AtomicU64>,
}
impl PersistenceBackend for SettlementBackend {
    fn info(&self) -> native::BackendInfo {
        self.store.backend().info()
    }
    fn read(&self, request: Arc<native::Read>) -> native::Call<'_, native::ReadResult> {
        Box::pin(async move {
            match self.mode.load(Ordering::SeqCst) {
                5 => Err(native::Failure::Unavailable),
                6 => Err(native::Failure::Unknown),
                _ => self.store.backend().read(request).await,
            }
        })
    }
    fn scan(&self, request: Arc<native::Scan>) -> native::Call<'_, native::Page> {
        self.store.backend().scan(request)
    }
    fn commit(&self, candidate: native::PreparedCandidate) -> native::Call<'_, native::Decision> {
        Box::pin(async move {
            self.attempts
                .lock()
                .unwrap()
                .push((candidate.candidate().id, candidate.fingerprint()));
            match self.mode.load(Ordering::SeqCst) {
                1 => Err(native::Failure::Refused),
                2 => {
                    self.store.backend().commit(candidate).await?;
                    Err(native::Failure::Unknown)
                }
                3 => panic!("settlement Store unwound"),
                _ => self.store.backend().commit(candidate).await,
            }
        })
    }
    fn clock(&self, dataset: native::DatasetId) -> native::Call<'_, native::ClockObservation> {
        self.store.backend().clock(dataset)
    }
}

#[test]
fn pending_settlement_keeps_capacity_and_survives_sweep_until_store_confirmation() {
    for mode in 0..=4 {
        let store = core();
        let store_mode = Arc::new(AtomicU64::new(0));

        let attempts: AttemptWitness = Arc::default();
        let r = rig_with_backend(
            store.clone(),
            WorkBounds {
                max_live: 1,
                retain_ms: 0,
            },
            Arc::new(SettlementBackend {
                attempts: attempts.clone(),
                store,
                mode: store_mode.clone(),
            }),
        );
        let (handle, reference) = open(&r, 1, b"working");
        let held = Arc::new(HoldNext::default());
        let s = r.s.with_pool(held.clone());
        held.armed.store(true, Ordering::SeqCst);
        let answer: Arc<Mutex<Option<Stored>>> = Arc::default();
        let put = answer.clone();
        assert!(matches!(
            s.work_settle(
                &caller("inst"),
                Some(1),
                handle,
                b"done",
                Box::new(move |value| *put.lock().unwrap() = Some(value))
            ),
            Ran::Later
        ));
        assert!(answer.lock().unwrap().is_none());
        let found = run(|later| s.work_find(&caller("inst"), Some(2), &reference, later));
        assert_eq!(
            state_and_record(&found),
            (WORK_LIVE, b"working".to_vec()),
            "mode {mode}"
        );
        assert_eq!(
            run(|later| s.work_settle(&caller("inst"), Some(1), handle, b"again", later)).error,
            refusal::SETTLED,
            "a second settlement cannot own the same handle"
        );
        assert_eq!(
            run(|later| s.work_resume(&caller("inst"), Some(2), handle, later)).outcome,
            Outcome::Ready
        );
        let attempted = run(|later| s.work_open(&caller("inst"), Some(1), "job", b"second", later));
        assert_eq!(
            (attempted.outcome, attempted.error),
            (Outcome::Refused, refusal::AT_BOUND),
            "mode {mode}"
        );
        assert_eq!(
            s.work().held(),
            1,
            "a zero-retention submit cannot sweep pending work"
        );
        let booked = s.work().get("inst", handle).unwrap();
        assert!(booked.live);
        assert_eq!(booked.bound, Some(2));

        let job = held.job.lock().unwrap().take().unwrap();
        attempts.lock().unwrap().clear();
        store_mode.store(mode, Ordering::SeqCst);
        if mode == 4 {
            drop(job);
        } else {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            assert_eq!(result.is_err(), mode == 3);
        }
        if matches!(mode, 2 | 3) {
            assert!(
                answer.lock().unwrap().is_none(),
                "an uncertain settlement retains its callback"
            );
            let booked = s.work().get("inst", handle).unwrap();
            assert!(booked.live && booked.record == b"working");
            assert_eq!(booked.bound, Some(2));
            assert_eq!(
                run(|later| s.work_open(&caller("inst"), Some(1), "job", b"second", later)).error,
                refusal::AT_BOUND
            );
            assert_eq!(s.work().held(), 1, "unknown work cannot be swept");
            store_mode.store(0, Ordering::SeqCst);
            s.flush_tick();
            assert_eq!(
                answer
                    .lock()
                    .unwrap()
                    .take()
                    .expect("matching receipt confirms settlement")
                    .outcome,
                Outcome::Ready
            );
            let observed = attempts.lock().unwrap();
            assert_eq!(observed.len(), 2);
            assert_eq!(
                observed[0], observed[1],
                "retry preserves the attempt identity and fingerprint"
            );
            drop(observed);
            let booked = s.work().get("inst", handle).unwrap();
            assert!(
                !booked.live && booked.record == b"done",
                "only the original payload is published"
            );
            assert_eq!(booked.bound, Some(2));
            let stored = read_row(&r.store, &booked.reference).unwrap();
            assert_eq!(
                Work::read(&Arc::from("inst"), booked.reference, &stored)
                    .unwrap()
                    .record,
                b"done"
            );
            assert_eq!(
                run(|later| s.work_open(&caller("inst"), Some(1), "job", b"second", later)).outcome,
                Outcome::Ready
            );
            continue;
        }
        let answered = answer
            .lock()
            .unwrap()
            .take()
            .expect("every exit answers its caller");
        assert_eq!(
            answered.outcome,
            if mode == 0 {
                Outcome::Ready
            } else {
                Outcome::Failed
            }
        );
        let booked = s.work().get("inst", handle).unwrap();
        assert_eq!(
            booked.bound,
            Some(2),
            "the intervening resume binding survives"
        );
        assert_eq!(booked.live, mode != 0);
        assert_eq!(
            booked.record.as_slice(),
            if mode == 0 {
                b"done".as_slice()
            } else {
                b"working".as_slice()
            }
        );
        store_mode.store(0, Ordering::SeqCst);
        if mode != 0 {
            assert_eq!(
                run(|later| s.work_open(&caller("inst"), Some(1), "job", b"second", later)).error,
                refusal::AT_BOUND,
                "an unconfirmed settlement never releases capacity"
            );
            assert_eq!(
                run(|later| s.work_settle(&caller("inst"), Some(2), handle, b"retried", later))
                    .outcome,
                Outcome::Ready,
                "ownership retired for a real retry"
            );
        }
        assert_eq!(
            run(|later| s.work_open(&caller("inst"), Some(1), "job", b"second", later)).outcome,
            Outcome::Ready,
            "only a confirmed settlement releases capacity"
        );
    }
}

#[test]
fn dropping_a_queued_settlement_retires_ownership_before_its_callback_retries() {
    let r = rig();
    let (handle, _) = open(&r, 1, b"working");
    let held = Arc::new(HoldNext::default());
    let s = Arc::new(r.s.with_pool(held.clone()));
    held.armed.store(true, Ordering::SeqCst);
    let retry = s.clone();
    let answered = Arc::new(AtomicBool::new(false));
    let seen = answered.clone();
    assert!(matches!(
        s.work_settle(
            &caller("inst"),
            Some(1),
            handle,
            b"done",
            Box::new(move |value| {
                assert_eq!(
                    (value.outcome, value.error),
                    (Outcome::Failed, POOL_REFUSED)
                );
                let retried = run(|later| {
                    retry.work_settle(&caller("inst"), Some(1), handle, b"retry", later)
                });
                assert_eq!(
                    retried.outcome,
                    Outcome::Ready,
                    "callback observes retired ownership"
                );
                seen.store(true, Ordering::SeqCst);
            })
        ),
        Ran::Later
    ));
    let job = held.job.lock().unwrap().take().unwrap();
    drop(job);
    assert!(answered.load(Ordering::SeqCst));
    assert_eq!(s.work().get("inst", handle).unwrap().record, b"retry");
}

fn status(s: &KernelServices, instance: &str, reference: &[u8]) -> Stored {
    let answer = run(|later| s.work_status(&caller(instance), reference, later));
    assert!(answer.bytes.is_empty());
    assert!(answer.spans.is_empty());
    answer
}

#[test]
fn work_status_is_instance_scoped_read_only_and_survives_restart() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"private record");
    let before = r.s.work().get("inst", handle).unwrap();
    assert_eq!(
        status(&r.s, "inst", &reference).value,
        svc::WORK_STATUS_LIVE
    );
    assert_eq!(
        status(&r.s, "other", &reference).value,
        svc::WORK_STATUS_ABSENT
    );
    assert_eq!(
        status(&r.s, "inst", b"00000000000000000000000000000000").value,
        svc::WORK_STATUS_ABSENT
    );
    assert_eq!(
        r.s.work().get("inst", handle).unwrap(),
        before,
        "observation does not bind or alter work"
    );
    assert_eq!(
        status(&r.s, "unadmitted", &reference).outcome,
        Outcome::Refused
    );
    assert_eq!(
        settle(&r, "inst", Some(1), handle, b"secret final record").outcome,
        Outcome::Ready
    );
    assert_eq!(
        status(&r.s, "inst", &reference).value,
        svc::WORK_STATUS_SETTLED
    );
    let restarted = rig_over(r.store.clone(), WorkBounds::default());
    assert_eq!(
        status(&restarted.s, "inst", &reference).value,
        svc::WORK_STATUS_SETTLED
    );
    assert_eq!(
        status(&restarted.s, "other", &reference).value,
        svc::WORK_STATUS_ABSENT
    );
    assert_eq!(
        restarted.s.work().held(),
        0,
        "receipt observation never adopts a handle"
    );
    restarted.clock.store(1_300_000, Ordering::SeqCst);
    assert_eq!(
        status(&restarted.s, "inst", &reference).value,
        svc::WORK_STATUS_ABSENT,
        "expired receipt is not proof"
    );
}

#[test]
fn work_status_requires_confirmed_settlement_and_preserves_failed_work() {
    for fails in [false, true] {
        let store = core();
        let mode = Arc::new(AtomicU64::new(0));
        let r = rig_with_backend(
            store.clone(),
            WorkBounds::default(),
            Arc::new(SettlementBackend {
                attempts: Arc::default(),
                store,
                mode: mode.clone(),
            }),
        );
        let (handle, reference) = open(&r, 1, b"live");
        let held = Arc::new(HoldNext::default());
        let s = r.s.with_pool(held.clone());
        held.armed.store(true, Ordering::SeqCst);
        let result: Arc<Mutex<Option<Stored>>> = Arc::default();
        let delivered = result.clone();
        assert!(matches!(
            s.work_settle(
                &caller("inst"),
                Some(1),
                handle,
                b"done",
                Box::new(move |answer| {
                    *delivered.lock().unwrap() = Some(answer);
                })
            ),
            Ran::Later
        ));
        assert_eq!(
            status(&s, "inst", &reference).value,
            svc::WORK_STATUS_SETTLING
        );
        assert_eq!(
            status(&s, "other", &reference).value,
            svc::WORK_STATUS_ABSENT
        );
        mode.store(u64::from(fails), Ordering::SeqCst);
        held.job.lock().unwrap().take().unwrap()();
        assert_eq!(
            result.lock().unwrap().take().unwrap().outcome,
            if fails {
                Outcome::Failed
            } else {
                Outcome::Ready
            }
        );
        assert_eq!(
            status(&s, "inst", &reference).value,
            if fails {
                svc::WORK_STATUS_LIVE
            } else {
                svc::WORK_STATUS_SETTLED
            }
        );
    }
}

#[test]
fn work_status_restart_rejects_corrupt_rows_and_handles_live_and_tombstoned_rows() {
    let r = rig();
    let (handle, reference) = open(&r, 1, b"live");
    let restarted = rig_over(r.store.clone(), WorkBounds::default());
    assert_eq!(
        status(&restarted.s, "inst", &reference).value,
        svc::WORK_STATUS_LIVE
    );
    assert_eq!(restarted.s.work().held(), 0);
    let work = r.s.work().get("inst", handle).unwrap();
    write_row(&r.store, &work.reference, vec![255]);
    assert_eq!(
        status(&restarted.s, "inst", &reference).outcome,
        Outcome::Failed
    );
    write_row(&r.store, &work.reference, vec![]);
    assert_eq!(
        status(&restarted.s, "inst", &reference).value,
        svc::WORK_STATUS_ABSENT
    );
}

#[test]
fn work_status_cold_store_read_failure_never_proves_or_mutates_settlement() {
    for settled in [false, true] {
        let original = rig();
        let (handle, reference) = open(&original, 1, b"private live record");
        if settled {
            assert_eq!(
                settle(
                    &original,
                    "inst",
                    Some(1),
                    handle,
                    b"private terminal record"
                )
                .outcome,
                Outcome::Ready
            );
        }
        let work = original.s.work().get("inst", handle).unwrap();
        let before = read_row(&original.store, &work.reference).unwrap();
        let mode = Arc::new(AtomicU64::new(0));
        let restarted = rig_with_backend(
            original.store.clone(),
            WorkBounds::default(),
            Arc::new(SettlementBackend {
                attempts: Arc::default(),
                store: original.store.clone(),
                mode: mode.clone(),
            }),
        );
        for failure in [5, 6] {
            mode.store(failure, Ordering::SeqCst);
            let answer = status(&restarted.s, "inst", &reference);
            assert_eq!(answer.outcome, Outcome::Failed);
            assert_ne!(answer.value, svc::WORK_STATUS_SETTLED);
            assert_eq!(
                restarted.s.work().held(),
                0,
                "a failed observation never adopts or settles work"
            );
            assert_eq!(
                read_row(&original.store, &work.reference)
                    .unwrap()
                    .as_slice(),
                before.as_slice(),
                "read failure leaves the durable row unchanged"
            );
        }
        mode.store(0, Ordering::SeqCst);
        let answer = status(&restarted.s, "inst", &reference);
        assert_eq!(answer.outcome, Outcome::Ready);
        assert_eq!(
            answer.value,
            if settled {
                svc::WORK_STATUS_SETTLED
            } else {
                svc::WORK_STATUS_LIVE
            }
        );
        assert_eq!(restarted.s.work().held(), 0);
    }
}
