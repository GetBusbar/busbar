// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store crossings through the real host API must preserve local decision order.

use super::*;
use crate::store::plane_view::KIND_TRUST_DECISION;
use crate::trust::book::RulingRow;
use busbar_contract::records::{PlaneRecordRef, PlaneSelector};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

const CROSSING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const INSTANCE: &str = "inst";
const COUNTERPARTY: &str = "cp";
const WHOLE_KEY: &str = "inst/cp";
const ITEM: &str = "tool";
const OTHER_ITEM: &str = "other-tool";
const ORIGINAL: &str = "original-digest";
const CHANGED: &str = "changed-digest";

/// Keep real records, with hooks only at the Store crossings whose order the test controls.
fn node(r: &Rig, probe: &Arc<Probe>, pool: Arc<dyn Offload>) -> Arc<KernelServices> {
    assert!(probe.record_store.set(Arc::clone(&r.store)).is_ok());
    if probe.decision_write.get().is_none() {
        let store = Arc::clone(&r.store);
        assert!(probe
            .decision_write
            .set(Arc::new(move |record| {
                RecordStore::upsert_plane_record(&*store, record)
            }))
            .is_ok());
    }
    if probe.decision_read.get().is_none() {
        let store = Arc::clone(&r.store);
        assert!(probe
            .decision_read
            .set(Arc::new(move || {
                RecordStore::list_plane_records(&*store, KIND_TRUST_DECISION, &PlaneSelector::All)
            }))
            .is_ok());
    }
    let record = DemotionRecord::default();
    record.set_sink(probe.clone());
    let clock = Arc::clone(&r.clock);
    let node = Arc::new(
        KernelServices::new()
            .with_pool(pool)
            .with_demotions(Arc::new(record), SECTION_KEY)
            .with_wall_clock(Arc::new(move || clock.load(Ordering::SeqCst))),
    );
    assert!(probe.kernel.set(Arc::downgrade(&node)).is_ok());
    let mut facts = trusting(Some(ORIGINAL));
    for item in [ITEM, OTHER_ITEM] {
        facts.trust[0]
            .1
            .approved
            .insert(item.into(), ORIGINAL.into());
    }
    node.admit(INSTANCE, facts).unwrap();
    node
}

fn kept(r: &Rig, item: Option<&str>) -> RulingRow {
    RecordStore::list_plane_records(&*r.store, KIND_TRUST_DECISION, &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|body| serde_json::from_slice::<RulingRow>(body).unwrap())
        .find(|row| row.instance == INSTANCE && row.item.as_deref() == item)
        .expect("the decision was kept")
}

fn judged(node: &KernelServices, item: Option<&str>) -> Result<(), Distrust> {
    node.trust_judge(
        INSTANCE,
        &TrustFacts {
            counterparty: COUNTERPARTY,
            item,
            digest: item.map(|_| ORIGINAL),
        },
    )
}

fn next_window(r: &Rig) {
    r.clock.fetch_add(
        u64::try_from(
            std::time::Duration::from_secs(crate::governance::REVOCATION_SYNC_TTL_SECS).as_millis(),
        )
        .unwrap(),
        Ordering::SeqCst,
    );
}

/// Park AFTER the real upsert, before the host can apply it to RAM.
fn park_first_write(probe: &Probe, r: &Rig) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered, at_store) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let first = AtomicBool::new(true);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_write
        .set(Arc::new(move |record| {
            RecordStore::upsert_plane_record(&*store, record)?;
            if first.swap(false, Ordering::SeqCst) {
                entered.send(()).unwrap();
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(CROSSING_TIMEOUT)
                    .unwrap();
            }
            Ok(())
        }))
        .is_ok());
    (at_store, release)
}

#[test]
fn a_kept_approval_cannot_apply_after_a_newer_same_key_revoke() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let (at_store, release) = park_first_write(&probe, &r);
    let node = node(&r, &probe, Arc::new(Inline));
    std::thread::scope(|scope| {
        let approval = scope.spawn(|| node.trust_rule(WHOLE_KEY, Ruling::Approve));
        at_store.recv_timeout(CROSSING_TIMEOUT).unwrap();
        // Old code writes revoke B and applies B here, then applies parked approval A last.
        let overlapping = node.trust_rule(WHOLE_KEY, Ruling::Revoke);
        let blocked_sight =
            run(|later| node.trust_sight(&caller(INSTANCE), COUNTERPARTY, CHANGED, later));
        let during = judged(&node, None);
        release.send(()).unwrap();
        approval.join().unwrap().unwrap();
        assert_eq!(overlapping, Err(TrustRefused::Stale));
        assert_eq!(
            (blocked_sight.outcome, blocked_sight.error),
            (Outcome::Refused, DECISION_UNKEPT)
        );
        assert_eq!(during, Err(Distrust::NotApproved));
    });
    assert_eq!(kept(&r, None).approved.as_deref(), Some(ORIGINAL));
    assert_eq!(judged(&node, None), Ok(()));
    node.trust_rule(WHOLE_KEY, Ruling::Revoke).unwrap();
    assert_eq!(kept(&r, None).approved, None);
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
}

#[path = "trust_sight_ordering_tests.rs"]
mod trust_sight_ordering_tests;

#[test]
fn item_owners_allow_distinct_keys_and_refuse_drift_before_any_side_effect() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let (at_store, release) = park_first_write(&probe, &r);
    let node = node(&r, &probe, Arc::new(Inline));
    std::thread::scope(|scope| {
        let revoke = scope
            .spawn(|| node.decide_key(INSTANCE, COUNTERPARTY, Some(ITEM), Ruling::Revoke, None));
        at_store.recv_timeout(CROSSING_TIMEOUT).unwrap();
        let overlap = node.decide_key(INSTANCE, COUNTERPARTY, Some(ITEM), Ruling::Approve, None);
        let sight = node.trust_sight_item(&caller(INSTANCE), COUNTERPARTY, ITEM, CHANGED);
        let other = node.decide_key(
            INSTANCE,
            COUNTERPARTY,
            Some(OTHER_ITEM),
            Ruling::Revoke,
            None,
        );
        let whole = node.trust_rule(WHOLE_KEY, Ruling::Approve);
        let row = node
            .trust_rows()
            .into_iter()
            .find(|row| row.item.as_deref() == Some(ITEM))
            .unwrap();
        release.send(()).unwrap();
        revoke.join().unwrap().unwrap();
        assert_eq!(overlap, Err(TrustRefused::Stale));
        assert_eq!(
            (sight.outcome, sight.error),
            (Outcome::Refused, DECISION_UNKEPT)
        );
        assert_eq!(
            row.seen, None,
            "the refused sighting changes no observation"
        );
        other.unwrap();
        whole.unwrap();
    });
    assert_eq!(kept(&r, Some(ITEM)).approved, None);
    assert_eq!(judged(&node, Some(ITEM)), Err(Distrust::NotApproved));
    node.decide_key(INSTANCE, COUNTERPARTY, Some(ITEM), Ruling::Approve, None)
        .unwrap();
    assert_eq!(judged(&node, Some(ITEM)), Ok(()));
}

#[test]
fn a_parked_item_demotion_cannot_overwrite_a_newer_item_ruling() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let (at_store, release) = park_first_write(&probe, &r);
    let node = node(&r, &probe, Arc::new(Inline));
    std::thread::scope(|scope| {
        let drift =
            scope.spawn(|| node.trust_sight_item(&caller(INSTANCE), COUNTERPARTY, ITEM, CHANGED));
        at_store.recv_timeout(CROSSING_TIMEOUT).unwrap();
        let overlap = node.decide_key(INSTANCE, COUNTERPARTY, Some(ITEM), Ruling::Revoke, None);
        release.send(()).unwrap();
        assert_eq!(drift.join().unwrap().outcome, Outcome::Ready);
        assert_eq!(overlap, Err(TrustRefused::Stale));
    });
    assert!(kept(&r, Some(ITEM)).demoted);
    node.decide_key(INSTANCE, COUNTERPARTY, Some(ITEM), Ruling::Revoke, None)
        .unwrap();
    assert!(!kept(&r, Some(ITEM)).demoted);
    assert_eq!(kept(&r, Some(ITEM)).approved, None);
}

#[test]
fn a_store_callback_can_reenter_and_an_unwind_retires_its_decision_owner() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let target = Arc::new(OnceLock::<std::sync::Weak<KernelServices>>::new());
    let inside = Arc::clone(&target);
    let first = AtomicBool::new(true);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_write
        .set(Arc::new(move |record: PlaneRecordRef<'_>| {
            if first.swap(false, Ordering::SeqCst) {
                let node = inside.get().unwrap().upgrade().unwrap();
                assert!(node.instances.try_lock().is_ok());
                assert_eq!(
                    node.trust_rule(WHOLE_KEY, Ruling::Revoke),
                    Err(TrustRefused::Stale)
                );
                // A different key can cross the same Store callback without a host lock.
                node.decide_key(
                    INSTANCE,
                    COUNTERPARTY,
                    Some(OTHER_ITEM),
                    Ruling::Revoke,
                    None,
                )
                .unwrap();
                panic!("the decision Store unwound before its upsert");
            }
            RecordStore::upsert_plane_record(&*store, record)
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    assert!(target.set(Arc::downgrade(&node)).is_ok());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.trust_rule(WHOLE_KEY, Ruling::Approve)
    }))
    .is_err());
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    assert_eq!(judged(&node, None), Ok(()));
    assert_eq!(kept(&r, None).approved.as_deref(), Some(ORIGINAL));
}

#[test]
fn failed_and_unknown_store_results_leave_ram_unchanged_and_release_the_owner() {
    for committed in [false, true] {
        let r = rig();
        let probe = Arc::new(Probe::default());
        let first = AtomicBool::new(true);
        let store = Arc::clone(&r.store);
        assert!(probe
            .decision_write
            .set(Arc::new(move |record| {
                if first.swap(false, Ordering::SeqCst) {
                    if committed {
                        RecordStore::upsert_plane_record(&*store, record)?;
                    }
                    return Err("the Store could not confirm the decision".into());
                }
                RecordStore::upsert_plane_record(&*store, record)
            }))
            .is_ok());
        let node = node(&r, &probe, Arc::new(Inline));
        assert!(matches!(
            node.trust_rule(WHOLE_KEY, Ruling::Approve),
            Err(TrustRefused::Store(_))
        ));
        assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
        if committed {
            assert_eq!(kept(&r, None).approved.as_deref(), Some(ORIGINAL));
            node.trust_resync_tick();
            assert_eq!(
                judged(&node, None),
                Ok(()),
                "a later read retains the existing unknown-commit reconciliation"
            );
        }
        node.trust_rule(WHOLE_KEY, Ruling::Revoke).unwrap();
        assert_eq!(kept(&r, None).approved, None);
        assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    }
}

#[test]
fn an_old_resync_snapshot_cannot_clear_a_completed_local_revoke() {
    stale_snapshot_after_local_revoke(None);
    stale_snapshot_after_local_revoke(Some(ITEM));
}

fn stale_snapshot_after_local_revoke(item: Option<&str>) {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let armed = Arc::new(AtomicBool::new(false));
    let park = Arc::clone(&armed);
    let (entered, at_store) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_read
        .set(Arc::new(move || {
            let rows =
                RecordStore::list_plane_records(&*store, KIND_TRUST_DECISION, &PlaneSelector::All)?;
            if park.swap(false, Ordering::SeqCst) {
                entered.send(()).unwrap();
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(CROSSING_TIMEOUT)
                    .unwrap();
            }
            Ok(rows)
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    if item.is_some() {
        node.decide_key(INSTANCE, COUNTERPARTY, item, Ruling::Approve, None)
            .unwrap();
    }
    armed.store(true, Ordering::SeqCst);
    std::thread::scope(|scope| {
        let read = scope.spawn(|| node.trust_resync_tick());
        at_store.recv_timeout(CROSSING_TIMEOUT).unwrap();
        let revoked = node.decide_key(INSTANCE, COUNTERPARTY, item, Ruling::Revoke, None);
        release.send(()).unwrap();
        read.join().unwrap();
        revoked.unwrap();
    });
    assert_eq!(
        judged(&node, item),
        Err(Distrust::NotApproved),
        "the completed revoke survives the old approval snapshot"
    );
    assert_eq!(kept(&r, item).approved, None);
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(judged(&node, item), Err(Distrust::NotApproved));
    // A fresh read still accepts another node's later approval.
    let remote = self::node(&r, &Arc::new(Probe::default()), Arc::new(Inline));
    remote
        .decide_key(INSTANCE, COUNTERPARTY, item, Ruling::Approve, None)
        .unwrap();
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(judged(&node, item), Ok(()));
}

#[test]
fn a_failed_ruling_and_a_re_admit_both_retire_the_original_decision_owner() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let target = Arc::new(OnceLock::<std::sync::Weak<KernelServices>>::new());
    let inside = Arc::clone(&target);
    let first = AtomicBool::new(true);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_write
        .set(Arc::new(move |record| {
            if first.swap(false, Ordering::SeqCst) {
                let node = inside.get().unwrap().upgrade().unwrap();
                // Replacing the declaration must preserve ownership of the still-running Store call.
                node.admit(INSTANCE, trusting(Some(CHANGED))).unwrap();
                assert_eq!(
                    node.trust_rule(WHOLE_KEY, Ruling::Revoke),
                    Err(TrustRefused::Stale)
                );
            }
            RecordStore::upsert_plane_record(&*store, record)
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    assert!(target.set(Arc::downgrade(&node)).is_ok());
    assert_eq!(
        node.decide_key(INSTANCE, COUNTERPARTY, None, Ruling::Approve, Some(CHANGED)),
        Err(TrustRefused::NothingSighted)
    );
    assert_eq!(
        node.trust_rule(WHOLE_KEY, Ruling::Approve),
        Err(TrustRefused::Stale)
    );
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    assert_eq!(kept(&r, None).approved.as_deref(), Some(ORIGINAL));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    assert_eq!(kept(&r, None).approved.as_deref(), Some(CHANGED));
    assert_eq!(judged(&node, None), Ok(()));
}

#[test]
fn a_reentrant_resync_does_not_apply_an_unconfirmed_store_write() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let target = Arc::new(OnceLock::<std::sync::Weak<KernelServices>>::new());
    let inside = Arc::clone(&target);
    let first = AtomicBool::new(true);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_write
        .set(Arc::new(move |record| {
            RecordStore::upsert_plane_record(&*store, record)?;
            if first.swap(false, Ordering::SeqCst) {
                let node = inside.get().unwrap().upgrade().unwrap();
                // The fleet read sees the upsert, but the local caller has no confirmed outcome yet.
                node.trust_resync_tick();
                assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
                return Err("the Store could not confirm its committed write".into());
            }
            Ok(())
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    assert!(target.set(Arc::downgrade(&node)).is_ok());
    assert!(matches!(
        node.trust_rule(WHOLE_KEY, Ruling::Approve),
        Err(TrustRefused::Store(_))
    ));
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(judged(&node, None), Ok(()));
}

#[test]
fn a_resync_started_during_a_local_write_cannot_replay_it_after_completion() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let write_armed = Arc::new(AtomicBool::new(false));
    let read_armed = Arc::new(AtomicBool::new(false));
    let (write_entered, at_write) = mpsc::channel();
    let (finish_write, write_release) = mpsc::channel();
    let (read_entered, at_read) = mpsc::channel();
    let (finish_read, read_release) = mpsc::channel();
    let write_release = Mutex::new(write_release);
    let read_release = Mutex::new(read_release);
    let park_write = Arc::clone(&write_armed);
    let park_read = Arc::clone(&read_armed);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_write
        .set(Arc::new(move |record| {
            if park_write.swap(false, Ordering::SeqCst) {
                write_entered.send(()).unwrap();
                write_release
                    .lock()
                    .unwrap()
                    .recv_timeout(CROSSING_TIMEOUT)
                    .unwrap();
            }
            RecordStore::upsert_plane_record(&*store, record)
        }))
        .is_ok());
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_read
        .set(Arc::new(move || {
            let rows =
                RecordStore::list_plane_records(&*store, KIND_TRUST_DECISION, &PlaneSelector::All)?;
            if park_read.swap(false, Ordering::SeqCst) {
                read_entered.send(()).unwrap();
                read_release
                    .lock()
                    .unwrap()
                    .recv_timeout(CROSSING_TIMEOUT)
                    .unwrap();
            }
            Ok(rows)
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    write_armed.store(true, Ordering::SeqCst);
    read_armed.store(true, Ordering::SeqCst);
    std::thread::scope(|scope| {
        let revoke = scope.spawn(|| node.trust_rule(WHOLE_KEY, Ruling::Revoke));
        at_write.recv_timeout(CROSSING_TIMEOUT).unwrap();
        let read = scope.spawn(|| node.trust_resync_tick());
        at_read.recv_timeout(CROSSING_TIMEOUT).unwrap();
        finish_write.send(()).unwrap();
        let revoked = revoke.join().unwrap();
        finish_read.send(()).unwrap();
        read.join().unwrap();
        revoked.unwrap();
    });
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    assert_eq!(kept(&r, None).approved, None);
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
}

#[test]
fn a_store_unwind_after_upsert_preserves_ram_and_releases_the_owner() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let first = AtomicBool::new(true);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_write
        .set(Arc::new(move |record| {
            RecordStore::upsert_plane_record(&*store, record)?;
            assert!(
                !first.swap(false, Ordering::SeqCst),
                "the Store unwound after committing"
            );
            Ok(())
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || node.trust_rule(WHOLE_KEY, Ruling::Approve)
    ))
    .is_err());
    assert_eq!(kept(&r, None).approved.as_deref(), Some(ORIGINAL));
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    node.trust_rule(WHOLE_KEY, Ruling::Revoke).unwrap();
    assert_eq!(kept(&r, None).approved, None);
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
}

#[test]
fn ordinary_sightings_do_not_defer_a_fresh_remote_revoke() {
    let r = rig();
    let probe = Arc::new(Probe::default());
    let target = Arc::new(OnceLock::<std::sync::Weak<KernelServices>>::new());
    let inside = Arc::clone(&target);
    let store = Arc::clone(&r.store);
    assert!(probe
        .decision_read
        .set(Arc::new(move || {
            let rows =
                RecordStore::list_plane_records(&*store, KIND_TRUST_DECISION, &PlaneSelector::All)?;
            if let Some(node) = inside.get().and_then(std::sync::Weak::upgrade) {
                assert_eq!(
                    run(|later| node.trust_sight(&caller(INSTANCE), COUNTERPARTY, ORIGINAL, later))
                        .value,
                    svc::TRUST_SAME
                );
                assert_eq!(
                    node.trust_sight_item(&caller(INSTANCE), COUNTERPARTY, ITEM, ORIGINAL)
                        .outcome,
                    Outcome::Ready
                );
            }
            Ok(rows)
        }))
        .is_ok());
    let node = node(&r, &probe, Arc::new(Inline));
    assert!(target.set(Arc::downgrade(&node)).is_ok());
    node.trust_rule(WHOLE_KEY, Ruling::Approve).unwrap();
    let remote = self::node(&r, &Arc::new(Probe::default()), Arc::new(Inline));
    remote.trust_rule(WHOLE_KEY, Ruling::Revoke).unwrap();
    node.trust_resync_tick();
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
}
