// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::store::plane_view::KIND_TRUST_DECISION;
use busbar_contract::records::{PlaneSelector, RecordStoreResult};

fn follower(
    r: &Rig,
    pool: Arc<dyn Offload>,
    before_read: impl Fn() -> RecordStoreResult<()> + Send + Sync + 'static,
) -> Arc<KernelServices> {
    let store = Arc::clone(&r.store);
    let probe = Arc::new(Probe::default());
    assert!(probe
        .decision_read
        .set(Arc::new(move || {
            before_read()?;
            RecordStore::list_plane_records(&*store, KIND_TRUST_DECISION, &PlaneSelector::All)
        }))
        .is_ok());
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
    node.admit("inst", trusting(Some("fp"))).unwrap();
    node
}

fn remote_approval(r: &Rig) {
    assert_eq!(
        run(|later| r.s.trust_sight(&caller("inst"), "cp", "c1", later)).value,
        svc::TRUST_NEW,
    );
    r.s.trust_rule("inst/cp", Ruling::Approve).unwrap();
}

fn next_window(r: &Rig) {
    let window_ms = u64::try_from(
        std::time::Duration::from_secs(crate::governance::REVOCATION_SYNC_TTL_SECS).as_millis(),
    )
    .unwrap();
    r.clock.fetch_add(window_ms, Ordering::SeqCst);
}

fn pending(node: &KernelServices) {
    assert_eq!(
        node.trust_unreached(&caller("inst"), "cp").value,
        svc::TRUST_NEW
    );
}

fn approved(node: &KernelServices) {
    assert_eq!(
        node.trust_unreached(&caller("inst"), "cp").value,
        svc::TRUST_SAME
    );
    assert_eq!(
        node.trust_judge(
            "inst",
            &TrustFacts {
                counterparty: "cp",
                item: None,
                digest: None,
            },
        ),
        Ok(()),
        "the remote approval admits the counterparty",
    );
}

#[test]
fn a_bounded_pool_refusal_releases_the_resync_for_the_next_window() {
    let r = rig();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let node = follower(
        &r,
        Arc::new(BlockingPool::new(rt.handle().clone(), 0)),
        || Ok(()),
    );
    remote_approval(&r);
    node.trust_resync_tick();
    pending(&node);

    let held = Arc::new(Held::default());
    let node = Arc::try_unwrap(node)
        .unwrap()
        .with_pool(Arc::new(Arc::clone(&held)));
    node.trust_resync_tick();
    assert_eq!(
        held.drain(),
        0,
        "a refused attempt still keeps the normal TTL"
    );
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 1, "the real retry was submitted");
    approved(&node);
}

#[test]
fn dropping_a_queued_resync_allows_a_later_read_to_apply_remote_decisions() {
    let r = rig();
    let held = Arc::new(Held::default());
    let node = follower(&r, Arc::new(Arc::clone(&held)), || Ok(()));
    remote_approval(&r);
    node.trust_resync_tick();
    let jobs = std::mem::take(&mut *held.0.lock().unwrap());
    assert_eq!(jobs.len(), 1);
    drop(jobs);
    pending(&node);
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 1);
    approved(&node);
}

#[test]
fn an_unwinding_decision_read_releases_the_resync_for_a_real_retry() {
    let r = rig();
    let held = Arc::new(Held::default());
    let panic_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&panic_read);
    let node = follower(&r, Arc::new(Arc::clone(&held)), move || {
        assert!(
            !flag.swap(false, Ordering::SeqCst),
            "the decision store panicked"
        );
        Ok(())
    });
    remote_approval(&r);
    panic_read.store(true, Ordering::SeqCst);
    node.trust_resync_tick();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| held.drain())).is_err());
    pending(&node);
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 1);
    approved(&node);
}

#[test]
fn refused_and_completed_reads_keep_the_ttl_and_apply_later_remote_decisions() {
    let r = rig();
    let held = Arc::new(Held::default());
    let refuse_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&refuse_read);
    let node = follower(&r, Arc::new(Arc::clone(&held)), move || {
        if flag.load(Ordering::SeqCst) {
            Err("the decision store refused the read".into())
        } else {
            Ok(())
        }
    });
    remote_approval(&r);
    refuse_read.store(true, Ordering::SeqCst);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 1);
    pending(&node);
    refuse_read.store(false, Ordering::SeqCst);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 0, "refusal does not bypass the TTL");
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 1);
    approved(&node);

    r.s.trust_rule("inst/cp", Ruling::Revoke).unwrap();
    node.trust_resync_tick();
    assert_eq!(held.drain(), 0, "success does not bypass the TTL");
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(held.drain(), 1);
    assert_eq!(
        node.trust_judge(
            "inst",
            &TrustFacts {
                counterparty: "cp",
                item: None,
                digest: None
            }
        ),
        Err(Distrust::NotApproved),
        "a later remote revoke is applied after the successful read",
    );
}

#[test]
fn queued_and_reentrant_ticks_never_overlap_a_resync() {
    let r = rig();
    let held = Arc::new(Held::default());
    let reenter = Arc::new(OnceLock::<std::sync::Weak<KernelServices>>::new());
    let target = Arc::clone(&reenter);
    let clock = Arc::clone(&r.clock);
    let node = follower(&r, Arc::new(Arc::clone(&held)), move || {
        if let Some(node) = target.get().and_then(std::sync::Weak::upgrade) {
            assert!(
                node.instances.try_lock().is_ok(),
                "the read holds no host lock"
            );
            clock.fetch_add(
                u64::try_from(
                    std::time::Duration::from_secs(crate::governance::REVOCATION_SYNC_TTL_SECS)
                        .as_millis(),
                )
                .unwrap(),
                Ordering::SeqCst,
            );
            node.trust_resync_tick();
        }
        Ok(())
    });
    assert!(reenter.set(Arc::downgrade(&node)).is_ok());
    remote_approval(&r);
    node.trust_resync_tick();
    next_window(&r);
    node.trust_resync_tick();
    assert_eq!(
        held.0.lock().unwrap().len(),
        1,
        "the queued read holds single flight"
    );
    assert_eq!(held.drain(), 1);
    assert!(
        held.0.lock().unwrap().is_empty(),
        "the reentrant tick submitted no read"
    );
    approved(&node);

    r.s.trust_rule("inst/cp", Ruling::Revoke).unwrap();
    node.trust_resync_tick();
    assert_eq!(
        held.drain(),
        1,
        "completion released the read for the elapsed window"
    );
    assert!(held.0.lock().unwrap().is_empty());
    assert_eq!(
        node.trust_judge(
            "inst",
            &TrustFacts {
                counterparty: "cp",
                item: None,
                digest: None
            }
        ),
        Err(Distrust::NotApproved),
    );
}
