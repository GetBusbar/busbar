// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::services::HostServices;
#[path = "trust_native.rs"]
pub(super) mod native;
use crate::{
    host_services::{TrustRefused, DECISION_UNKEPT},
    trust::book::{Distrust, Ruling},
};
use busbar_contract::{
    abi::{host::service as svc, mechanism::call::Outcome},
    services::Ran,
};
use native::*;
use std::sync::{atomic::Ordering, Arc};

#[tokio::test]
async fn a_kept_approval_cannot_apply_after_a_newer_same_key_revoke() {
    let r = Rig::new().await;
    r.observe(ORIGINAL).await;
    r.backend.park_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let approval = tokio::spawn(async move { node.trust_rule(KEY, Ruling::Approve).await });
    entered(&r.backend).await;
    assert_eq!(
        r.node.trust_rule(KEY, Ruling::Revoke).await,
        Err(TrustRefused::Stale)
    );
    let blocked = call(|later| r.node.trust_sight(&caller(), PEER, CHANGED, later)).await;
    assert_eq!(
        (blocked.outcome, blocked.error),
        (Outcome::Refused, DECISION_UNKEPT)
    );
    assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
    r.backend.release.notify_one();
    approval.await.unwrap().unwrap();
    assert_eq!(r.kept(None).await.approved.as_deref(), Some(ORIGINAL));
}

#[tokio::test]
async fn item_owners_allow_distinct_keys_and_refuse_drift_before_any_side_effect() {
    let r = Rig::new().await;
    r.backend.park_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let revoke = tokio::spawn(async move {
        node.decide_key(INSTANCE, PEER, Some("tool"), Ruling::Revoke, None)
            .await
    });
    entered(&r.backend).await;
    assert_eq!(
        r.node
            .decide_key(INSTANCE, PEER, Some("tool"), Ruling::Approve, None)
            .await,
        Err(TrustRefused::Stale)
    );
    let blocked = call(|later| {
        r.node
            .trust_sight_item(&caller(), PEER, "tool", CHANGED, later)
    })
    .await;
    assert_eq!(blocked.error, DECISION_UNKEPT);
    r.node
        .decide_key(INSTANCE, PEER, Some("other-tool"), Ruling::Revoke, None)
        .await
        .unwrap();
    r.backend.release.notify_one();
    revoke.await.unwrap().unwrap();
    assert_eq!(r.kept(Some("tool")).await.approved, None);
}

#[tokio::test]
async fn a_parked_item_demotion_cannot_overwrite_a_newer_item_ruling() {
    let r = Rig::new().await;
    r.approve().await;
    r.backend.park_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let drift = tokio::spawn(async move {
        call(|later| node.trust_sight_item(&caller(), PEER, "tool", CHANGED, later)).await
    });
    entered(&r.backend).await;
    assert_eq!(
        r.node
            .decide_key(INSTANCE, PEER, Some("tool"), Ruling::Approve, None)
            .await,
        Err(TrustRefused::Stale)
    );
    r.backend.release.notify_one();
    assert_eq!(drift.await.unwrap().outcome, Outcome::Ready);
    r.node
        .decide_key(INSTANCE, PEER, Some("tool"), Ruling::Approve, None)
        .await
        .unwrap();
    assert!(!r.kept(Some("tool")).await.demoted);
}

#[tokio::test]
async fn a_store_callback_can_reenter_and_an_unwind_retires_its_decision_owner() {
    let r = Rig::new().await;
    r.observe(ORIGINAL).await;
    r.backend.panic_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    assert!(
        tokio::spawn(async move { node.trust_rule(KEY, Ruling::Approve).await })
            .await
            .unwrap_err()
            .is_panic()
    );
    assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
    r.node.trust_rule(KEY, Ruling::Revoke).await.unwrap();
    assert_eq!(r.kept(None).await.approved, None);
}

#[tokio::test]
async fn failed_and_unknown_store_results_leave_ram_unchanged_and_release_the_owner() {
    for unknown in [false, true] {
        let r = Rig::new().await;
        r.observe(ORIGINAL).await;
        if unknown {
            r.backend.inner.lose_reply.store(true, Ordering::SeqCst)
        } else {
            r.backend.refuse_commit.store(true, Ordering::SeqCst)
        }
        assert!(matches!(
            r.node.trust_rule(KEY, Ruling::Approve).await,
            Err(TrustRefused::Store(_))
        ));
        assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
        r.backend.refuse_commit.store(false, Ordering::SeqCst);
        r.node.trust_rule(KEY, Ruling::Revoke).await.unwrap();
        assert_eq!(r.kept(None).await.approved, None);
    }
}

#[tokio::test]
async fn an_old_resync_snapshot_cannot_clear_a_completed_local_revoke() {
    for item in [None, Some("tool")] {
        let r = Rig::new().await;
        r.approve().await;
        r.backend.park_scan.store(true, Ordering::SeqCst);
        r.node.trust_resync_tick();
        entered(&r.backend).await;
        r.node
            .decide_key(INSTANCE, PEER, item, Ruling::Revoke, None)
            .await
            .unwrap();
        r.backend.release.notify_one();
        idle_resync(&r.node).await;
        assert_eq!(judged(&r.node, item), Err(Distrust::NotApproved));
    }
}

#[tokio::test]
async fn a_failed_ruling_and_a_re_admit_both_retire_the_original_decision_owner() {
    let r = Rig::new().await;
    r.observe(ORIGINAL).await;
    r.backend.park_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let approval = tokio::spawn(async move { node.trust_rule(KEY, Ruling::Approve).await });
    entered(&r.backend).await;
    let node = r.node.clone();
    let mut changed = facts();
    changed.trust[0].1.pin.as_mut().unwrap().fingerprint = Some(CHANGED.into());
    let admission = tokio::spawn(async move { node.admit(INSTANCE, changed).await });
    r.backend.release.notify_one();
    approval.await.unwrap().unwrap();
    admission.await.unwrap().unwrap();
    assert_ne!(judged(&r.node, None), Ok(()));
}

#[tokio::test]
async fn a_reentrant_resync_does_not_apply_an_unconfirmed_store_write() {
    let r = Rig::new().await;
    r.observe(ORIGINAL).await;
    r.backend.park_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let approval = tokio::spawn(async move { node.trust_rule(KEY, Ruling::Approve).await });
    entered(&r.backend).await;
    r.node.trust_resync_tick();
    tokio::task::yield_now().await;
    assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
    r.backend.release.notify_one();
    approval.await.unwrap().unwrap();
    idle_resync(&r.node).await;
}

#[tokio::test]
async fn a_resync_started_during_a_local_write_cannot_replay_it_after_completion() {
    let r = Rig::new().await;
    r.approve().await;
    r.backend.park_commit.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let revoke = tokio::spawn(async move { node.trust_rule(KEY, Ruling::Revoke).await });
    entered(&r.backend).await;
    r.node.trust_resync_tick();
    r.backend.release.notify_one();
    revoke.await.unwrap().unwrap();
    idle_resync(&r.node).await;
    assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
}

#[tokio::test]
async fn a_store_unwind_after_upsert_preserves_ram_and_releases_the_owner() {
    let r = Rig::new().await;
    r.observe(ORIGINAL).await;
    r.backend.panic_after.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    assert!(
        tokio::spawn(async move { node.trust_rule(KEY, Ruling::Approve).await })
            .await
            .unwrap_err()
            .is_panic()
    );
    assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
    assert_eq!(r.kept(None).await.approved.as_deref(), Some(ORIGINAL));
    r.node.trust_rule(KEY, Ruling::Revoke).await.unwrap();
    assert_eq!(r.kept(None).await.approved, None);
}

#[tokio::test]
async fn ordinary_sightings_do_not_defer_a_fresh_remote_revoke() {
    let r = Rig::new().await;
    r.approve().await;
    let (follower, _) = r.follower(Arc::new(AsyncPool)).await;
    r.node.trust_rule(KEY, Ruling::Revoke).await.unwrap();
    r.backend.park_scan.store(true, Ordering::SeqCst);
    follower.trust_resync_tick();
    entered(&r.backend).await;
    assert_eq!(
        call(|later| follower.trust_sight(&caller(), PEER, ORIGINAL, later))
            .await
            .value,
        svc::TRUST_SAME
    );
    assert!(matches!(
        follower.trust_sight_item(&caller(), PEER, "tool", ORIGINAL, Box::new(|_| {})),
        Ran::Now(_)
    ));
    r.backend.release.notify_one();
    idle_resync(&follower).await;
    assert_eq!(judged(&follower, None), Err(Distrust::NotApproved));
}

#[tokio::test]
async fn guarded_trust_conflict_preserves_the_durable_decision() {
    let r = Rig::new().await;
    r.approve().await;
    r.observe(CHANGED).await;
    let before = r.record.decisions().await.unwrap();
    let rows = r.node.trust_rows();
    for ruling in [Ruling::Approve, Ruling::Revoke] {
        assert_eq!(
            r.node.trust_rule_if_seen(KEY, ruling, Some(ORIGINAL)).await,
            Err(TrustRefused::Stale)
        );
        assert_eq!(r.node.trust_rows(), rows);
        assert_eq!(r.record.decisions().await.unwrap(), before);
    }
    r.node
        .trust_rule_if_seen(KEY, Ruling::Approve, Some(CHANGED))
        .await
        .unwrap();
    assert_eq!(r.kept(None).await.approved.as_deref(), Some(CHANGED));
}

#[path = "trust_sight_ordering_tests.rs"]
mod trust_sight_ordering_tests;
