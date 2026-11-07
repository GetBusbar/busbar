// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::trust_ordering_tests::native::*;
use crate::host_services::BlockingPool;
use crate::trust::book::{Distrust, Ruling};
use std::sync::{atomic::Ordering, Arc};

#[tokio::test]
async fn a_bounded_pool_refusal_releases_the_resync_for_the_next_window() {
    let r = Rig::new().await;
    let (node, _) = r
        .follower(Arc::new(BlockingPool::new(
            tokio::runtime::Handle::current(),
            0,
        )))
        .await;
    r.approve().await;
    node.trust_resync_tick();
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    let held = Arc::new(Held::default());
    let node = Arc::try_unwrap(node).unwrap().with_pool(held.clone());
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 0);
    r.next_window();
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 1);
    assert_eq!(judged(&node, None), Ok(()));
}

#[tokio::test]
async fn dropping_a_queued_resync_allows_a_later_read_to_apply_remote_decisions() {
    let r = Rig::new().await;
    let held = Arc::new(Held::default());
    let (node, _) = r.follower(held.clone()).await;
    r.approve().await;
    node.trust_resync_tick();
    assert_eq!(held.discard(), 1);
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    r.next_window();
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 1);
    assert_eq!(judged(&node, None), Ok(()));
}

#[tokio::test]
async fn an_unwinding_decision_read_releases_the_resync_for_a_real_retry() {
    let r = Rig::new().await;
    let held = Arc::new(Held::default());
    let (node, _) = r.follower(held.clone()).await;
    r.approve().await;
    r.backend.panic_scan.store(true, Ordering::SeqCst);
    node.trust_resync_tick();
    let drain = held.clone();
    assert!(tokio::spawn(async move { drain.drain().await })
        .await
        .unwrap_err()
        .is_panic());
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    r.next_window();
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 1);
    assert_eq!(judged(&node, None), Ok(()));
}

#[tokio::test]
async fn refused_and_completed_reads_keep_the_ttl_and_apply_later_remote_decisions() {
    let r = Rig::new().await;
    let held = Arc::new(Held::default());
    let (node, _) = r.follower(held.clone()).await;
    r.approve().await;
    r.backend.refuse_scan.store(true, Ordering::SeqCst);
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 1);
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
    r.backend.refuse_scan.store(false, Ordering::SeqCst);
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 0);
    r.next_window();
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 1);
    assert_eq!(judged(&node, None), Ok(()));
    r.node.trust_rule(KEY, Ruling::Revoke).await.unwrap();
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 0);
    r.next_window();
    node.trust_resync_tick();
    assert_eq!(held.drain().await, 1);
    assert_eq!(judged(&node, None), Err(Distrust::NotApproved));
}

#[tokio::test]
async fn queued_and_reentrant_ticks_never_overlap_a_resync() {
    let r = Rig::new().await;
    let held = Arc::new(Held::default());
    let (node, _) = r.follower(held.clone()).await;
    r.approve().await;
    node.trust_resync_tick();
    r.next_window();
    node.trust_resync_tick();
    assert_eq!(held.0.lock().unwrap().len(), 1);
    r.backend.park_scan.store(true, Ordering::SeqCst);
    let pool = held.clone();
    let drain = tokio::spawn(async move { pool.drain().await });
    entered(&r.backend).await;
    r.next_window();
    node.trust_resync_tick();
    assert!(held.0.lock().unwrap().is_empty());
    r.backend.release.notify_one();
    assert_eq!(drain.await.unwrap(), 1);
    assert_eq!(judged(&node, None), Ok(()));
}
