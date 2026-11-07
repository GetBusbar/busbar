// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::native::*;
use crate::{
    host_services::{TrustRefused, POOL_REFUSED},
    trust::book::{Distrust, Ruling},
};
use busbar_contract::services::HostServices;
use busbar_contract::{
    abi::{host::service as svc, mechanism::call::Outcome},
    services::Ran,
};
use std::sync::{atomic::Ordering, Arc};

#[tokio::test]
async fn a_queued_drift_cannot_resurrect_quarantine_after_a_completed_approval() {
    let r = Rig::new().await;
    r.approve().await;
    let held = Arc::new(Held::default());
    let (node, record) = r.follower(held.clone()).await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    assert!(matches!(
        node.trust_sight(
            &caller(),
            PEER,
            CHANGED,
            Box::new(move |result| {
                let _ = tx.send(result);
            })
        ),
        Ran::Later
    ));
    assert_eq!(
        node.trust_rule(KEY, Ruling::Approve).await,
        Err(TrustRefused::Stale)
    );
    node.decide_key(INSTANCE, PEER, Some("other-tool"), Ruling::Revoke, None)
        .await
        .unwrap();
    assert!(record.read().await.unwrap().is_empty());
    assert_eq!(judged(&node, None), Err(Distrust::Quarantined));
    assert_eq!(held.drain().await, 1);
    assert_eq!(rx.await.unwrap().value, svc::TRUST_DRIFTED);
    assert_eq!(record.read().await.unwrap().len(), 1);
    node.trust_rule(KEY, Ruling::Approve).await.unwrap();
    assert!(record.read().await.unwrap().is_empty());
    let (restarted, _) = r.follower(Arc::new(AsyncPool)).await;
    assert_eq!(judged(&restarted, None), Ok(()));
}

#[tokio::test]
async fn dropping_an_unrun_drift_retires_ownership_before_answering_its_caller() {
    let r = Rig::new().await;
    r.approve().await;
    let held = Arc::new(Held::default());
    let (node, _) = r.follower(held.clone()).await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    assert!(matches!(
        node.trust_sight(
            &caller(),
            PEER,
            CHANGED,
            Box::new(move |result| {
                let _ = tx.send(result);
            })
        ),
        Ran::Later
    ));
    assert_eq!(held.discard(), 1);
    let failed = rx.await.unwrap();
    assert_eq!(
        (failed.outcome, failed.error),
        (Outcome::Failed, POOL_REFUSED)
    );
    assert_eq!(judged(&node, None), Err(Distrust::Quarantined));
    node.trust_rule(KEY, Ruling::Approve).await.unwrap();
    assert_eq!(judged(&node, None), Ok(()));
}

#[tokio::test]
async fn an_unwinding_drift_store_retires_ownership_before_the_failed_answer() {
    let r = Rig::new().await;
    r.approve().await;
    let held = Arc::new(Held::default());
    let (node, _) = r.follower(held.clone()).await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    r.backend.panic_commit.store(true, Ordering::SeqCst);
    assert!(matches!(
        node.trust_sight(
            &caller(),
            PEER,
            CHANGED,
            Box::new(move |result| {
                let _ = tx.send(result);
            })
        ),
        Ran::Later
    ));
    let pool = held.clone();
    assert!(tokio::spawn(async move { pool.drain().await })
        .await
        .unwrap_err()
        .is_panic());
    assert_eq!(rx.await.unwrap().outcome, Outcome::Failed);
    assert_eq!(judged(&node, None), Err(Distrust::Quarantined));
    node.trust_rule(KEY, Ruling::Approve).await.unwrap();
    assert_eq!(judged(&node, None), Ok(()));
}

#[tokio::test]
async fn a_refused_demotion_store_keeps_ram_quarantine_and_retires_ownership() {
    let r = Rig::new().await;
    r.approve().await;
    r.backend.refuse_commit.store(true, Ordering::SeqCst);
    assert_eq!(r.observe(CHANGED).await.outcome, Outcome::Failed);
    assert_eq!(judged(&r.node, None), Err(Distrust::Quarantined));
    assert!(r.record.read().await.unwrap().is_empty());
    r.backend.refuse_commit.store(false, Ordering::SeqCst);
    r.node.trust_rule(KEY, Ruling::Approve).await.unwrap();
    assert_eq!(judged(&r.node, None), Ok(()));
}
