// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::host_records::tests::{attach, Backend};
use std::sync::atomic::Ordering;

async fn node(backend: Arc<Backend>) -> DemotionRecord {
    let record = DemotionRecord::new();
    record.set_store(Arc::new(attach(backend).await)).unwrap();
    record
}
fn ruling() -> RulingRow {
    RulingRow {
        instance: "instance".into(),
        counterparty: "peer".into(),
        item: None,
        approved: Some("digest".into()),
        declared: None,
        demoted: false,
    }
}

#[tokio::test]
async fn recorded_demotion_survives_a_fresh_owner() {
    let backend = Arc::new(Backend::default());
    node(backend.clone())
        .await
        .record("peer", "quarantined", 100)
        .await
        .unwrap();
    let rows = node(backend).await.read().await.unwrap();
    assert_eq!(
        rows,
        vec![DemotionRow {
            upstream: "peer".into(),
            reason: "quarantined".into(),
            recorded_at: 100
        }]
    );
}

#[tokio::test]
async fn rerecord_replaces_and_clear_preserves_other_demotions() {
    let record = node(Arc::new(Backend::default())).await;
    record.record("peer", "quarantined", 100).await.unwrap();
    record.record("peer", "quarantined", 200).await.unwrap();
    record.record("other", "quarantined", 300).await.unwrap();
    assert_eq!(
        record
            .read()
            .await
            .unwrap()
            .iter()
            .find(|r| r.upstream == "peer")
            .unwrap()
            .recorded_at,
        200
    );
    record.clear("peer").await.unwrap();
    let rows = record.read().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].upstream, "other");
    record.clear("absent").await.unwrap();
    assert_eq!(record.read().await.unwrap(), rows);
}

#[tokio::test]
async fn only_quarantine_and_approval_change_a_demotion() {
    use crate::trust::TrustState;
    let record = node(Arc::new(Backend::default())).await;
    settle(&record, "peer", TrustState::Quarantined)
        .await
        .unwrap();
    for state in [
        TrustState::Error,
        TrustState::Suspended,
        TrustState::Pending,
    ] {
        settle(&record, "peer", state).await.unwrap();
        assert_eq!(record.read().await.unwrap().len(), 1);
    }
    settle(&record, "peer", TrustState::Approved).await.unwrap();
    assert!(record.read().await.unwrap().is_empty());
}

#[tokio::test]
async fn approval_and_superseded_demotions_share_one_commit_and_snapshot() {
    let record = node(Arc::new(Backend::default())).await;
    record
        .record("instance\u{1f}peer", "quarantined", 100)
        .await
        .unwrap();
    record.record("peer", "quarantined", 100).await.unwrap();
    let ruling = ruling();
    record
        .keep_decision_clearing(&ruling, &["instance\u{1f}peer".into(), "peer".into()])
        .await
        .unwrap();
    let snapshot = record.snapshot().await.unwrap();
    assert!(snapshot.demotions.is_empty());
    assert_eq!(snapshot.decisions, vec![ruling]);
}

#[tokio::test]
async fn unknown_write_is_settled_before_admission_or_newer_write() {
    let backend = Arc::new(Backend::default());
    let record = node(backend.clone()).await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(record.record("peer", "quarantined", 100).await.is_err());
    assert!(!record.pending.lock().unwrap().is_empty());
    assert_eq!(record.snapshot().await.unwrap().demotions.len(), 1);
    record.clear("peer").await.unwrap();
    assert!(record.read().await.unwrap().is_empty());
}

#[tokio::test]
async fn cancellation_retains_original_candidate_and_backend() {
    let backend = Arc::new(Backend::default());
    let record = node(backend.clone()).await;
    backend.hang.store(true, Ordering::SeqCst);
    {
        let mut write = Box::pin(record.record("peer", "quarantined", 100));
        assert!(futures::poll!(&mut write).is_pending());
    }
    assert!(record
        .set_store(Arc::new(attach(Arc::new(Backend::default())).await))
        .is_err());
    backend.hang.store(false, Ordering::SeqCst);
    assert_eq!(record.snapshot().await.unwrap().demotions.len(), 1);
}

#[tokio::test]
async fn unattached_owner_has_no_persistent_facts() {
    let record = DemotionRecord::default();
    record.record("peer", "quarantined", 100).await.unwrap();
    assert!(record.read().await.unwrap().is_empty());
    assert!(record.decisions().await.unwrap().is_empty());
}
