// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::connections::grant::{GrantRecords, GrantState, GrantVersion};
use crate::governance::at_rest::AtRestKeys;
use busbar_contract::persistence::{AttemptId, DatasetId};
use futures::FutureExt;
use std::sync::atomic::Ordering;

fn header() -> codec::Header {
    codec::Header {
        generation: 1,
        origin: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 2,
            writer: [3; 16],
            execution_epoch: 4,
            operation: [5; 16],
        },
        purpose: 1,
        before: None,
        after: GrantVersion {
            epoch: 1,
            revision: 1,
            state: GrantState::Live,
        },
        transition: [6; 32],
    }
}

#[test]
fn recovery_header_preserves_the_original_authority_and_never_allocates_a_new_id() {
    let source = header();
    let bytes = source.encode();
    let restored = codec::Header::decode(&bytes).unwrap();
    assert_eq!(restored, source);
    assert_eq!(restored.origin.operation, [5; 16]);
    assert_eq!(restored.origin.execution_epoch, 4);
}

#[test]
fn malformed_or_future_intent_headers_are_refused_without_fallback() {
    let bytes = header().encode();
    for cut in 0..bytes.len() {
        assert!(codec::Header::decode(&bytes[..cut]).is_err());
    }
    let mut future = bytes.clone();
    future[7] = 2;
    assert!(codec::Header::decode(&future).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(codec::Header::decode(&trailing).is_err());
    for index in [8, 16, 40, 56, 64] {
        let mut invalid = header();
        match index {
            8 => invalid.generation = 0,
            16 => invalid.origin.dataset = DatasetId([0; 16]),
            40 => invalid.origin.writer = [0; 16],
            56 => invalid.origin.execution_epoch = 0,
            _ => invalid.origin.operation = [0; 16],
        }
        assert!(codec::Header::decode(&invalid.encode()).is_err());
    }
}

#[test]
fn terminal_outcomes_never_alias_pending_or_each_other() {
    assert_ne!(codec::Phase::Pending.tag(), codec::Phase::Applied.tag());
    assert_ne!(codec::Phase::Applied.tag(), codec::Phase::NoEffect.tag());
    for phase in [
        codec::Phase::Pending,
        codec::Phase::Applied,
        codec::Phase::NoEffect,
    ] {
        assert_eq!(codec::Phase::decode(phase.tag()).unwrap(), phase);
    }
    assert!(codec::Phase::decode(0).is_err());
    assert!(codec::Phase::decode(4).is_err());
}

#[test]
fn a_stale_generation_cannot_be_reused_as_a_new_preparation() {
    assert_eq!(next_generation(None).unwrap(), 1);
    assert_eq!(next_generation(Some(17)).unwrap(), 18);
    assert_eq!(next_generation(Some(u64::MAX)), Err(Error::Overflow));
}

#[test]
fn recovered_or_superseded_results_cannot_be_foreground_success() {
    assert_eq!(Outcome::Superseded, Outcome::Superseded);
    assert!(!Outcome::Superseded.applied());
    assert!(!Outcome::NoEffect.applied());
    assert!(!Outcome::Pending.applied());
    assert!(!Outcome::Reconcile.applied());
    assert!(Outcome::Applied.applied());
}

struct Fixture {
    backend: Arc<fixture::Backend>,
    owner: Arc<CallerIntents>,
    records: GrantRecords,
    key: GrantKey,
    codec: Arc<CallerProtectedRecords>,
}
async fn fixture() -> Fixture {
    let backend = Arc::new(fixture::Backend::new());
    let codec = Arc::new(
        AtRestKeys::new(&[7; 32], None)
            .caller_records(262144)
            .unwrap(),
    );
    let store = backend.attach(1).await;
    let records = GrantRecords::new(
        codec.clone(),
        store.info().dataset.0,
        store.info().atomic_domain,
    )
    .unwrap();
    let owner =
        CallerIntents::new(store, codec.clone(), Arc::new(WriterRetirements::default())).unwrap();
    ready(&owner).await;
    Fixture {
        backend,
        owner,
        records,
        key: GrantKey::new("plane", "instance", "subject", "upstream").unwrap(),
        codec,
    }
}
async fn ready(owner: &CallerIntents) {
    for _ in 0..20 {
        if owner.recover_page().await.unwrap() {
            return;
        }
    }
    panic!("bounded empty/small recovery did not finish");
}
async fn install(f: &Fixture) -> PreparedGrantOperation {
    f.owner
        .begin_operation()
        .unwrap()
        .prepare(
            f.records
                .install(&f.key, None, b"\xffrotating-grant-canary")
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn native_success_is_two_transactions_and_foreground_result_is_single_use() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let f = fixture().await;
    let mut operation = install(&f).await;
    assert_eq!(operation.drive().await.unwrap(), Outcome::Applied);
    assert_eq!(f.backend.calls(), 2);
    assert_eq!(operation.drive().await.unwrap(), Outcome::Superseded);
    assert!(f.owner.read_current(&f.key).await.unwrap().is_some());
    assert!(!f.backend.contains_plaintext(b"rotating-grant-canary"));
}

#[tokio::test]
async fn lost_prepare_reply_never_crosses_main_until_exact_native_retry() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let f = fixture().await;
    let mut operation = install(&f).await;
    f.backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(operation.drive().await.unwrap(), Outcome::Pending);
    assert_eq!(f.backend.calls(), 1);
    assert_eq!(f.owner.read_current(&f.key).await, Err(Error::Pending));
    assert_eq!(operation.drive().await.unwrap(), Outcome::Applied);
    let sent = f.backend.sent();
    assert_eq!(sent[0], sent[1]);
}

#[tokio::test]
async fn canceled_prepare_is_retained_then_closed_without_installing_a_grant() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let f = fixture().await;
    let mut operation = install(&f).await;
    f.backend.hang.store(true, Ordering::SeqCst);
    assert!(operation.drive().now_or_never().is_none());
    drop(operation);
    assert_eq!(f.owner.read_current(&f.key).await, Err(Error::Pending));
    f.backend.hang.store(false, Ordering::SeqCst);
    f.owner.maintain(8).await.unwrap();
    assert!(f.owner.read_current(&f.key).await.unwrap().is_none());
    let slot = f.owner.observe(f.key.encoded()).await.unwrap();
    assert_eq!(slot.slot.unwrap().1, codec::Phase::NoEffect);
}

#[tokio::test]
async fn restart_fences_original_writer_and_resolves_prepared_intent_without_main_replay() {
    let _guard = crate::persistence::undrained::ledger_test_guard().await;
    let f = fixture().await;
    let operation = install(&f).await;
    let prepared = operation
        .draft
        .operation
        .state
        .lock()
        .unwrap()
        .prepared
        .clone()
        .unwrap();
    assert!(matches!(
        f.owner.submit(&prepared.prepare).await.unwrap(),
        SubmitResult::Decided(_)
    ));
    let main_digest = prepared.main.fingerprint();
    // Discard every process-local owner; only native rows and keys survive.
    drop(operation);
    drop(prepared);
    drop(f.owner);
    let restarted = CallerIntents::new(
        f.backend.attach(2).await,
        f.codec,
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    ready(&restarted).await;
    assert!(restarted.read_current(&f.key).await.unwrap().is_none());
    assert_eq!(
        restarted
            .observe(f.key.encoded())
            .await
            .unwrap()
            .slot
            .unwrap()
            .1,
        codec::Phase::NoEffect
    );
    assert!(!f.backend.sent().contains(&main_digest));
    assert!(f.backend.closed(1));
}

#[tokio::test]
async fn restarted_applied_terminal_preserves_grant_without_replaying_any_candidate() {
    let f = fixture().await;
    let mut operation = install(&f).await;
    assert_eq!(operation.drive().await.unwrap(), Outcome::Applied);
    let before = f.backend.calls();
    drop(operation);
    drop(f.owner);
    let restarted = CallerIntents::new(
        f.backend.attach(2).await,
        f.codec,
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    ready(&restarted).await;
    assert!(restarted.read_current(&f.key).await.unwrap().is_some());
    assert_eq!(f.backend.calls(), before);
}

#[tokio::test]
async fn restart_after_lost_main_ack_recovers_atomic_terminal_without_issuing_a_new_operation() {
    let f = fixture().await;
    let operation = install(&f).await;
    let prepared = operation
        .draft
        .operation
        .state
        .lock()
        .unwrap()
        .prepared
        .clone()
        .unwrap();
    f.owner.submit(&prepared.prepare).await.unwrap();
    f.backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.owner.submit(&prepared.main).await.unwrap(),
        SubmitResult::Uncertain
    ));
    let before = f.backend.calls();
    drop(operation);
    drop(prepared);
    drop(f.owner);
    let restarted = CallerIntents::new(
        f.backend.attach(2).await,
        f.codec,
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    ready(&restarted).await;
    assert_eq!(
        restarted
            .observe(f.key.encoded())
            .await
            .unwrap()
            .slot
            .unwrap()
            .1,
        codec::Phase::Applied
    );
    assert!(restarted.read_current(&f.key).await.unwrap().is_some());
    assert_eq!(f.backend.calls(), before);
}

#[tokio::test]
async fn durable_guard_serializes_replicas_and_terminal_key_cannot_be_silently_discarded() {
    let f = fixture().await;
    let operation = install(&f).await;
    let prepared = operation
        .draft
        .operation
        .state
        .lock()
        .unwrap()
        .prepared
        .clone()
        .unwrap();
    f.owner.submit(&prepared.prepare).await.unwrap();
    f.backend.lease(1, u64::MAX);
    let other = CallerIntents::new(
        f.backend.attach(2).await,
        f.codec.clone(),
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    ready(&other).await;
    assert_eq!(other.read_current(&f.key).await, Err(Error::Pending));
    let foreign = other
        .begin_operation()
        .unwrap()
        .prepare(f.records.install(&f.key, None, b"other").unwrap())
        .await;
    assert!(matches!(foreign, Err(Error::Pending)));
    drop(operation);
    f.owner.maintain(8).await.unwrap();
    let wrong = Arc::new(
        AtRestKeys::new(&[9; 32], Some(&[8; 32]))
            .caller_records(262144)
            .unwrap(),
    );
    let lost = CallerIntents::new(
        f.backend.attach(3).await,
        wrong,
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    assert_eq!(lost.recover_page().await, Err(Error::Corrupt));
    assert!(matches!(lost.begin_operation(), Err(Error::NotReady)));
}

#[tokio::test]
async fn keyed_revoke_read_fences_before_await_and_unsubmitted_drop_releases_it() {
    let f = fixture().await;
    let mut installed = install(&f).await;
    assert_eq!(installed.drive().await.unwrap(), Outcome::Applied);
    let mut revoke = f.owner.begin_operation().unwrap();
    f.backend.hang_read.store(true, Ordering::SeqCst);
    assert!(revoke.read_current(&f.key).now_or_never().is_none());
    assert_eq!(f.owner.read_current(&f.key).await, Err(Error::Pending));
    let mut competing = f.owner.begin_operation().unwrap();
    assert_eq!(competing.read_current(&f.key).await, Err(Error::Pending));
    drop(revoke);
    drop(competing);
    f.backend.hang_read.store(false, Ordering::SeqCst);
    assert!(f.owner.read_current(&f.key).await.unwrap().is_some());
    assert_eq!(f.backend.calls(), 2);
}

#[tokio::test]
async fn a_delayed_replica_preparation_cannot_resurrect_a_revoked_grant() {
    let f = fixture().await;
    let mut installed = install(&f).await;
    assert_eq!(installed.drive().await.unwrap(), Outcome::Applied);
    let original = f.owner.read_current(&f.key).await.unwrap().unwrap();
    let snapshot = f.records.decode(&f.key, &original).unwrap();
    let other = CallerIntents::new(
        f.backend.attach(2).await,
        f.codec.clone(),
        Arc::new(WriterRetirements::default()),
    )
    .unwrap();
    ready(&other).await;
    let mut delayed = other
        .begin_operation()
        .unwrap()
        .prepare(
            f.records
                .install(&f.key, Some(&snapshot), b"newgrant")
                .unwrap(),
        )
        .await
        .unwrap();
    let mut revoke = f
        .owner
        .begin_operation()
        .unwrap()
        .prepare(f.records.revoke(&f.key, Some(&snapshot)).unwrap())
        .await
        .unwrap();
    assert_eq!(revoke.drive().await.unwrap(), Outcome::Applied);
    assert_eq!(delayed.drive().await.unwrap(), Outcome::Superseded);
    let row = f.owner.read_current(&f.key).await.unwrap().unwrap();
    let final_state = f.records.decode(&f.key, &row).unwrap();
    assert_eq!(final_state.version().state, GrantState::Revoked);
    assert!(final_state.version().epoch > snapshot.version().epoch);
}
