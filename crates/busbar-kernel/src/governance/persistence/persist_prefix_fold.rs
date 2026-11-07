// SPDX-License-Identifier: Apache-2.0
use super::*;

fn effects(backend: &Backend, recovery: &StoreRecovery) -> (usize, usize) {
    (
        backend.state.lock().unwrap().sent.len(),
        recovery.state.lock().unwrap().pending.len(),
    )
}
#[tokio::test]
async fn persist_prefix_proves_local_predecessor_parent_and_same_digest_without_effects() {
    let (backend, recovery) = fixture().await;
    let (parent, checkpoint, child) = linked_events();
    persist_all(&recovery, &[&parent, &checkpoint, &child]).await;
    let next = transition(&child, RecoveryState::Applied);
    let before = effects(&backend, &recovery);
    recovery.verify_origin(&next).await.unwrap();
    assert_eq!(
        effects(&backend, &recovery),
        before,
        "preflight remains read only"
    );
    recovery.persist(&next).await.unwrap();
    let before = effects(&backend, &recovery);
    recovery.persist(&next).await.unwrap();
    assert_eq!(
        effects(&backend, &recovery),
        before,
        "same digest cannot append or select twice"
    );
}
#[tokio::test]
async fn persist_prefix_brackets_initially_absent_head_as_an_exact_option() {
    let (backend, recovery) = fixture().await;
    let initial = intent();
    assert!(
        head(&recovery.store, &initial.operation_id)
            .await
            .unwrap()
            .is_none()
    );
    let before = effects(&backend, &recovery);
    recovery.verify_origin(&initial).await.unwrap();
    assert_eq!(effects(&backend, &recovery), before);
    let event = initial.clone();
    after_read(&backend, address(&initial.operation_id), move |backend| {
        select(
            backend,
            &event,
            &Head {
                version: 1,
                node: 7,
                sequence: 1,
                revision: 0,
                event_digest: event.fingerprint().unwrap(),
            },
        );
    });
    assert!(recovery.verify_origin(&initial).await.is_err());
    assert_eq!(effects(&backend, &recovery), before);
}
#[tokio::test]
async fn persist_prefix_rejects_changed_child_parent_or_fence_before_any_effects() {
    for change in 0..3 {
        let (backend, recovery) = fixture().await;
        let (parent, checkpoint, child) = linked_events();
        persist_all(&recovery, &[&parent, &checkpoint, &child]).await;
        let target = if change == 1 {
            parent.operation_id
        } else {
            child.operation_id
        };
        let event = if change == 1 {
            parent.clone()
        } else {
            child.clone()
        };
        after_read(&backend, address(&target), move |backend| {
            if change == 2 {
                set_root_epoch(backend, 3)
            } else {
                let raw = backend.state.lock().unwrap().rows[&address(&target)].clone();
                let mut tip: Head =
                    serde_json::from_slice(raw.expose(&crate::seal::lend())).unwrap();
                tip.revision += 1;
                select(backend, &event, &tip);
            }
        });
        let before = effects(&backend, &recovery);
        assert!(
            recovery
                .persist(&transition(&child, RecoveryState::Applied))
                .await
                .is_err()
        );
        assert_eq!(
            effects(&backend, &recovery),
            before,
            "failed preflight retains custody and publishes nothing"
        );
    }
}
#[tokio::test]
async fn persist_prefix_missing_or_corrupt_sealed_fact_fails_before_pending_or_store_publication() {
    for missing in [false, true] {
        let (backend, recovery) = fixture().await;
        let initial = intent();
        recovery.persist(&initial).await.unwrap();
        let tip = head(&recovery.store, &initial.operation_id)
            .await
            .unwrap()
            .unwrap()
            .0;
        let (at, _) = record_row(&backend, recovery.node, tip.sequence);
        damage(&backend, &at, missing);
        let before = effects(&backend, &recovery);
        assert!(
            recovery
                .persist(&transition(&initial, RecoveryState::LandedUnknown))
                .await
                .is_err()
        );
        assert_eq!(effects(&backend, &recovery), before);
    }
}
#[tokio::test]
async fn persist_prefix_binds_transient_full_candidate_seal_even_when_original_is_restored() {
    transient_pointer(2).await;
}
#[tokio::test]
async fn persist_prefix_final_fold_checks_an_unselected_tail_before_effects() {
    let (backend, recovery) = fixture().await;
    let initial = intent();
    recovery.persist(&initial).await.unwrap();
    let mut unrelated = intent();
    unrelated.operation_id = [44; 16];
    let tail = append_unselected(
        &recovery,
        Candidate {
            event: unrelated,
            previous_head: None,
            adoption: None,
        },
    )
    .await;
    let (at, _) = record_row(&backend, recovery.node, tail.sequence);
    damage(&backend, &at, false);
    let before = effects(&backend, &recovery);
    assert!(
        recovery
            .persist(&transition(&initial, RecoveryState::LandedUnknown))
            .await
            .is_err()
    );
    assert_eq!(effects(&backend, &recovery), before);
}
#[tokio::test]
async fn persist_prefix_preproof_cannot_replace_fresh_post_cas_origin_verification() {
    let (backend, recovery) = fixture().await;
    let (parent, checkpoint, child) = linked_events();
    persist_all(&recovery, &[&parent, &checkpoint]).await;
    let tip = head(&recovery.store, &parent.operation_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    let (at, _) = record_row(&backend, recovery.node, tip.sequence);
    let selected = address(&child.operation_id);
    let damaged = Arc::new(AtomicBool::new(false));
    let observed = damaged.clone();
    *backend.after_read.lock().unwrap() = Some(Arc::new(move |backend, request| {
        if request.addresses.contains(&selected)
            && backend.state.lock().unwrap().rows.contains_key(&selected)
            && !observed.swap(true, Ordering::SeqCst)
        {
            damage(backend, &at, false);
        }
    }));
    assert!(recovery.persist(&child).await.is_err());
    assert!(damaged.load(Ordering::SeqCst));
    assert!(
        recovery
            .state
            .lock()
            .unwrap()
            .pending
            .contains_key(&child.operation_id),
        "post-selection proof failure retains exact candidate custody"
    );
}
#[tokio::test]
async fn persist_prefix_foreign_parent_and_adopted_predecessor_restart_a_fresh_cold_preflight() {
    let (backend, old) = fixture().await;
    let recipient = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let (parent, checkpoint, child) = linked_events();
    persist_all(&old, &[&parent, &checkpoint]).await;
    let before = effects(&backend, &recipient);
    recipient.verify_origin(&child).await.unwrap();
    assert_eq!(effects(&backend, &recipient), before);
    let (adopter, verdict) = adopted(backend.clone(), &old).await;
    let next = transition(&verdict, RecoveryState::Settled);
    let before = effects(&backend, &adopter);
    adopter.verify_origin(&next).await.unwrap();
    assert_eq!(effects(&backend, &adopter), before);
    adopter.persist(&next).await.unwrap();
}
#[tokio::test]
async fn persist_prefix_overflow_cold_restart_rechecks_unrelated_actual_journal_records() {
    let (backend, recovery) = fixture().await;
    let mut unrelated = intent();
    unrelated.operation_id = [44; 16];
    let tail = append_unselected(
        &recovery,
        Candidate {
            event: unrelated,
            previous_head: None,
            adoption: None,
        },
    )
    .await;
    let (event, tip) = long_history(&recovery).await;
    select(&backend, &event, &tip);
    let next = transition(&event, RecoveryState::LandedUnknown);
    let before = effects(&backend, &recovery);
    recovery.verify_origin(&next).await.unwrap();
    assert_eq!(effects(&backend, &recovery), before);
    let (at, _) = record_row(&backend, recovery.node, tail.sequence);
    damage(&backend, &at, false);
    assert!(recovery.persist(&next).await.is_err());
    assert_eq!(effects(&backend, &recovery), before);
}
