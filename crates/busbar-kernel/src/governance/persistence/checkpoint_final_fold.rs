// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn checkpoint_final_fold_proves_selected_ancestor_and_its_actual_parent_origin() {
    let (_, recovery) = fixture().await;
    let (parent, checkpoint, child) = linked_events();
    let applied = transition(&child, RecoveryState::Applied);
    let settled = transition(&applied, RecoveryState::Settled);
    persist_all(
        &recovery,
        &[&parent, &checkpoint, &child, &applied, &settled],
    )
    .await;
    for event in [&child, &applied, &settled] {
        recovery.verify_checkpoint(event).await.unwrap();
        recovery.confirm_owned_checkpoint(event).await.unwrap();
    }
}
#[tokio::test]
async fn checkpoint_final_fold_rejects_raw_head_advance_and_retired_authority() {
    for retired in [false, true] {
        let (backend, recovery) = fixture().await;
        let initial = intent();
        recovery.persist(&initial).await.unwrap();
        let event = initial.clone();
        after_read(&backend, address(&initial.operation_id), move |backend| {
            if retired {
                set_root_epoch(backend, 3);
            } else {
                let (mut tip, _) = {
                    let state = backend.state.lock().unwrap();
                    let raw = state.rows[&address(&event.operation_id)].clone();
                    (
                        serde_json::from_slice::<Head>(raw.expose(&crate::seal::lend())).unwrap(),
                        raw,
                    )
                };
                tip.revision += 1;
                select(backend, &event, &tip);
            }
        });
        assert!(recovery.confirm_owned_checkpoint(&initial).await.is_err());
    }
}
#[tokio::test]
async fn checkpoint_final_fold_rejects_changed_materialized_fact_after_read() {
    let (backend, recovery) = fixture().await;
    let initial = intent();
    recovery.persist(&initial).await.unwrap();
    let tip = head(&recovery.store, &initial.operation_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    let (at, _) = record_row(&backend, recovery.node, tip.sequence);
    after_read(&backend, address(&initial.operation_id), move |backend| {
        damage(backend, &at, false)
    });
    assert!(recovery.verify_checkpoint(&initial).await.is_err());
}
#[tokio::test]
async fn checkpoint_final_fold_binds_transient_resealed_ancestor_pointer_after_restoration() {
    transient_pointer(1).await;
}
#[tokio::test]
async fn checkpoint_final_fold_uses_fresh_cold_proof_for_foreign_adopted_history() {
    let (backend, old) = fixture().await;
    let recipient = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let initial = intent();
    old.persist(&initial).await.unwrap();
    recipient.verify_checkpoint(&initial).await.unwrap();
    assert!(recipient.confirm_owned_checkpoint(&initial).await.is_err());
    let (adopter, _) = adopted(backend, &old).await;
    adopter.confirm_owned_checkpoint(&initial).await.unwrap();
}
#[tokio::test]
async fn checkpoint_final_fold_overflow_restarts_cold_and_checks_unrelated_journal_tamper() {
    let (backend, recovery) = fixture().await;
    let mut unrelated = intent();
    unrelated.operation_id = [44; 16];
    let unselected = append_unselected(
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
    recovery.confirm_owned_checkpoint(&intent()).await.unwrap();
    let (at, _) = record_row(&backend, recovery.node, unselected.sequence);
    damage(&backend, &at, false);
    assert!(recovery.confirm_owned_checkpoint(&intent()).await.is_err());
}
