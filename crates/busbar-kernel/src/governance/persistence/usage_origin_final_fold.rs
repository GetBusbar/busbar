// SPDX-License-Identifier: Apache-2.0
//! Native async equivalents of the former root final-fold fixtures. Faults alter
//! the primitive rows actually read by the production recovery owner.
use super::*;

async fn fixture() -> (Arc<Backend>, StoreRecovery) {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    (backend, recovery)
}
fn linked_events() -> (RecoveryEvent, RecoveryEvent, RecoveryEvent) {
    let mut child = intent();
    child.operation_id = [9; 16];
    child.body_fingerprint = [8; 32];
    let template = serde_json::json!({"physical":[1,2,3]});
    let mut parent = intent();
    parent.operation_id = [6; 16];
    parent.payload = b"{\"handoffs\":[]}".to_vec();
    let mut checkpoint = transition(&parent, RecoveryState::Applied);
    checkpoint.payload = serde_json::to_vec(&serde_json::json!({"handoffs":[{
        "operation_id":child.operation_id,"kind":child.kind,
        "body_fingerprint":child.body_fingerprint,"first_sent_at_ms":child.first_sent_at_ms,
        "payload":serde_json::to_vec(&template).unwrap()
    }]}))
    .unwrap();
    let mut physical = template;
    physical["origin"] = serde_json::json!({"operation_id":checkpoint.operation_id,
        "event_fingerprint":checkpoint.fingerprint().unwrap()});
    child.payload = serde_json::to_vec(&physical).unwrap();
    (parent, checkpoint, child)
}
async fn persist_all(recovery: &StoreRecovery, events: &[&RecoveryEvent]) {
    for event in events {
        recovery.persist(event).await.unwrap();
    }
}
fn record_row(backend: &Backend, node: u64, sequence: u64) -> (Address, Secret<Vec<u8>>) {
    let state = backend.state.lock().unwrap();
    state
        .rows
        .iter()
        .find_map(|(address, raw)| {
            let record = JournalRecord::decode(raw.expose(&crate::seal::lend())).ok()?;
            (record.identity() == (node, sequence)).then(|| (address.clone(), raw.clone()))
        })
        .expect("native original frame")
}
fn damage(backend: &Backend, at: &Address, missing: bool) {
    let mut state = backend.state.lock().unwrap();
    if missing {
        state.rows.remove(at);
    } else {
        state
            .rows
            .insert(at.clone(), Secret::new(b"corrupt original".to_vec()));
    }
}
fn after_read(backend: &Backend, at: Address, action: impl Fn(&Backend) + Send + Sync + 'static) {
    let fired = AtomicBool::new(false);
    *backend.after_read.lock().unwrap() = Some(Arc::new(move |backend, request| {
        if request.addresses.contains(&at) && !fired.swap(true, Ordering::SeqCst) {
            action(backend);
        }
    }));
}
async fn append_unselected(recovery: &StoreRecovery, value: Candidate) -> Head {
    let run = recovery
        .journal
        .stage_run(&[Entry::new(
            RecordClass::Reconciliation,
            body(&value).unwrap(),
        )])
        .unwrap();
    recovery.journal.confirm(&run).await.unwrap();
    Head {
        version: 1,
        node: recovery.node,
        sequence: run.records()[0].node_seq,
        revision: value.event.revision,
        event_digest: value.event.fingerprint().unwrap(),
    }
}
async fn long_history(recovery: &StoreRecovery) -> (RecoveryEvent, Head) {
    let mut event = intent();
    let mut prior = None;
    for revision in 0..130 {
        let appended = append_unselected(
            recovery,
            Candidate {
                event: event.clone(),
                previous_head: prior,
                adoption: None,
            },
        )
        .await;
        prior = Some(appended);
        if revision < 129 {
            event = transition(&event, RecoveryState::LandedUnknown);
        }
    }
    let tip = prior.unwrap();
    // Fault-fixture setup selects the exact head the native runtime appended;
    // serving writes still go exclusively through CoreStore and StoreRecovery.
    // The caller inserts it through its fixture backend below.
    (event, tip)
}
fn select(backend: &Backend, event: &RecoveryEvent, tip: &Head) {
    backend.state.lock().unwrap().rows.insert(
        address(&event.operation_id),
        Secret::new(serde_json::to_vec(tip).unwrap()),
    );
}
async fn adopted(backend: Arc<Backend>, old: &StoreRecovery) -> (StoreRecovery, RecoveryEvent) {
    let initial = intent();
    let unknown = transition(&initial, RecoveryState::LandedUnknown);
    persist_all(old, &[&initial, &unknown]).await;
    let recipient = sink(Arc::new(attach(backend, 2).await), 8).await;
    let verdict = transition(&unknown, RecoveryState::VerdictNotLanded);
    let resolution = RecoveryResolution {
        operation_id: unknown.operation_id,
        body_fingerprint: unknown.body_fingerprint,
        expected_revision: unknown.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "old sender and backend quiesced".into(),
    };
    recipient
        .adopt_verdict_selection(&resolution, std::slice::from_ref(&verdict))
        .await
        .unwrap();
    (recipient, verdict)
}

#[tokio::test]
async fn final_origin_fold_accepts_the_actual_selected_parent_and_child() {
    let (_, recovery) = fixture().await;
    let (parent, checkpoint, child) = linked_events();
    persist_all(&recovery, &[&parent, &checkpoint, &child]).await;
    recovery.verify_origin(&child).await.unwrap();
}
#[tokio::test]
async fn final_origin_fold_rejects_a_head_advanced_between_read_and_finish() {
    let (backend, recovery) = fixture().await;
    let initial = intent();
    recovery.persist(&initial).await.unwrap();
    after_read(&backend, address(&initial.operation_id), move |backend| {
        let mut tip: Head = serde_json::from_slice(
            backend.state.lock().unwrap().rows[&address(&initial.operation_id)]
                .expose(&crate::seal::lend()),
        )
        .unwrap();
        tip.revision += 1;
        select(backend, &initial, &tip);
    });
    assert!(recovery.verify_origin(&intent()).await.is_err());
}
#[tokio::test]
async fn final_origin_fold_rejects_retired_authority_between_read_and_finish() {
    let (backend, recovery) = fixture().await;
    let initial = intent();
    recovery.persist(&initial).await.unwrap();
    after_read(&backend, address(&initial.operation_id), |backend| {
        set_root_epoch(backend, 3)
    });
    assert!(recovery.verify_origin(&initial).await.is_err());
}
#[tokio::test]
async fn final_origin_fold_rejects_corrupt_or_missing_actual_store_facts() {
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
        after_read(&backend, address(&initial.operation_id), move |backend| {
            damage(backend, &at, missing)
        });
        assert!(recovery.verify_origin(&initial).await.is_err());
    }
}

/// Preserve the original transient full-seal witness: the whole-node proof sees
/// canonical frames, ancestry traversal sees a resealed predecessor, and the
/// backend restores canonical bytes before the final fold.
async fn transient_pointer(mode: u8) {
    let (backend, recovery) = fixture().await;
    let (parent, checkpoint, child) = linked_events();
    recovery.persist(&parent).await.unwrap();
    let alternate = append_unselected(
        &recovery,
        Candidate {
            event: parent.clone(),
            previous_head: None,
            adoption: None,
        },
    )
    .await;
    persist_all(&recovery, &[&checkpoint, &child]).await;
    let tip = head(&recovery.store, &checkpoint.operation_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    let (at, original) = record_row(&backend, recovery.node, tip.sequence);
    let mut edited = JournalRecord::decode(original.expose(&crate::seal::lend())).unwrap();
    let mut altered = candidate(&edited).unwrap().unwrap();
    altered.previous_head = Some(alternate);
    assert_eq!(altered.event, checkpoint);
    edited.body = body(&altered).unwrap();
    edited.body_hash = edited.digest_of_body();
    edited.hash = edited.digest_of_chain();
    let changed = Secret::new(edited.encode());
    let restored = original.clone();
    let restored_at = at.clone();
    let reads = AtomicU64::new(0);
    let observed_transient = Arc::new(AtomicBool::new(false));
    let observed = observed_transient.clone();
    let swap_after = match mode {
        0 => 2,
        1 => 0,
        _ => 4,
    };
    *backend.after_read.lock().unwrap() = Some(Arc::new(move |backend, request| {
        if request.addresses == [at.clone()] {
            match reads.fetch_add(1, Ordering::SeqCst) {
                count if count == swap_after => {
                    backend
                        .state
                        .lock()
                        .unwrap()
                        .rows
                        .insert(at.clone(), changed.clone());
                }
                count if count == swap_after + 1 => {
                    observed.store(true, Ordering::SeqCst);
                    backend
                        .state
                        .lock()
                        .unwrap()
                        .rows
                        .insert(at.clone(), original.clone());
                }
                _ => {}
            }
        }
    }));
    let before = backend.state.lock().unwrap().sent.len();
    let result = match mode {
        0 => recovery.verify_origin(&child).await,
        1 => recovery.confirm_owned_checkpoint(&checkpoint).await,
        _ => {
            recovery
                .persist(&transition(&child, RecoveryState::Applied))
                .await
        }
    };
    *backend.after_read.lock().unwrap() = None;
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(restored_at, restored);
    assert!(
        observed_transient.load(Ordering::SeqCst),
        "ancestry lookup must actually observe the transient resealed frame"
    );
    let rejected = result.is_err();
    if mode == 2 && rejected {
        assert_eq!(
            backend.state.lock().unwrap().sent.len(),
            before,
            "transient preflight failure publishes nothing"
        );
        assert!(recovery.state.lock().unwrap().pending.is_empty());
    }
    assert!(
        rejected,
        "restoring canonical bytes cannot erase a different full seal observed during ancestry traversal"
    );
    recovery.verify_origin(&child).await.unwrap();
}
#[tokio::test]
async fn final_origin_fold_rejects_transient_resealed_pointer_even_after_store_restoration() {
    transient_pointer(0).await;
}
#[tokio::test]
async fn final_origin_fold_uses_cold_verification_for_foreign_and_adopted_ancestry() {
    let (backend, old) = fixture().await;
    let (recipient, verdict) = adopted(backend, &old).await;
    recipient.verify_origin(&verdict).await.unwrap();
    recipient.confirm_owned_checkpoint(&intent()).await.unwrap();
    old.verify_origin(&verdict).await.unwrap();
}
#[tokio::test]
async fn final_origin_fold_overflow_falls_back_to_fresh_full_tamper_verification() {
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
    recovery.verify_origin(&event).await.unwrap();
    let (at, _) = record_row(&backend, recovery.node, tail.sequence);
    damage(&backend, &at, false);
    assert!(recovery.verify_origin(&event).await.is_err());
}
#[tokio::test]
async fn final_origin_fold_rejects_parent_head_advanced_between_read_and_finish() {
    let (backend, recovery) = fixture().await;
    let (parent, checkpoint, child) = linked_events();
    persist_all(&recovery, &[&parent, &checkpoint, &child]).await;
    after_read(&backend, address(&parent.operation_id), move |backend| {
        let mut tip: Head = serde_json::from_slice(
            backend.state.lock().unwrap().rows[&address(&parent.operation_id)]
                .expose(&crate::seal::lend()),
        )
        .unwrap();
        tip.revision += 1;
        select(backend, &parent, &tip);
    });
    assert!(recovery.verify_origin(&child).await.is_err());
}
#[tokio::test]
async fn final_origin_fold_verifies_unselected_tail_after_all_facts_are_found() {
    let (backend, recovery) = fixture().await;
    let initial = intent();
    recovery.persist(&initial).await.unwrap();
    let mut unrelated = intent();
    unrelated.operation_id = [45; 16];
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
    assert!(recovery.verify_origin(&initial).await.is_err());
}
#[path = "checkpoint_final_fold.rs"]
mod checkpoint_final_fold;
#[path = "persist_prefix_fold.rs"]
mod persist_prefix_fold;
