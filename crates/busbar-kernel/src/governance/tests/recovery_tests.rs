// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type ForeignJournals = std::collections::BTreeMap<[u8; 16], (u64, Vec<RecoveryEvent>)>;
type ConfirmedAdoptions =
    std::collections::BTreeMap<[u8; 16], (RecoveryResolution, Vec<RecoveryEvent>)>;

#[derive(Default)]
pub(in crate::governance) struct Journal {
    pub(in crate::governance) selected: Mutex<Vec<RecoveryEvent>>,
    pub(in crate::governance) fail_after_write: AtomicBool,
    foreign: Mutex<ForeignJournals>,
    adoption_attempts: Mutex<Vec<(RecoveryResolution, Vec<RecoveryEvent>)>>,
    confirmed_adoptions: Mutex<ConfirmedAdoptions>,
    lose_adoption_reply: AtomicBool,
    pub(in crate::governance) persists: std::sync::atomic::AtomicUsize,
    pub(in crate::governance) persisted_ops: Mutex<Vec<([u8; 16], u64)>>,
}
#[async_trait::async_trait]
impl RecoverySink for Journal {
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Ok(self.selected.lock().unwrap().clone())
    }
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.persists.fetch_add(1, Ordering::Relaxed);
        self.persisted_ops
            .lock()
            .unwrap()
            .push((event.operation_id, event.revision));
        if self
            .foreign
            .lock()
            .unwrap()
            .contains_key(&event.operation_id)
        {
            return Err(RecoveryError::Conflict(
                "foreign operation is readonly".into(),
            ));
        }
        let mut selected = self.selected.lock().unwrap();
        if !selected.contains(event) {
            selected.push(event.clone());
        }
        if self.fail_after_write.load(Ordering::Relaxed) {
            Err(RecoveryError::Unavailable(
                "reply lost after selection".into(),
            ))
        } else {
            Ok(())
        }
    }
    async fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let chain = self
            .foreign
            .lock()
            .unwrap()
            .get(&event.operation_id)
            .map(|(_, events)| events.clone())
            .unwrap_or_else(|| {
                self.selected
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|selected| selected.operation_id == event.operation_id)
                    .cloned()
                    .collect()
            });
        let present = chain.iter().any(|selected| selected == event);
        summarize_recovery_chains(chain)?;
        if present {
            Ok(())
        } else {
            Err(RecoveryError::Conflict(
                "checkpoint is not currently selected".into(),
            ))
        }
    }
    async fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        Ok(self
            .foreign
            .lock()
            .unwrap()
            .values()
            .map(|(owner_node, events)| RecoveryInspection {
                owner_node: *owner_node,
                event: events.last().unwrap().clone(),
            })
            .collect())
    }
    async fn adopt_verdict(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        resolution.validate_quiescence()?;
        self.adoption_attempts
            .lock()
            .unwrap()
            .push((resolution.clone(), transitions.to_vec()));
        if let Some((previous, events)) = self
            .confirmed_adoptions
            .lock()
            .unwrap()
            .get(&resolution.operation_id)
        {
            if previous != resolution || events.as_slice() != transitions {
                return Err(RecoveryError::Conflict(
                    "adoption differs from confirmed immutable candidate".into(),
                ));
            }
            return Ok(self
                .selected
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.operation_id == resolution.operation_id)
                .cloned()
                .collect());
        }
        let mut foreign = self.foreign.lock().unwrap();
        let (_, original) = foreign
            .get(&resolution.operation_id)
            .ok_or_else(|| RecoveryError::Conflict("foreign head disappeared".into()))?;
        let head = original.last().unwrap();
        if head.revision != resolution.expected_revision
            || head.body_fingerprint != resolution.body_fingerprint
        {
            return Err(RecoveryError::Conflict("foreign head changed".into()));
        }
        let mut chain = original.clone();
        for event in transitions {
            event.follows(chain.last())?;
            chain.push(event.clone());
        }
        foreign.remove(&resolution.operation_id);
        drop(foreign);
        self.selected.lock().unwrap().extend(chain.clone());
        self.confirmed_adoptions.lock().unwrap().insert(
            resolution.operation_id,
            (resolution.clone(), transitions.to_vec()),
        );
        if self.lose_adoption_reply.swap(false, Ordering::Relaxed) {
            return Err(RecoveryError::Unavailable(
                "adoption selected but reply lost".into(),
            ));
        }
        Ok(chain)
    }
    async fn verify_origin(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let owned: Vec<_> = self
            .selected
            .lock()
            .unwrap()
            .iter()
            .filter(|selected| selected.operation_id == event.operation_id)
            .cloned()
            .collect();
        let genesis = owned
            .first()
            .cloned()
            .or_else(|| {
                self.foreign
                    .lock()
                    .unwrap()
                    .get(&event.operation_id)
                    .and_then(|(_, events)| events.first().cloned())
            })
            .unwrap_or_else(|| event.clone());
        if (event.revision == 0 && event != &genesis)
            || event.origin_reference()? != genesis.origin_reference()?
            || event.kind != genesis.kind
            || event.body_fingerprint != genesis.body_fingerprint
            || event.first_sent_at_ms != genesis.first_sent_at_ms
        {
            return Err(RecoveryError::Conflict("child identity changed".into()));
        }
        let Some(origin) = genesis.origin_reference()? else {
            return Ok(());
        };
        let parent = self
            .selected
            .lock()
            .unwrap()
            .iter()
            .find(|parent| {
                parent.operation_id == origin.operation_id
                    && parent.fingerprint().ok() == Some(origin.event_fingerprint)
            })
            .cloned()
            .or_else(|| {
                self.foreign
                    .lock()
                    .unwrap()
                    .get(&origin.operation_id)
                    .and_then(|(_, events)| {
                        events
                            .iter()
                            .find(|parent| {
                                parent.fingerprint().ok() == Some(origin.event_fingerprint)
                            })
                            .cloned()
                    })
            })
            .ok_or_else(|| RecoveryError::Invalid("origin is not selected".into()))?;
        parent.authorizes_child(&genesis)
    }
}
impl Journal {
    fn make_foreign(&self, operation_id: [u8; 16], owner_node: u64) {
        let mut selected = self.selected.lock().unwrap();
        let chain = selected
            .iter()
            .filter(|event| event.operation_id == operation_id)
            .cloned()
            .collect();
        selected.retain(|event| event.operation_id != operation_id);
        self.foreign
            .lock()
            .unwrap()
            .insert(operation_id, (owner_node, chain));
    }
}

fn intent() -> RecoveryEvent {
    RecoveryEvent {
        operation_id: [1; 16],
        revision: 0,
        previous_event: None,
        kind: RecoveryKind::Usage,
        body_fingerprint: [2; 32],
        state: RecoveryState::Intent,
        first_sent_at_ms: Some(42),
        payload: vec![3],
    }
}
fn successor(previous: &RecoveryEvent, state: RecoveryState) -> RecoveryEvent {
    RecoveryEvent {
        revision: previous.revision + 1,
        previous_event: Some(previous.fingerprint().unwrap()),
        state,
        ..previous.clone()
    }
}

#[tokio::test]
async fn ambiguous_selection_retains_exact_candidate_until_confirmed() {
    let sink = Arc::new(Journal::default());
    let book = RecoveryBook::default();
    book.replay(sink.clone()).await.unwrap();
    let event = intent();
    sink.fail_after_write.store(true, Ordering::Relaxed);
    assert!(book.keep(&event).await.is_err());
    assert!(book.selected(event.operation_id).is_none());
    let mut different = event.clone();
    different.payload.push(9);
    assert!(matches!(
        book.keep(&different).await,
        Err(RecoveryError::Conflict(_))
    ));
    sink.fail_after_write.store(false, Ordering::Relaxed);
    book.keep(&event).await.unwrap();
    assert_eq!(book.selected(event.operation_id), Some(event.clone()));
    book.keep(&event).await.unwrap();
    sink.fail_after_write.store(true, Ordering::Relaxed);
    let persisted = sink.persists.load(Ordering::Relaxed);
    book.keep(&event).await.unwrap();
    assert_eq!(
        sink.persists.load(Ordering::Relaxed),
        persisted,
        "an already selected event with nothing pending is not re-persisted"
    );
    assert_eq!(
        sink.selected.lock().unwrap().as_slice(),
        std::slice::from_ref(&event)
    );
    sink.fail_after_write.store(false, Ordering::Relaxed);
    let next = successor(&event, RecoveryState::Applied);
    book.keep(&next).await.unwrap();
    assert_eq!(sink.persists.load(Ordering::Relaxed), persisted + 1);
    assert_eq!(book.selected(event.operation_id), Some(next));
}

#[tokio::test]
async fn staged_candidate_survives_failed_persistence_and_cannot_change() {
    let sink = Arc::new(Journal::default());
    let book = RecoveryBook::default();
    book.replay(sink.clone()).await.unwrap();
    let event = intent();
    let stage = |payload| {
        book.stage(
            event.operation_id,
            event.kind,
            event.body_fingerprint,
            event.state,
            event.first_sent_at_ms,
            payload,
        )
    };
    assert_eq!(stage(event.payload.clone()).unwrap(), event);
    assert!(stage(vec![99]).is_err());
    sink.fail_after_write.store(true, Ordering::Relaxed);
    assert!(book.keep(&event).await.is_err());
    assert_eq!(stage(event.payload.clone()).unwrap(), event);
}

#[tokio::test]
async fn replay_rejects_gap_and_same_revision_fork() {
    let event = intent();
    for invalid in [
        RecoveryEvent {
            revision: 2,
            ..successor(&event, RecoveryState::Applied)
        },
        RecoveryEvent {
            payload: vec![99],
            ..event.clone()
        },
    ] {
        let sink = Arc::new(Journal::default());
        *sink.selected.lock().unwrap() = vec![event.clone(), invalid];
        assert!(RecoveryBook::default().replay(sink).await.is_err());
    }
}

#[test]
fn raw_checkpoints_keep_definitive_decisions_until_custody_is_transferred() {
    let event = intent();
    for decision in [RecoveryState::Applied, RecoveryState::ConditionConflict] {
        let previous = successor(&event, decision);
        successor(&previous, decision)
            .follows(Some(&previous))
            .unwrap();
    }
    let unknown = successor(&event, RecoveryState::LandedUnknown);
    for decision in [
        RecoveryState::VerdictLanded,
        RecoveryState::VerdictNotLanded,
    ] {
        let previous = successor(&unknown, decision);
        successor(&previous, decision)
            .follows(Some(&previous))
            .unwrap();
        assert!(successor(&previous, RecoveryState::Intent)
            .follows(Some(&previous))
            .is_err());
    }
}

#[test]
fn chain_identity_and_first_sent_time_never_reset() {
    let event = intent();
    for invalid in [
        RecoveryEvent {
            first_sent_at_ms: Some(43),
            ..successor(&event, RecoveryState::Applied)
        },
        RecoveryEvent {
            kind: RecoveryKind::Metering,
            ..successor(&event, RecoveryState::Applied)
        },
        RecoveryEvent {
            body_fingerprint: [8; 32],
            ..successor(&event, RecoveryState::Applied)
        },
    ] {
        assert!(invalid.follows(Some(&event)).is_err());
    }
}
async fn raw_intent(gov: &super::super::GovState, requests: i128) -> RecoveryEvent {
    let child = super::super::GovState::usage_recovery_child(
        "recovery-bucket",
        0,
        super::super::ExactUsageDelta {
            requests,
            ..Default::default()
        },
        super::super::ExactUsageDelta::default(),
    )
    .unwrap()
    .unwrap();
    let event = gov
        .new_recovery_event(
            child.operation_id,
            child.kind,
            child.body_fingerprint,
            RecoveryState::Intent,
            child.first_sent_at_ms,
            child.payload,
        )
        .unwrap();
    gov.keep_recovery_event(&event).await.unwrap();
    event
}

#[tokio::test]
async fn restart_cannot_turn_recent_wall_time_into_receipt_age_authority() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let first = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    first.attach_recovery_sink(sink.clone()).await.unwrap();
    first.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&first, 7).await;
    assert!(first.recovery_sent_here(intent.operation_id));
    drop(first);
    let restarted = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    restarted.attach_recovery_sink(sink).await.unwrap();
    restarted.resume_raw_recovery().await.unwrap();
    assert_eq!(
        restarted.recovery_event(intent.operation_id).unwrap().state,
        RecoveryState::LandedUnknown
    );
    assert!(!restarted.recovery_sent_here(intent.operation_id));
    let raw: serde_json::Value = serde_json::from_slice(
        &restarted
            .recovery_event(intent.operation_id)
            .unwrap()
            .payload,
    )
    .unwrap();
    assert_eq!(raw["age_unknown"], true);
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        0
    );
}

#[tokio::test]
async fn unknown_usage_absorbs_negative_then_not_landed_reposts_only_net_raw_debt() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    original.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&original, 7).await;
    drop(original);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let negative = super::super::ExactUsageDelta {
        requests: -3,
        ..Default::default()
    };
    let captured = gov
        .capture_usage_recovery(
            "recovery-bucket",
            0,
            negative,
            super::super::ExactUsageDelta::default(),
            &gov.capture_foreign_settled_snapshot().await,
        )
        .unwrap();
    assert!(captured.child.is_none());
    gov.drive_durable_usage_flight(&captured).await.unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        0
    );
    let unknown = gov.recovery_event(intent.operation_id).unwrap();
    gov.resolve_raw_recovery(&RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: unknown.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "backend outcome independently checked".into(),
    })
    .await
    .unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        4
    );
    assert_eq!(
        gov.recovery_event(intent.operation_id).unwrap().state,
        RecoveryState::Settled
    );
}

#[tokio::test]
async fn selected_parent_checkpoint_reconstructs_exact_missing_usage_child() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let first = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    first.attach_recovery_sink(sink.clone()).await.unwrap();
    first.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&first, 1).await;
    store
        .ledger()
        .add_usage_batch_deduped(
            busbar_contract::records::OpId(intent.operation_id),
            &[(
                "recovery-bucket",
                0,
                super::super::UsageDelta {
                    requests: 1,
                    ..Default::default()
                },
            )],
        )
        .await
        .unwrap();
    let child = GovState::usage_recovery_child(
        "child-bucket",
        0,
        super::super::ExactUsageDelta {
            requests: 7,
            ..Default::default()
        },
        super::super::ExactUsageDelta::default(),
    )
    .unwrap()
    .unwrap();
    let mut custody: super::super::raw_recovery::UsageCustody =
        serde_json::from_slice(&intent.payload).unwrap();
    custody.plain = Default::default();
    custody.handoffs.push(child.clone());
    let applied = first
        .new_recovery_event(
            intent.operation_id,
            intent.kind,
            intent.body_fingerprint,
            RecoveryState::Applied,
            intent.first_sent_at_ms,
            serde_json::to_vec(&custody).unwrap(),
        )
        .unwrap();
    first.keep_recovery_event(&applied).await.unwrap();
    assert!(first.recovery_event(child.operation_id).is_none());
    drop(first);
    let restarted = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    restarted.attach_recovery_sink(sink).await.unwrap();
    restarted.resume_raw_recovery().await.unwrap();
    let restored = restarted.recovery_event(child.operation_id).unwrap();
    assert_eq!(restored.body_fingerprint, child.body_fingerprint);
    assert_eq!(
        store
            .ledger()
            .get_usage("child-bucket", 0)
            .await
            .unwrap()
            .requests,
        7
    );
    restarted.resume_raw_recovery().await.unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage("child-bucket", 0)
            .await
            .unwrap()
            .requests,
        7
    );
}
#[tokio::test]
async fn two_unknown_positives_cannot_release_each_others_dependent_negatives() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    original.resume_raw_recovery().await.unwrap();
    let first = raw_intent(&original, 7).await;
    let second = raw_intent(&original, 11).await;
    drop(original);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let captured = gov
        .capture_usage_recovery(
            "recovery-bucket",
            0,
            super::super::ExactUsageDelta {
                requests: -18,
                ..Default::default()
            },
            Default::default(),
            &gov.capture_foreign_settled_snapshot().await,
        )
        .unwrap();
    assert!(captured.child.is_none());
    assert!(captured.deferred_plain.requests < 0);
    gov.drive_durable_usage_flight(&captured).await.unwrap();
    let remaining = gov
        .capture_usage_recovery(
            "recovery-bucket",
            0,
            captured.deferred_plain,
            captured.deferred_dated,
            &gov.capture_foreign_settled_snapshot().await,
        )
        .unwrap();
    assert!(remaining.child.is_none());
    assert!(remaining.deferred_plain.is_zero());
    gov.drive_durable_usage_flight(&remaining).await.unwrap();
    for intent in [first, second] {
        let selected = gov.recovery_event(intent.operation_id).unwrap();
        gov.resolve_raw_recovery(&RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: selected.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "operator".into(),
            reason: "neither original operation reached backend".into(),
        })
        .await
        .unwrap();
    }
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        0
    );
}

#[tokio::test]
async fn unknown_chunk_transfers_never_sent_unsigned_remainder_to_fresh_children() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    original.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&original, i128::from(u64::MAX)).await;
    drop(original);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    assert_eq!(
        gov.recovery_event(intent.operation_id).unwrap().state,
        RecoveryState::LandedUnknown
    );
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        u64::MAX - i64::MAX as u64,
        "only the old sent chunk is unknown; never-sent remainder keeps progressing"
    );
}
#[tokio::test]
async fn verdict_without_both_quiescence_attestations_persists_nothing() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    original.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&original, 7).await;
    drop(original);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let selected = gov.recovery_event(intent.operation_id).unwrap();
    let count = sink.selected.lock().unwrap().len();
    let cost = crate::cost::CostModel::flat(0);
    for (sender_quiesced, backend_quiesced) in [(false, false), (false, true), (true, false)] {
        let resolution = RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: selected.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced,
            backend_quiesced,
            actor: "operator".into(),
            reason: "quiescence is not confirmed".into(),
        };
        assert!(matches!(
            gov.recovery().resolve(&cost, resolution.clone()).await,
            Err(RecoveryError::Invalid(_))
        ));
        assert!(matches!(
            gov.resolve_raw_recovery(&resolution).await,
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!(
            gov.recovery_event(intent.operation_id),
            Some(selected.clone())
        );
        assert_eq!(sink.selected.lock().unwrap().len(), count);
        assert_eq!(
            store
                .ledger()
                .get_usage("recovery-bucket", 0)
                .await
                .unwrap()
                .requests,
            0
        );
    }
}

#[tokio::test]
async fn attested_verdict_still_requires_same_process_driver_quiescence() {
    use super::super::GovState;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    original.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&original, 7).await;
    drop(original);
    let gov = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let selected = gov.recovery_event(intent.operation_id).unwrap();
    let count = sink.selected.lock().unwrap().len();
    let driver = gov.recovery_driver(intent.operation_id).unwrap();
    let _running = driver.enter(false).await.unwrap();
    let resolution = RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: selected.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "attestation alone cannot override a running driver".into(),
    };
    assert!(matches!(
        gov.recovery()
            .resolve(&crate::cost::CostModel::flat(0), resolution)
            .await,
        Err(RecoveryError::Conflict(_))
    ));
    assert_eq!(gov.recovery_event(intent.operation_id), Some(selected));
    assert_eq!(sink.selected.lock().unwrap().len(), count);
}
#[tokio::test]
async fn retiring_a_successful_root_releases_ram_without_deleting_its_store_chain() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&gov, 7).await;
    gov.drive_raw_recovery(intent.operation_id).await.unwrap();
    let journal_len = sink.selected.lock().unwrap().len();
    assert_eq!(journal_len, 3);
    gov.forget_confirmed_recovery(intent.operation_id);
    assert!(gov.recovery_event(intent.operation_id).is_none());
    assert_eq!(sink.selected.lock().unwrap().len(), journal_len);
    drop(gov);
    let restarted = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    restarted.attach_recovery_sink(sink.clone()).await.unwrap();
    restarted.resume_raw_recovery().await.unwrap();
    assert!(restarted.recovery_event(intent.operation_id).is_none());
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        7
    );
    assert_eq!(sink.selected.lock().unwrap().len(), journal_len);
}

#[tokio::test]
async fn retiring_live_or_unknown_custody_cannot_discard_its_authority() {
    use super::super::GovState;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    original.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&original, 7).await;
    original.forget_confirmed_recovery(intent.operation_id);
    assert_eq!(
        original.recovery_event(intent.operation_id),
        Some(intent.clone())
    );
    drop(original);
    let gov = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    gov.forget_confirmed_recovery(intent.operation_id);
    assert_eq!(
        gov.recovery_event(intent.operation_id).unwrap().state,
        RecoveryState::LandedUnknown
    );
    let unknown = gov.recovery_event(intent.operation_id).unwrap();
    gov.resolve_raw_recovery(&RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: unknown.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "original never reached backend".into(),
    })
    .await
    .unwrap();
    gov.forget_confirmed_recovery(intent.operation_id);
    assert_eq!(
        gov.recovery_event(intent.operation_id).unwrap().state,
        RecoveryState::Settled
    );
    gov.validate_recovery_origin(
        &gov.selected_recovery_events()
            .into_iter()
            .find(|event| event.operation_id != intent.operation_id)
            .unwrap(),
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn foreign_adoption_lost_reply_retains_exact_children_and_sends_only_after_confirmation() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    let intent = raw_intent(&original, 7).await;
    sink.make_foreign(intent.operation_id, 17);
    drop(original);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    assert!(
        gov.recovery_event(intent.operation_id).is_none(),
        "inspection grants no writable custody"
    );
    let listed = gov.recovery().list(None, 10).await.unwrap().pop().unwrap();
    assert_eq!(listed.owner_node, Some(17));
    assert!(!listed.can_resolve);
    let resolution = RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: intent.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "adopter".into(),
        reason: "all old senders disarmed and backend mutations settled".into(),
    };
    let cost = crate::cost::CostModel::flat(0);
    sink.lose_adoption_reply.store(true, Ordering::Relaxed);
    assert!(matches!(
        gov.recovery().resolve(&cost, resolution.clone()).await,
        Err(RecoveryError::Unavailable(_))
    ));
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        0,
        "a selected adoption with an unknown reply cannot authorize local backend effects yet"
    );
    assert!(sink.inspect_foreign().await.unwrap().is_empty());
    let settled = gov
        .recovery()
        .resolve(&cost, resolution.clone())
        .await
        .unwrap();
    assert_eq!(settled.state, RecoveryState::Settled);
    assert_eq!(settled.owner_node, None);
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        7
    );
    let attempts = sink.adoption_attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts[0], attempts[1],
        "retry must retain exact child IDs and raw candidate bytes"
    );
    gov.recovery().resolve(&cost, resolution).await.unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        7
    );
}

#[tokio::test]
async fn foreign_reaffirmation_preserves_original_decision_audit_and_rejects_opposite_choice() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    let intent = raw_intent(&original, 7).await;
    let unknown = intent
        .checkpoint(RecoveryState::LandedUnknown, intent.payload.clone())
        .unwrap();
    original.keep_recovery_event(&unknown).await.unwrap();
    let old_resolution = RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: unknown.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "original-operator".into(),
        reason: "original not-landed verdict".into(),
    };
    let verdict = GovState::stage_foreign_raw_verdict(&unknown, &old_resolution)
        .unwrap()
        .pop()
        .unwrap();
    original.keep_recovery_event(&verdict).await.unwrap();
    sink.make_foreign(intent.operation_id, 23);
    drop(original);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    let mut adoption = RecoveryResolution {
        expected_revision: verdict.revision,
        actor: "new-operator".into(),
        reason: "new ownership attestation".into(),
        ..old_resolution
    };
    let cost = crate::cost::CostModel::flat(0);
    adoption.verdict = RecoveryVerdict::Landed;
    assert!(matches!(
        gov.recovery().resolve(&cost, adoption.clone()).await,
        Err(RecoveryError::Conflict(_))
    ));
    assert!(sink.adoption_attempts.lock().unwrap().is_empty());
    adoption.verdict = RecoveryVerdict::NotLanded;
    gov.recovery()
        .resolve(&cost, adoption.clone())
        .await
        .unwrap();
    let selected = gov.recovery_event(intent.operation_id).unwrap();
    let raw: serde_json::Value = serde_json::from_slice(&selected.payload).unwrap();
    assert_eq!(raw["verdict"]["actor"], "original-operator");
    assert_eq!(raw["verdict"]["reason"], "original not-landed verdict");
    assert_eq!(
        sink.adoption_attempts.lock().unwrap()[0].0.actor,
        "new-operator"
    );
    gov.recovery().resolve(&cost, adoption).await.unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        7
    );
}
#[tokio::test]
async fn foreign_settled_child_is_observed_as_receipt_without_adoption_or_reposting() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let original = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    original.attach_recovery_sink(sink.clone()).await.unwrap();
    let intent = raw_intent(&original, 1).await;
    store
        .ledger()
        .add_usage_batch_deduped(
            busbar_contract::records::OpId(intent.operation_id),
            &[(
                "recovery-bucket",
                0,
                super::super::UsageDelta {
                    requests: 1,
                    ..Default::default()
                },
            )],
        )
        .await
        .unwrap();
    let child = GovState::usage_recovery_child(
        "receipt-child",
        0,
        super::super::ExactUsageDelta {
            requests: 7,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap()
    .unwrap();
    let mut custody: super::super::raw_recovery::UsageCustody =
        serde_json::from_slice(&intent.payload).unwrap();
    custody.plain = Default::default();
    custody.handoffs.push(child.clone());
    let applied = original
        .new_recovery_event(
            intent.operation_id,
            intent.kind,
            intent.body_fingerprint,
            RecoveryState::Applied,
            intent.first_sent_at_ms,
            serde_json::to_vec(&custody).unwrap(),
        )
        .unwrap();
    original.keep_recovery_event(&applied).await.unwrap();
    original.drive_recovery_children(&applied).await.unwrap();
    original
        .drive_raw_recovery(child.operation_id)
        .await
        .unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage("receipt-child", 0)
            .await
            .unwrap()
            .requests,
        7
    );
    sink.make_foreign(child.operation_id, 42);
    drop(original);

    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    assert!(gov.recovery_event(child.operation_id).is_none());
    gov.resume_raw_recovery().await.unwrap();
    let settled = gov.recovery_event(intent.operation_id).unwrap();
    assert_eq!(settled.state, RecoveryState::Settled);
    assert!(gov.recovery_children_settled(&settled).await.unwrap());
    gov.resume_recovery_children(&settled).await.unwrap();
    assert!(
        gov.recovery_event(child.operation_id).is_none(),
        "readonly receipt grants no child write ownership"
    );
    assert!(sink.adoption_attempts.lock().unwrap().is_empty());
    assert_eq!(
        store
            .ledger()
            .get_usage("receipt-child", 0)
            .await
            .unwrap()
            .requests,
        7
    );
}
#[tokio::test]
async fn many_selected_revisions_keep_endpoints_and_verify_old_checkpoints_cold() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    let initial = raw_intent(&gov, 7).await;
    let mut current = initial.clone();
    let mut old = None;
    for revision in 1..=256 {
        current = gov
            .new_recovery_event(
                current.operation_id,
                current.kind,
                current.body_fingerprint,
                RecoveryState::Intent,
                current.first_sent_at_ms,
                current.payload.clone(),
            )
            .unwrap();
        gov.keep_recovery_event(&current).await.unwrap();
        if revision == 64 {
            old = Some(current.clone());
        }
    }
    let old = old.unwrap();
    assert_eq!(
        gov.recovery_initial_event(initial.operation_id),
        Some(initial.clone())
    );
    assert_eq!(gov.recovery_event(initial.operation_id), Some(current));
    assert!(
        gov.recovery_ancestor(initial.operation_id, old.fingerprint().unwrap())
            .is_none(),
        "historical payloads are not retained in the live per-operation Book"
    );
    gov.verify_recovery_checkpoint(&old).await.unwrap();
    {
        let owned = gov.recovery_book.entries.lock().unwrap();
        let entry = owned.get(&initial.operation_id).unwrap();
        assert!(entry.pending.is_none() && entry.adoption.is_none());
        assert_eq!(entry.initial.as_ref(), Some(&initial));
    }
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        0,
        "ancestry verification performs no usage effect"
    );
}

#[tokio::test]
async fn compatibility_selection_and_checkpoint_proofs_reject_unselected_forks_and_gaps() {
    let sink = Journal::default();
    let initial = intent();
    let applied = successor(&initial, RecoveryState::Applied);
    let settled = successor(&applied, RecoveryState::Settled);
    *sink.selected.lock().unwrap() = vec![initial.clone(), applied.clone(), settled.clone()];
    let selections = sink.replay_selections().await.unwrap();
    assert_eq!(
        selections,
        vec![RecoverySelection {
            initial: initial.clone(),
            selected: settled
        }]
    );
    sink.verify_checkpoint(&applied).await.unwrap();
    let unselected = successor(&initial, RecoveryState::LandedUnknown);
    assert!(
        matches!(
            sink.verify_checkpoint(&unselected).await,
            Err(RecoveryError::Conflict(_))
        ),
        "an otherwise legal journal candidate is not current selected ancestry"
    );
    let gap = RecoveryEvent {
        revision: 2,
        ..applied
    };
    *sink.selected.lock().unwrap() = vec![initial, gap];
    assert!(
        matches!(
            sink.replay_selections().await,
            Err(RecoveryError::Invalid(_))
        ),
        "matching initial/current identity cannot replace full legal predecessor verification"
    );
}
#[tokio::test]
async fn admin_resume_can_advance_a_captured_prerequisite_without_wedging_its_flight() {
    use super::super::GovState;
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let first = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    first.attach_recovery_sink(sink.clone()).await.unwrap();
    let admin = GovState::usage_recovery_child(
        "admin-bucket",
        0,
        super::super::ExactUsageDelta {
            requests: 1,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap()
    .unwrap();
    let admin_intent = first
        .new_recovery_event(
            admin.operation_id,
            admin.kind,
            admin.body_fingerprint,
            RecoveryState::Intent,
            admin.first_sent_at_ms,
            admin.payload,
        )
        .unwrap();
    first.keep_recovery_event(&admin_intent).await.unwrap();
    drop(first);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let admin_unknown = gov.recovery_event(admin_intent.operation_id).unwrap();
    assert_eq!(admin_unknown.state, RecoveryState::LandedUnknown);
    let owner = raw_intent(&gov, 7).await;
    let captured = gov
        .capture_usage_recovery(
            "recovery-bucket",
            0,
            super::super::ExactUsageDelta {
                requests: -3,
                ..Default::default()
            },
            Default::default(),
            &gov.capture_foreign_settled_snapshot().await,
        )
        .unwrap();
    let prerequisite = captured.prerequisite.as_ref().unwrap().clone();
    assert_eq!(prerequisite.operation_id, owner.operation_id);
    assert!(captured.child.is_none());
    assert!(gov.recovery_event(owner.operation_id).unwrap().revision < prerequisite.revision);

    gov.recovery()
        .resolve(
            &crate::cost::CostModel::flat(0),
            RecoveryResolution {
                operation_id: admin_unknown.operation_id,
                body_fingerprint: admin_unknown.body_fingerprint,
                expected_revision: admin_unknown.revision,
                verdict: RecoveryVerdict::NotLanded,
                sender_quiesced: true,
                backend_quiesced: true,
                actor: "operator".into(),
                reason: "admin operation independently confirmed not landed".into(),
            },
        )
        .await
        .unwrap();
    let settled = gov.recovery_event(owner.operation_id).unwrap();
    assert_eq!(settled.state, RecoveryState::Settled);
    assert!(settled.revision > prerequisite.revision);
    assert!(
        gov.keep_recovery_event(&prerequisite).await.is_err(),
        "Book.keep never rewinds a selected head"
    );
    let count = sink.selected.lock().unwrap().len();
    gov.drive_durable_usage_flight(&captured).await.unwrap();
    assert_eq!(sink.selected.lock().unwrap().len(), count);
    assert_eq!(gov.recovery_event(owner.operation_id), Some(settled));
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        4
    );
    assert_eq!(
        store
            .ledger()
            .get_usage("admin-bucket", 0)
            .await
            .unwrap()
            .requests,
        1
    );

    let mut forged = captured;
    let parent = forged.prerequisite.as_mut().unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&parent.payload).unwrap();
    payload["absorbed_plain"]["requests"] = serde_json::Value::String("-2".into());
    parent.payload = serde_json::to_vec(&payload).unwrap();
    assert!(
        gov.drive_durable_usage_flight(&forged).await.is_err(),
        "a different legal candidate at that revision is not selected ancestry"
    );
    assert_eq!(
        store
            .ledger()
            .get_usage("recovery-bucket", 0)
            .await
            .unwrap()
            .requests,
        4
    );
}
#[tokio::test]
async fn reused_host_flushes_fresh_refund_only_after_exact_foreign_settled_subtree_proof() {
    use super::super::{GovState, VirtualKey};
    for mode in 0..5 {
        let store = crate::real_store::core().await;
        let sink = Arc::new(Journal::default());
        let key_id = format!("vk_foreign_snapshot_{mode}");
        let key = VirtualKey {
            id: key_id.clone(),
            generation_hash: super::super::binding_marker(&key_id, "generation"),
            enabled: true,
            ..Default::default()
        };
        store.identity().put_key(&key).await.unwrap();
        let first = GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap();
        first.attach_recovery_sink(sink.clone()).await.unwrap();
        let total = if mode == 4 {
            u64::MAX
        } else {
            i64::MAX as u64 + 7
        };
        let root = GovState::usage_recovery_child(
            &key.id,
            0,
            super::super::ExactUsageDelta {
                requests: i128::from(total),
                billable_requests: i128::from(total),
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap()
        .unwrap();
        let initial = first
            .new_recovery_event(
                root.operation_id,
                root.kind,
                root.body_fingerprint,
                RecoveryState::Intent,
                root.first_sent_at_ms,
                root.payload,
            )
            .unwrap();
        first.keep_recovery_event(&initial).await.unwrap();
        let mut custody: super::super::raw_recovery::UsageCustody =
            serde_json::from_slice(&initial.payload).unwrap();
        store
            .ledger()
            .add_usage_batch_deduped(
                busbar_contract::records::OpId(initial.operation_id),
                &[(key.id.as_str(), 0, custody.chunk_plain.clone())],
            )
            .await
            .unwrap();
        let remainder = total - i64::MAX as u64;
        let child = GovState::usage_recovery_child(
            &key.id,
            0,
            super::super::ExactUsageDelta {
                requests: i128::from(remainder),
                billable_requests: i128::from(remainder),
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap()
        .unwrap();
        custody.plain = Default::default();
        custody.dated = Default::default();
        custody.handoffs.push(child.clone());
        let applied = first
            .new_recovery_event(
                initial.operation_id,
                initial.kind,
                initial.body_fingerprint,
                RecoveryState::Applied,
                initial.first_sent_at_ms,
                serde_json::to_vec(&custody).unwrap(),
            )
            .unwrap();
        first.keep_recovery_event(&applied).await.unwrap();
        first.drive_recovery_children(&applied).await.unwrap();
        let child_initial = first.recovery_event(child.operation_id).unwrap();
        let mut unselected = None;
        match mode {
            1 => {}
            2 => {
                let mut raw: super::super::raw_recovery::UsageCustody =
                    serde_json::from_slice(&child_initial.payload).unwrap();
                store
                    .ledger()
                    .add_usage_batch_deduped(
                        busbar_contract::records::OpId(child.operation_id),
                        &[(key.id.as_str(), 0, raw.chunk_plain.clone())],
                    )
                    .await
                    .unwrap();
                raw.plain = Default::default();
                raw.dated = Default::default();
                let candidate = child_initial
                    .checkpoint(RecoveryState::Applied, serde_json::to_vec(&raw).unwrap())
                    .unwrap();
                unselected = Some(
                    candidate
                        .checkpoint(RecoveryState::Settled, candidate.payload.clone())
                        .unwrap(),
                );
            }
            _ => {
                first.drive_raw_recovery(child.operation_id).await.unwrap();
                if mode == 3 {
                    let mut changed = custody.clone();
                    let mut payload: serde_json::Value =
                        serde_json::from_slice(&changed.handoffs[0].payload).unwrap();
                    payload["plain"]["requests"] = serde_json::Value::String("8".into());
                    payload["plain"]["billable_requests"] = serde_json::Value::String("8".into());
                    changed.handoffs[0].payload = serde_json::to_vec(&payload).unwrap();
                    let checkpoint = first
                        .new_recovery_event(
                            initial.operation_id,
                            initial.kind,
                            initial.body_fingerprint,
                            RecoveryState::Applied,
                            initial.first_sent_at_ms,
                            serde_json::to_vec(&changed).unwrap(),
                        )
                        .unwrap();
                    first.keep_recovery_event(&checkpoint).await.unwrap();
                }
                if mode == 4 {
                    let child_done = first.recovery_event(child.operation_id).unwrap();
                    let raw: super::super::raw_recovery::UsageCustody =
                        serde_json::from_slice(&child_done.payload).unwrap();
                    let grandchild = &raw.handoffs[0];
                    assert_eq!(
                        first.recovery_event(grandchild.operation_id).unwrap().state,
                        RecoveryState::Intent
                    );
                    sink.make_foreign(grandchild.operation_id, 42);
                }
            }
        }
        sink.make_foreign(child.operation_id, 42);
        drop(first);

        let gov = GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap();
        gov.attach_recovery_sink(sink.clone()).await.unwrap();
        let cost = crate::cost::CostModel::flat(0);
        gov.hydrate_budgets_async(&cost, crate::store::now())
            .await
            .unwrap();
        assert!(gov.recovery_event(child.operation_id).is_none());
        if let Some(candidate) = unselected {
            assert!(
                sink.verify_checkpoint(&candidate).await.is_err(),
                "unselected final-looking candidate is not a receipt"
            );
        }
        if mode == 4 {
            let proof = gov.capture_foreign_settled_snapshot().await;
            let held = gov
                .capture_usage_recovery(
                    &key.id,
                    0,
                    super::super::ExactUsageDelta {
                        billable_requests: -1,
                        ..Default::default()
                    },
                    Default::default(),
                    &proof,
                )
                .unwrap();
            assert_eq!(
                held.deferred_plain.billable_requests, -1,
                "a settled child with an unknown descendant does not prove its whole exposure settled"
            );
            continue;
        }
        let before = store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .billable_requests;
        let grant = gov.try_admit(&cost, &key, "", crate::store::now()).unwrap();
        gov.flush_budgets().await;
        assert_eq!(
            store
                .ledger()
                .get_usage(&key.id, 0)
                .await
                .unwrap()
                .billable_requests,
            before + 1
        );
        gov.refund_charge(grant.charge());
        gov.flush_budgets().await;
        let after = store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .billable_requests;
        assert_eq!(
            after,
            if mode == 0 { before } else { before + 1 },
            "only an exact fully settled foreign subtree releases the matching fresh refund (mode {mode})"
        );
        assert!(gov.recovery_event(child.operation_id).is_none());
        assert!(sink.adoption_attempts.lock().unwrap().is_empty());
    }
}

async fn settled_parent_with_handoffs(
    store: &Arc<crate::persistence::facade::CoreStore>,
    sink: &Arc<Journal>,
    children: usize,
    settle: bool,
) -> (super::super::GovState, RecoveryEvent) {
    use super::super::GovState;
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(sink.clone()).await.unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let intent = raw_intent(&gov, 1).await;
    store
        .ledger()
        .add_usage_batch_deduped(
            busbar_contract::records::OpId(intent.operation_id),
            &[(
                "recovery-bucket",
                0,
                super::super::UsageDelta {
                    requests: 1,
                    ..Default::default()
                },
            )],
        )
        .await
        .unwrap();
    let mut custody: super::super::raw_recovery::UsageCustody =
        serde_json::from_slice(&intent.payload).unwrap();
    custody.plain = Default::default();
    for index in 0..children {
        let child = GovState::usage_recovery_child(
            &format!("child-bucket-{index}"),
            0,
            super::super::ExactUsageDelta {
                requests: 7,
                ..Default::default()
            },
            super::super::ExactUsageDelta::default(),
        )
        .unwrap()
        .unwrap();
        custody.handoffs.push(child);
    }
    let applied = gov
        .new_recovery_event(
            intent.operation_id,
            intent.kind,
            intent.body_fingerprint,
            RecoveryState::Applied,
            intent.first_sent_at_ms,
            serde_json::to_vec(&custody).unwrap(),
        )
        .unwrap();
    gov.keep_recovery_event(&applied).await.unwrap();
    if settle {
        // The first pass selects and drives every child.
        gov.resume_raw_recovery().await.unwrap();
        gov.resume_raw_recovery().await.unwrap();
    }
    (gov, applied)
}

#[tokio::test]
async fn selected_parent_with_handoffs_is_not_repersisted() {
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let (gov, parent) = settled_parent_with_handoffs(&store, &sink, 2, true).await;
    assert!(gov.recovery_event(parent.operation_id).is_some());
    let settled = sink.persists.load(Ordering::Relaxed);
    for _ in 0..100 {
        gov.resume_raw_recovery().await.unwrap();
    }
    assert_eq!(
        sink.persists.load(Ordering::Relaxed) - settled,
        0,
        "100 recovery ticks over a settled parent must not re-persist it"
    );
}

#[tokio::test]
async fn new_child_still_selected_after_fast_exit() {
    let store = crate::real_store::core().await;
    let sink = Arc::new(Journal::default());
    let (gov, parent) = settled_parent_with_handoffs(&store, &sink, 1, false).await;
    let custody: super::super::raw_recovery::UsageCustody =
        serde_json::from_slice(&parent.payload).unwrap();
    let child = custody.handoffs[0].clone();
    assert!(gov.recovery_event(child.operation_id).is_none());
    sink.persisted_ops.lock().unwrap().clear();
    gov.resume_raw_recovery().await.unwrap();
    let selected = gov.recovery_event(child.operation_id).unwrap();
    assert_eq!(selected.body_fingerprint, child.body_fingerprint);
    let ops = sink.persisted_ops.lock().unwrap().clone();
    assert!(
        ops.iter().any(|(op, _)| *op == child.operation_id),
        "the new child is selected through persist"
    );
    // The parent may advance (Applied -> Settled is a new revision and a
    // real write); what must not happen is persisting the revision that
    // is already selected.
    assert_eq!(
        ops.iter()
            .filter(|(op, revision)| *op == parent.operation_id && *revision == parent.revision)
            .count(),
        0,
        "the already selected parent revision is not persisted again"
    );
}
