// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    control, BackendInfo, Call, ClockObservation, DatasetId, Durability, Failure, Mutation, Page,
    PersistenceBackend, PreparedCandidate,
};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    sent: Vec<PreparedCandidate>,
}
fn control_address(key: Vec<u8>) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key,
    }
}
fn row(state: &State, address: &Address) -> Option<Secret<Vec<u8>>> {
    if let Some(value) = state.rows.get(address) {
        return Some(value.clone());
    }
    if address.namespace != control::NAMESPACE.0 {
        return None;
    }
    let value = if address.key == control::DATASET_KEY {
        control::Dataset {
            id: DatasetId([1; 16]),
            writer_epoch: 2,
        }
        .encode()
        .unwrap()
        .to_vec()
    } else {
        control::Writer {
            retired_through: 2,
            admitted_through: 3,
        }
        .encode()
        .unwrap()
        .to_vec()
    };
    Some(Secret::new(value))
}
fn set_root_epoch(backend: &Backend, epoch: u64) {
    backend.state.lock().unwrap().rows.insert(
        control_address(control::DATASET_KEY.to_vec()),
        Secret::new(
            control::Dataset {
                id: DatasetId([1; 16]),
                writer_epoch: epoch,
            }
            .encode()
            .unwrap()
            .to_vec(),
        ),
    );
}
type ReadHook = Arc<dyn Fn(&Backend, &Read) + Send + Sync>;

#[derive(Default)]
struct Backend {
    after_read: Mutex<Option<ReadHook>>,
    state: Mutex<State>,
    lose_reply: AtomicBool,
    hang: AtomicBool,
    clock_seconds: AtomicU64,
}
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: Durability::Local,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let result = ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: 10 + self.clock_seconds.load(Ordering::SeqCst),
                },
                values: request
                    .addresses
                    .iter()
                    .map(|address| row(&state, address))
                    .collect(),
            };
            drop(state);
            let hook = self.after_read.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(self, &request);
            }
            Ok(result)
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let mut rows = Vec::new();
            let mut bytes = 0;
            let mut next = None;
            for (at, value) in &state.rows {
                if at.namespace != request.namespace.0
                    || !at.key.starts_with(&request.prefix)
                    || request.after.as_ref().is_some_and(|after| at.key <= *after)
                {
                    continue;
                }
                if rows.len() == request.max_items
                    || bytes + at.key.len() + value.expose(&crate::seal::lend()).len()
                        > request.max_bytes
                {
                    next = rows
                        .last()
                        .map(|(at, _): &(Address, Secret<Vec<u8>>)| at.key.clone());
                    break;
                }
                bytes += at.key.len() + value.expose(&crate::seal::lend()).len();
                rows.push((at.clone(), value.clone()));
            }
            Ok(Page {
                generation: 0,
                rows,
                next,
            })
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async move {
            Ok(ClockObservation {
                authority: [3; 16],
                unix_seconds: 10 + self.clock_seconds.load(Ordering::SeqCst),
            })
        })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.clone());
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let candidate = prepared.candidate();
            if let Some(digest) = state.receipts.get(&candidate.id.operation) {
                return Ok(if *digest == prepared.fingerprint() {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            let root_raw = row(&state, &control_address(control::DATASET_KEY.to_vec())).unwrap();
            let root = control::Dataset::decode(root_raw.expose(&crate::seal::lend())).unwrap();
            let writer_raw = row(
                &state,
                &control_address(control::writer_key(candidate.id.writer).to_vec()),
            )
            .unwrap();
            let writer = control::Writer::decode(writer_raw.expose(&crate::seal::lend())).unwrap();
            if root.writer_epoch != candidate.id.writer_epoch
                || !writer.admits(candidate.id.execution_epoch)
            {
                return Ok(Decision::ExpiredUnknown);
            }
            if candidate
                .time
                .is_some_and(|guard| !guard.permits(10 + self.clock_seconds.load(Ordering::SeqCst)))
            {
                return Ok(Decision::TimeGuardFailed {
                    observed_at: ClockObservation {
                        authority: [3; 16],
                        unix_seconds: 10 + self.clock_seconds.load(Ordering::SeqCst),
                    },
                });
            }
            for predicate in &candidate.predicates {
                let found = row(&state, &predicate.address);
                if !match &predicate.expected {
                    ExpectedValue::Absent => found.is_none(),
                    ExpectedValue::Exact(value) => found.as_ref() == Some(value),
                } {
                    return Ok(Decision::ConditionConflict);
                }
            }
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(address) => {
                        state.rows.remove(address);
                    }
                    Mutation::DeleteRange { .. } => panic!("journal never uses range deletion"),
                }
            }
            state
                .receipts
                .insert(candidate.id.operation, prepared.fingerprint());
            if self.lose_reply.swap(false, Ordering::SeqCst) {
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}
async fn attach(backend: Arc<Backend>, writer: u8) -> CoreStore {
    attach_at(backend, writer, 2).await
}
async fn attach_at(backend: Arc<Backend>, writer: u8, writer_epoch: u64) -> CoreStore {
    CoreStore::attach(
        backend,
        WriterAuthority {
            writer_epoch,
            writer: [writer; 16],
            execution_epoch: 3,
        },
        Limits {
            pending_operations: 32,
            conflict_retries: 1,
            scan_items: 4,
            scan_bytes: 128 * 1024,
        },
    )
    .await
    .unwrap()
}

fn intent() -> RecoveryEvent {
    RecoveryEvent {
        operation_id: [1; 16],
        revision: 0,
        previous_event: None,
        kind: crate::governance::recovery::RecoveryKind::Usage,
        body_fingerprint: [2; 32],
        state: RecoveryState::Intent,
        first_sent_at_ms: Some(1000),
        payload: b"{}".to_vec(),
    }
}
fn transition(previous: &RecoveryEvent, state: RecoveryState) -> RecoveryEvent {
    RecoveryEvent {
        revision: previous.revision + 1,
        previous_event: Some(previous.fingerprint().unwrap()),
        state,
        ..previous.clone()
    }
}
async fn sink(store: Arc<CoreStore>, node: u64) -> StoreRecovery {
    let journal = RuntimeJournal::open(
        store,
        node,
        crate::persistence::journal::runtime::BufferBudget {
            records: 64,
            bytes: 1024 * 1024,
        },
    )
    .await
    .unwrap();
    StoreRecovery::new(journal, crate::teller::Kernel::new().durability_token()).unwrap()
}

async fn imported_usage(
    backend: Arc<Backend>,
    applied_head: bool,
) -> (RecoveryEvent, RecoveryEvent) {
    use crate::governance::{ExactUsageDelta, GovState};
    let source = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let child = GovState::usage_recovery_child(
        "imported",
        0,
        ExactUsageDelta {
            requests: i128::from(i64::MAX) + 7,
            billable_requests: i128::from(i64::MAX) + 7,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap()
    .unwrap();
    let initial = RecoveryEvent {
        operation_id: child.operation_id,
        revision: 0,
        previous_event: None,
        kind: child.kind,
        body_fingerprint: child.body_fingerprint,
        state: RecoveryState::Intent,
        first_sent_at_ms: Some(1000),
        payload: child.payload,
    };
    source.persist(&initial).await.unwrap();
    let selected = if applied_head {
        let mut custody: crate::governance::raw_recovery::UsageCustody =
            serde_json::from_slice(&initial.payload).unwrap();
        let remainder = GovState::usage_recovery_child(
            "imported",
            0,
            ExactUsageDelta {
                requests: 7,
                billable_requests: 7,
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap()
        .unwrap();
        custody.plain = Default::default();
        custody.handoffs.push(remainder);
        let mut event = transition(&initial, RecoveryState::Applied);
        event.payload = serde_json::to_vec(&custody).unwrap();
        source.persist(&event).await.unwrap();
        event
    } else {
        initial.clone()
    };
    let raw = backend
        .state
        .lock()
        .unwrap()
        .rows
        .get(&address(&initial.operation_id))
        .unwrap()
        .clone();
    let evidence = imported::AppliedImportEvidence {
        source_dataset: [1; 16],
        source_snapshot: [2; 16],
        source_content_digest: [3; 32],
        source_schema_digest: [4; 32],
        upgrade: [5; 16],
        fence_enforcement: [6; 32],
        route: [7; 32],
        receipt_evidence: [8; 32],
        historical_body_digest: [9; 32],
        recovery_closure_digest: [10; 32],
    };
    for (at, bytes) in imported::applied_disposition_rows(
        &initial,
        &selected,
        raw.expose(&crate::seal::lend()),
        &evidence,
    )
    .unwrap()
    {
        backend.state.lock().unwrap().rows.insert(at, bytes);
    }
    (initial, selected)
}

fn native_writer_lease(backend: &Backend, writer: u8, expires_ms: u64) -> Address {
    let key = [b"writer:".as_slice(), &2_u64.to_be_bytes(), &[writer; 16]].concat();
    let address = crate::persistence::scoped::migration_address(
        true,
        crate::persistence::boot_identity::INSTANCE,
        crate::persistence::boot_identity::NODE_SCHEMA,
        &key,
    )
    .unwrap();
    backend.state.lock().unwrap().rows.insert(
        address.clone(),
        Secret::new([&[writer; 16][..], &expires_ms.to_be_bytes()].concat()),
    );
    address
}

#[tokio::test]
async fn native_writer_retirement_waits_for_live_lease_and_preserves_renewal_race() {
    use crate::persistence::boot_identity::{WriterRetirement, WriterRetirements};
    let backend = Arc::new(Backend::default());
    let core = attach(backend.clone(), 2).await;
    let owner = WriterRetirements::default();
    let lease = native_writer_lease(&backend, 1, 11_000);
    assert!(matches!(
        owner.retire(&core, 2, [1; 16]).await.unwrap(),
        WriterRetirement::Live {
            retry_at_ms: 11_000
        }
    ));
    backend.clock_seconds.store(1, Ordering::SeqCst);
    *backend.after_read.lock().unwrap() = Some(Arc::new(move |backend, request| {
        if request.addresses.contains(&lease) {
            backend.after_read.lock().unwrap().take();
            native_writer_lease(backend, 1, 30_000);
        }
    }));
    assert!(matches!(
        owner.retire(&core, 2, [1; 16]).await.unwrap(),
        WriterRetirement::Pending
    ));
    assert!(matches!(
        owner.retire(&core, 2, [1; 16]).await.unwrap(),
        WriterRetirement::Live {
            retry_at_ms: 30_000
        }
    ));
    let raw = row(
        &backend.state.lock().unwrap(),
        &control_address(control::writer_key([1; 16]).to_vec()),
    )
    .unwrap();
    assert_ne!(
        control::Writer::decode(raw.expose(&crate::seal::lend()))
            .unwrap()
            .retired_through,
        u64::MAX
    );
}

#[tokio::test]
async fn native_writer_retirement_unknown_retries_exact_fence_and_blocks_delayed_effects() {
    use crate::persistence::boot_identity::{WriterRetirement, WriterRetirements};
    let backend = Arc::new(Backend::default());
    let old = attach(backend.clone(), 1).await;
    let core = attach(backend.clone(), 2).await;
    native_writer_lease(&backend, 1, 10_000);
    let delayed = PreparedCandidate::new(busbar_contract::persistence::Candidate {
        id: old.next_id().unwrap(),
        codec: busbar_contract::persistence::CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Put {
            address: Address {
                namespace: [21; 16],
                key: b"delayed".to_vec(),
            },
            value: Secret::new(vec![1]),
        }],
        time: None,
        result: Secret::default(),
    })
    .unwrap();
    let owner = WriterRetirements::default();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        owner.retire(&core, 2, [1; 16]).await.unwrap(),
        WriterRetirement::Pending
    ));
    let fingerprint = backend
        .state
        .lock()
        .unwrap()
        .sent
        .last()
        .unwrap()
        .fingerprint();
    assert!(matches!(
        owner.retire(&core, 2, [1; 16]).await.unwrap(),
        WriterRetirement::Retired(_)
    ));
    assert_eq!(
        backend
            .state
            .lock()
            .unwrap()
            .sent
            .iter()
            .filter(|candidate| candidate.fingerprint() == fingerprint)
            .count(),
        2
    );
    assert!(matches!(
        backend.commit(delayed).await.unwrap(),
        Decision::ExpiredUnknown
    ));
}

#[tokio::test]
async fn native_writer_retirement_adopts_current_intent_without_migration_or_duplicate_charge() {
    let backend = Arc::new(Backend::default());
    let (initial, _) = imported_usage(backend.clone(), false).await;
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .retain(|address, _| address.namespace != *b"busbar.recimp1\0\0");
    native_writer_lease(&backend, 1, 10_000);
    let target = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let selected = target.replay_selections().await.unwrap().pop().unwrap();
    assert_eq!(selected.initial, initial);
    assert_eq!(selected.selected.state, RecoveryState::VerdictNotLanded);
    let raw = row(
        &backend.state.lock().unwrap(),
        &control_address(control::writer_key([1; 16]).to_vec()),
    )
    .unwrap();
    assert_eq!(
        control::Writer::decode(raw.expose(&crate::seal::lend()))
            .unwrap()
            .retired_through,
        u64::MAX
    );
}

#[tokio::test]
async fn native_writer_retirement_cancellation_retains_original_target_and_candidate() {
    use crate::persistence::boot_identity::{WriterRetirement, WriterRetirements};
    let backend = Arc::new(Backend::default());
    let core = attach(backend.clone(), 2).await;
    native_writer_lease(&backend, 1, 10_000);
    let owner = WriterRetirements::default();
    backend.hang.store(true, Ordering::SeqCst);
    {
        let pending = owner.retire(&core, 2, [1; 16]);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
    }
    let fingerprint = backend
        .state
        .lock()
        .unwrap()
        .sent
        .last()
        .unwrap()
        .fingerprint();
    backend.hang.store(false, Ordering::SeqCst);
    assert!(matches!(
        owner.retire(&core, 2, [1; 16]).await.unwrap(),
        WriterRetirement::Retired(_)
    ));
    assert_eq!(
        backend
            .state
            .lock()
            .unwrap()
            .sent
            .iter()
            .filter(|candidate| candidate.fingerprint() == fingerprint)
            .count(),
        2
    );
    assert_eq!(core.pending_operations().unwrap(), 0);
}

#[tokio::test]
async fn imported_applied_intent_retains_exact_descriptor_after_unknown_and_original_ancestry() {
    let backend = Arc::new(Backend::default());
    let (initial, _) = imported_usage(backend.clone(), false).await;
    let target = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(target.adopt_imported().await.is_err());
    let descriptor_attempt = backend.state.lock().unwrap().sent.last().unwrap().clone();
    let selected = target.replay_selections().await.unwrap().pop().unwrap();
    assert_eq!(selected.initial, initial);
    assert_eq!(selected.selected.state, RecoveryState::VerdictLanded);
    let custody: serde_json::Value = serde_json::from_slice(&selected.selected.payload).unwrap();
    assert_eq!(custody["handoffs"][0]["first_sent_at_ms"], 10_000);
    let child_payload: Vec<u8> =
        serde_json::from_value(custody["handoffs"][0]["payload"].clone()).unwrap();
    let remainder: crate::governance::raw_recovery::UsageCustody =
        serde_json::from_slice(&child_payload).unwrap();
    assert_eq!(remainder.plain.requests, 7);
    let repeated = backend
        .state
        .lock()
        .unwrap()
        .sent
        .iter()
        .filter(|attempt| attempt.fingerprint() == descriptor_attempt.fingerprint())
        .count();
    assert_eq!(repeated, 2);
    let guards = backend
        .state
        .lock()
        .unwrap()
        .sent
        .last()
        .unwrap()
        .candidate()
        .predicates
        .iter()
        .map(|guard| guard.address.namespace)
        .collect::<Vec<_>>();
    assert!(guards.contains(b"busbar.recimp1\0\0"));
    assert!(guards.contains(b"busbar.recctx1\0\0"));
    target.replay_selections().await.unwrap();
}

#[tokio::test]
async fn native_writer_retirement_resolves_exact_applied_receipt_without_reapplying_chunk() {
    use crate::governance::GovState;
    let backend = Arc::new(Backend::default());
    let (initial, _) = imported_usage(backend.clone(), false).await;
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .retain(|address, _| address.namespace != *b"busbar.recimp1\0\0");
    let source = attach(backend.clone(), 1).await;
    let cells = GovState::legacy_usage_values(&initial).unwrap();
    let cells = cells
        .iter()
        .map(|(bucket, window, delta)| (bucket.as_str(), *window, delta.clone()))
        .collect::<Vec<_>>();
    source
        .ledger()
        .add_usage_batch_deduped(busbar_contract::records::OpId(initial.operation_id), &cells)
        .await
        .unwrap();
    native_writer_lease(&backend, 1, 10_000);
    let target_store = Arc::new(attach(backend, 2).await);
    let target = sink(target_store.clone(), 8).await;
    let selected = target.replay_selections().await.unwrap().pop().unwrap();
    assert_eq!(selected.selected.state, RecoveryState::VerdictLanded);
    assert_eq!(
        target_store
            .ledger()
            .get_usage("imported", 0)
            .await
            .unwrap()
            .requests,
        i64::MAX as u64
    );
    let replayed = target.replay_selections().await.unwrap().pop().unwrap();
    assert_eq!(replayed, selected);
    assert_eq!(
        target_store
            .ledger()
            .get_usage("imported", 0)
            .await
            .unwrap()
            .requests,
        i64::MAX as u64
    );
}

#[tokio::test]
async fn imported_applied_cold_descriptor_reuses_winning_birth_before_planning() {
    let backend = Arc::new(Backend::default());
    let (initial, _) = imported_usage(backend.clone(), false).await;
    let target = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(target.adopt_imported().await.is_err());
    backend.clock_seconds.store(50, Ordering::SeqCst);
    let restarted = sink(Arc::new(attach(backend, 3).await), 9).await;
    let selected = restarted.replay_selections().await.unwrap().pop().unwrap();
    assert_eq!(selected.initial, initial);
    let custody: serde_json::Value = serde_json::from_slice(&selected.selected.payload).unwrap();
    assert_eq!(custody["handoffs"][0]["first_sent_at_ms"], 10_000);
    assert!(target.replay_selections().await.is_err());
}

#[tokio::test]
async fn imported_applied_head_preserves_authorized_children_and_refuses_unretired_new_owner() {
    let backend = Arc::new(Backend::default());
    let (initial, original) = imported_usage(backend.clone(), true).await;
    let target = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let selected = target.replay_selections().await.unwrap().pop().unwrap();
    assert_eq!(selected.initial, initial);
    assert_eq!(selected.selected.state, RecoveryState::Applied);
    assert_eq!(selected.selected.payload, original.payload);
    let competitor = sink(Arc::new(attach(backend, 3).await), 9).await;
    assert!(
        matches!(competitor.replay_selections().await, Err(RecoveryError::Unavailable(message)) if message.contains("writer lease"))
    );
}
fn attestation(event: &RecoveryEvent) -> RecoveryResolution {
    RecoveryResolution {
        operation_id: event.operation_id,
        body_fingerprint: event.body_fingerprint,
        expected_revision: event.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "all prior senders and backend commands quiesced".into(),
    }
}

#[tokio::test]
async fn original_frames_select_complete_ancestry_and_ignore_unselected_forks() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 1).await);
    let recovery = sink(store.clone(), 7).await;
    let initial = intent();
    let applied_event = transition(&initial, RecoveryState::Applied);
    let settled = transition(&applied_event, RecoveryState::Settled);
    for event in [&initial, &applied_event, &settled] {
        recovery.persist(event).await.unwrap();
    }
    recovery.confirm_owned_checkpoint(&initial).await.unwrap();
    recovery
        .confirm_owned_checkpoint(&applied_event)
        .await
        .unwrap();
    let proof = recovery.owned().await.unwrap();
    let journal = StoreJournal::new(&store, 7).unwrap();
    let fork = transition(&initial, RecoveryState::LandedUnknown);
    let frame = journal
        .seal(
            &proof,
            Entry::new(
                RecordClass::Reconciliation,
                body(&Candidate {
                    event: fork.clone(),
                    previous_head: None,
                    adoption: None,
                })
                .unwrap(),
            ),
        )
        .unwrap();
    assert!(applied(journal.append(&proof, &[frame]).await.unwrap()).unwrap());
    assert!(recovery.verify_checkpoint(&fork).await.is_err());
    assert_eq!(
        recovery.replay().await.unwrap(),
        vec![initial.clone(), applied_event, settled.clone()]
    );
    assert_eq!(
        recovery.replay_selections().await.unwrap(),
        vec![RecoverySelection {
            initial,
            selected: settled
        }]
    );
}

#[tokio::test]
async fn unknown_append_retries_exact_original_and_refuses_changed_candidate() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 1).await);
    let recovery = sink(store, 7).await;
    let event = intent();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(recovery.persist(&event).await.is_err());
    let original = {
        recovery
            .state
            .lock()
            .unwrap()
            .pending
            .get(&event.operation_id)
            .unwrap()
            .record
            .clone()
    };
    let mut changed = event.clone();
    changed.payload = b"{\"changed\":true}".to_vec();
    assert!(matches!(
        recovery.persist(&changed).await,
        Err(RecoveryError::Conflict(_))
    ));
    recovery.persist(&event).await.unwrap();
    assert!(recovery.state.lock().unwrap().pending.is_empty());
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
    let frames = state
        .rows
        .values()
        .filter(|value| *value == &Secret::new(original.body.clone()))
        .count();
    assert_eq!(frames, 1);
}

#[tokio::test]
async fn attested_foreign_adoption_selects_only_final_verdict_and_transfers_ownership() {
    let backend = Arc::new(Backend::default());
    let old = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let recipient = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let initial = intent();
    old.persist(&initial).await.unwrap();
    let unknown = transition(&initial, RecoveryState::LandedUnknown);
    let verdict = transition(&unknown, RecoveryState::VerdictNotLanded);
    let resolution = attestation(&initial);
    let mut missing = resolution.clone();
    missing.backend_quiesced = false;
    assert!(recipient
        .adopt_verdict_selection(&missing, &[unknown.clone(), verdict.clone()])
        .await
        .is_err());
    let selected = recipient
        .adopt_verdict_selection(&resolution, &[unknown.clone(), verdict.clone()])
        .await
        .unwrap();
    assert_eq!(selected.selected, verdict);
    recipient.confirm_owned_checkpoint(&initial).await.unwrap();
    recipient.confirm_owned_checkpoint(&unknown).await.unwrap();
    assert!(old.confirm_owned_checkpoint(&initial).await.is_err());
    old.verify_checkpoint(&initial).await.unwrap();
    let inspections = old.inspect_foreign().await.unwrap();
    assert_eq!(inspections.len(), 1);
    assert_eq!(inspections[0].owner_node, 8);
    assert_eq!(
        recipient
            .adopt_verdict_selection(&resolution, &[unknown, verdict.clone()])
            .await
            .unwrap()
            .selected,
        verdict
    );
}

#[tokio::test]
async fn cold_dataset_cutover_revokes_cached_owned_receipt_proof() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let event = intent();
    recovery.persist(&event).await.unwrap();
    recovery.confirm_owned_checkpoint(&event).await.unwrap();
    set_root_epoch(&backend, 3);
    assert!(recovery.confirm_owned_checkpoint(&event).await.is_err());
}

#[tokio::test]
async fn selected_parent_requires_exact_child_template_and_immutable_origin() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend, 1).await), 7).await;
    let mut child = intent();
    child.operation_id = [9; 16];
    child.body_fingerprint = [8; 32];
    let template = serde_json::json!({"physical":[1,2,3]});
    let mut parent = intent();
    parent.operation_id = [6; 16];
    parent.payload = b"{\"handoffs\":[]}".to_vec();
    let mut checkpoint = transition(&parent, RecoveryState::Applied);
    checkpoint.payload=serde_json::to_vec(&serde_json::json!({"handoffs":[{"operation_id":child.operation_id,"kind":child.kind,"body_fingerprint":child.body_fingerprint,"first_sent_at_ms":child.first_sent_at_ms,"payload":serde_json::to_vec(&template).unwrap()}]})).unwrap();
    let mut physical = template;
    physical["origin"] = serde_json::json!({"operation_id":checkpoint.operation_id,"event_fingerprint":checkpoint.fingerprint().unwrap()});
    child.payload = serde_json::to_vec(&physical).unwrap();
    recovery.persist(&parent).await.unwrap();
    recovery.persist(&checkpoint).await.unwrap();
    let mut changed = child.clone();
    physical["physical"] = serde_json::json!([1, 2, 99]);
    changed.payload = serde_json::to_vec(&physical).unwrap();
    assert!(matches!(
        recovery.persist(&changed).await,
        Err(RecoveryError::Invalid(_))
    ));
    assert!(head(&recovery.store, &child.operation_id)
        .await
        .unwrap()
        .is_none());
    recovery.persist(&child).await.unwrap();
    let mut changed_origin = transition(&child, RecoveryState::LandedUnknown);
    let mut raw: serde_json::Value = serde_json::from_slice(&changed_origin.payload).unwrap();
    raw["origin"] = serde_json::Value::Null;
    changed_origin.payload = serde_json::to_vec(&raw).unwrap();
    assert!(matches!(
        recovery.persist(&changed_origin).await,
        Err(RecoveryError::Invalid(_))
    ));
    recovery.confirm_owned_checkpoint(&child).await.unwrap();
}

#[tokio::test]
async fn cancellation_keeps_the_exact_original_candidate_for_retry() {
    let backend = Arc::new(Backend::default());
    let recovery = Arc::new(sink(Arc::new(attach(backend.clone(), 1).await), 7).await);
    backend.hang.store(true, Ordering::SeqCst);
    let waiter = {
        let recovery = recovery.clone();
        tokio::spawn(async move { recovery.persist(&intent()).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while backend.state.lock().unwrap().sent.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(recovery.state.lock().unwrap().pending.len(), 1);
    backend.hang.store(false, Ordering::SeqCst);
    recovery.persist(&intent()).await.unwrap();
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
}

#[tokio::test]
async fn shared_runtime_orders_prior_audit_staging_before_recovery_frames() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend, 1).await), 7).await;
    let prior = recovery
        .journal
        .stage_run(&[Entry::new(
            RecordClass::Transaction,
            b"unrelated audit or amendment".to_vec(),
        )])
        .unwrap();
    recovery.persist(&intent()).await.unwrap();
    recovery.journal.confirm(&prior).await.unwrap();
    let selected = head(&recovery.store, &intent().operation_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(selected.sequence, prior.records()[0].node_seq + 1);
    recovery.confirm_owned_checkpoint(&intent()).await.unwrap();
}

#[path = "usage_origin_final_fold.rs"]
mod usage_origin_final_fold;
