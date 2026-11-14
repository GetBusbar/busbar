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
/// Owns the whole reply, so a test can await a real live append before the
/// unchanged row read. The synchronous `after_read` cannot await.
type AsyncReadHook = Arc<dyn Fn(Arc<Read>) -> Call<'static, ReadResult> + Send + Sync>;
type ScanHook = Arc<dyn Fn(Arc<Scan>) -> Call<'static, Page> + Send + Sync>;

#[derive(Default)]
struct Backend {
    after_read: Mutex<Option<ReadHook>>,
    read_hook: Mutex<Option<AsyncReadHook>>,
    scan_hook: Mutex<Option<ScanHook>>,
    state: Mutex<State>,
    lose_reply: AtomicBool,
    hang: AtomicBool,
    clock_seconds: AtomicU64,
}
impl Backend {
    fn read_rows(&self, request: &Read) -> ReadResult {
        let state = self.state.lock().unwrap();
        ReadResult::Values {
            observed_at: ClockObservation {
                authority: [3; 16],
                unix_seconds: 10 + self.clock_seconds.load(Ordering::SeqCst),
            },
            values: request
                .addresses
                .iter()
                .map(|address| row(&state, address))
                .collect(),
        }
    }
    fn scan_rows(&self, request: &Scan) -> Page {
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
        Page {
            generation: 0,
            rows,
            next,
        }
    }
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
        let hook = self.read_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            return hook(request);
        }
        Box::pin(async move {
            let result = self.read_rows(&request);
            let hook = self.after_read.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(self, &request);
            }
            Ok(result)
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        let hook = self.scan_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            return hook(request);
        }
        Box::pin(async move { Ok(self.scan_rows(&request)) })
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

#[tokio::test]
async fn history_record_cache_bounds_native_proof_and_preserves_miss_and_final_guard() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend, 1).await), 7).await;
    let mut events = Vec::new();
    for id in 1..=6 {
        let mut event = intent();
        event.operation_id = [id; 16];
        recovery.persist(&event).await.unwrap();
        events.push(event);
    }
    let tip = head(&recovery.store, &events[0].operation_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    let retained_tip = head(&recovery.store, &events[5].operation_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut history = History::new(&recovery.store);
    history.proof(recovery.node).await.unwrap();
    assert!(history.records.records.len() <= recovery.store.limits().scan_items);
    assert!(history.records.bytes <= recovery.store.limits().scan_bytes);
    assert!(!history
        .records
        .records
        .contains_key(&(tip.node, tip.sequence)));
    assert_eq!(history.candidate(&tip).await.unwrap().event, events[0]);
    // A subsequent append cannot invalidate immutable original bytes, but it
    // must still invalidate this attempt's final native authority predicates.
    let mut next = intent();
    next.operation_id = [7; 16];
    recovery.persist(&next).await.unwrap();
    assert_eq!(history.candidate(&tip).await.unwrap().event, events[0]);
    assert!(history
        .records
        .records
        .contains_key(&(retained_tip.node, retained_tip.sequence)));
    assert_eq!(
        history.candidate(&retained_tip).await.unwrap().event,
        events[5]
    );
    assert!(history.finish().await.is_err());
}

#[tokio::test]
async fn history_record_cache_never_publishes_an_incomplete_native_proof() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    recovery.persist(&intent()).await.unwrap();
    {
        let mut state = backend.state.lock().unwrap();
        let at = state
            .rows
            .iter()
            .find_map(|(at, value)| {
                JournalRecord::decode(value.expose(&crate::seal::lend()))
                    .ok()
                    .map(|_| at.clone())
            })
            .unwrap();
        state
            .rows
            .insert(at, Secret::new(b"corrupt original".to_vec()));
    }
    let mut history = History::new(&recovery.store);
    assert!(history.proof(recovery.node).await.is_err());
    assert!(history.records.records.is_empty());
    assert_eq!(history.records.bytes, 0);
    assert!(history.proofs.is_empty());
}

/// Two pages per independent namespace, with different generations in each bucket.
fn recovery_scan_page(request: &Scan) -> Page {
    let bucket = (0..=u8::MAX)
        .find(|bucket| partition::namespace(RECOVERY, &[&[*bucket]]) == request.namespace)
        .unwrap();
    assert_eq!(request.dataset, DatasetId([1; 16]));
    assert_eq!(request.prefix, RECOVERY.0);
    assert!(!request.allow_change);
    assert_eq!(request.max_items, 4);
    assert_eq!(request.max_bytes, 128 * 1024);
    let generation = 100 + u64::from(bucket);
    let mut operation = [0; 16];
    operation[0] = bucket;
    let next = if let Some(after) = &request.after {
        assert_eq!(*after, address(&operation).key);
        assert_eq!(request.generation, Some(generation));
        operation[15] = 1;
        None
    } else {
        assert_eq!(request.generation, None);
        Some(address(&operation).key)
    };
    let head = Head {
        version: 1,
        node: 1,
        sequence: u64::from(bucket) + 1,
        revision: u64::from(operation[15]),
        event_digest: [bucket; 32],
    };
    Page {
        generation,
        rows: vec![(
            address(&operation),
            Secret::new(serde_json::to_vec(&head).unwrap()),
        )],
        next,
    }
}

#[tokio::test]
async fn heads_overlap_four_buckets_with_serial_pages_and_sorted_complete_results() {
    #[derive(Default)]
    struct Trace {
        active: BTreeSet<[u8; 16]>,
        maximum: usize,
        visits: BTreeMap<[u8; 16], usize>,
    }
    let trace = Arc::new(Mutex::new(Trace::default()));
    let permits = Arc::new(tokio::sync::Semaphore::new(0));
    let backend = Arc::new(Backend::default());
    *backend.scan_hook.lock().unwrap() = Some(Arc::new({
        let trace = trace.clone();
        let permits = permits.clone();
        move |request| {
            let trace = trace.clone();
            let permits = permits.clone();
            Box::pin(async move {
                {
                    let mut trace = trace.lock().unwrap();
                    assert!(
                        trace.active.insert(request.namespace.0),
                        "overlapping pages in one bucket"
                    );
                    *trace.visits.entry(request.namespace.0).or_default() += 1;
                    trace.maximum = trace.maximum.max(trace.active.len());
                    assert!(trace.maximum <= 4);
                }
                // Keep bucket zero pending while other buckets complete out of order.
                if request.namespace == partition::namespace(RECOVERY, &[&[0]]) {
                    permits.acquire().await.unwrap().forget();
                } else {
                    tokio::task::yield_now().await;
                }
                let page = recovery_scan_page(&request);
                assert!(trace.lock().unwrap().active.remove(&request.namespace.0));
                Ok(page)
            })
        }
    }));
    let store = attach(backend, 1).await;
    let mut scanning = Box::pin(heads(&store));
    assert!(futures::poll!(&mut scanning).is_pending());
    assert_eq!(trace.lock().unwrap().active.len(), 4);
    // Drive later buckets to completion while the first is still pending.
    for _ in 0..512 {
        assert!(futures::poll!(&mut scanning).is_pending());
        tokio::task::yield_now().await;
    }
    assert_eq!(trace.lock().unwrap().visits.len(), 256);
    permits.add_permits(2);
    let result = scanning.await.unwrap();
    assert_eq!(result.len(), 512);
    for (index, (operation, head)) in result.iter().enumerate() {
        assert_eq!(operation[0] as usize, index / 2);
        assert_eq!(operation[15] as usize, index % 2);
        assert_eq!(head.sequence as usize, index / 2 + 1);
        assert_eq!(head.revision as usize, index % 2);
    }
    let trace = trace.lock().unwrap();
    assert_eq!(trace.maximum, 4);
    assert!(trace.active.is_empty());
    assert!(trace.visits.values().all(|pages| *pages == 2));
}

#[tokio::test]
async fn heads_refuse_invalid_or_failed_pages_without_partial_results() {
    for fault in 0..10 {
        let backend = Arc::new(Backend::default());
        *backend.scan_hook.lock().unwrap() = Some(Arc::new(move |request| {
            Box::pin(async move {
                let mut page = recovery_scan_page(&request);
                if request.namespace == partition::namespace(RECOVERY, &[&[2]])
                    && request.after.is_some()
                {
                    match fault {
                        0 => page.generation += 1,
                        1 => page.next = request.after.clone(),
                        2 => page.rows[0].0.namespace = [0; 16],
                        3 => page.rows[0].0.key.pop().map(|_| ()).unwrap(),
                        4 => page.rows[0].0.key[0] ^= 1,
                        5 => page.rows[0].0.key[16] ^= 1,
                        6..=8 => {
                            let mut head: Head =
                                serde_json::from_slice(page.rows[0].1.expose(&crate::seal::lend()))
                                    .unwrap();
                            match fault {
                                6 => head.version = 2,
                                7 => head.node = 0,
                                _ => head.sequence = 0,
                            }
                            page.rows[0].1 = Secret::new(serde_json::to_vec(&head).unwrap());
                        }
                        _ => return Err(Failure::Unknown),
                    }
                }
                Ok(page)
            })
        }));
        let store = attach(backend, 1).await;
        let error = heads(&store).await.unwrap_err();
        if fault == 9 {
            assert!(matches!(error, RecoveryError::Unavailable(_)));
        } else {
            assert!(
                matches!(error, RecoveryError::Invalid(_)),
                "fault {fault}: {error:?}"
            );
        }
    }
}

/// A live write on this node's own runtime journal. It moves the selected
/// head H and the owner's verified head together, as a concurrent audit,
/// usage or checkpoint commit does after boot.
async fn live_append(journal: &RuntimeJournal) {
    let run = journal
        .stage_run(&[Entry::new(
            RecordClass::Transaction,
            b"concurrent local journal write".to_vec(),
        )])
        .unwrap();
    journal.confirm(&run).await.unwrap();
}

#[derive(Clone, Copy)]
enum Interleave {
    /// The node's own journal owner commits one more record.
    Append,
    /// A cold dataset cutover fences this node's writer epoch.
    Cutover,
}

async fn interleave(backend: &Backend, journal: &RuntimeJournal, action: Interleave) {
    match action {
        Interleave::Append => live_append(journal).await,
        Interleave::Cutover => set_root_epoch(backend, 3),
    }
}

/// Run `action` once, inside the first RECOVERY bucket scan of a listing.
fn on_first_recovery_scan(
    backend: &Arc<Backend>,
    journal: &Arc<RuntimeJournal>,
    action: Interleave,
) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let (owner, journal, done) = (backend.clone(), journal.clone(), fired.clone());
    *backend.scan_hook.lock().unwrap() = Some(Arc::new(move |request: Arc<Scan>| {
        let (backend, journal, done) = (owner.clone(), journal.clone(), done.clone());
        let trigger = request.prefix == RECOVERY.0;
        if trigger {
            // One-shot: later scans, and the append's own I/O, see the plain store.
            backend.scan_hook.lock().unwrap().take();
        }
        Box::pin(async move {
            if trigger {
                interleave(&backend, &journal, action).await;
                done.store(true, Ordering::SeqCst);
            }
            Ok(backend.scan_rows(&request))
        })
    }));
    fired
}

/// Run `action` once, before answering the `nth` read that includes the
/// selected head row of `operation`.
fn on_nth_head_read(
    backend: &Arc<Backend>,
    journal: &Arc<RuntimeJournal>,
    operation: [u8; 16],
    nth: usize,
    action: Interleave,
) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target = address(&operation);
    let (owner, journal, done) = (backend.clone(), journal.clone(), fired.clone());
    *backend.read_hook.lock().unwrap() = Some(Arc::new(move |request: Arc<Read>| {
        let (backend, journal, done) = (owner.clone(), journal.clone(), done.clone());
        let trigger =
            request.addresses.contains(&target) && seen.fetch_add(1, Ordering::SeqCst) + 1 == nth;
        if trigger {
            backend.read_hook.lock().unwrap().take();
        }
        Box::pin(async move {
            if trigger {
                interleave(&backend, &journal, action).await;
                done.store(true, Ordering::SeqCst);
            }
            Ok(backend.read_rows(&request))
        })
    }));
    fired
}

/// Local node 7 selects nothing. Foreign node 9 selects parent [6;16] and its
/// Applied checkpoint; foreign node 8 selects child [9;16], whose origin is
/// that checkpoint. Returns the local sink, the checkpoint and the child.
async fn foreign_parent_and_child(
    backend: &Arc<Backend>,
) -> (StoreRecovery, RecoveryEvent, RecoveryEvent) {
    let local = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let child_owner = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let parent_owner = sink(Arc::new(attach(backend.clone(), 3).await), 9).await;
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
    parent_owner.persist(&parent).await.unwrap();
    parent_owner.persist(&checkpoint).await.unwrap();
    child_owner.persist(&child).await.unwrap();
    (local, checkpoint, child)
}

/// The listing is read-only. A record this node's own journal owner commits
/// while the RECOVERY buckets are scanned is not a loss of authority.
#[tokio::test]
async fn inspect_foreign_survives_live_local_append() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let fired = on_first_recovery_scan(&backend, &recovery.journal, Interleave::Append);
    let listed = recovery.inspect_foreign().await;
    assert!(fired.load(Ordering::SeqCst), "live append never ran");
    assert!(listed.unwrap().is_empty());
}

/// Per-foreign origin verification must not pin this node's selected head.
#[tokio::test]
async fn inspect_foreign_head_survives_live_local_append_in_origin_check() {
    let backend = Arc::new(Backend::default());
    let (recovery, checkpoint, child) = foreign_parent_and_child(&backend).await;
    let fired = on_nth_head_read(
        &backend,
        &recovery.journal,
        child.operation_id,
        2,
        Interleave::Append,
    );
    let listed = recovery.inspect_foreign().await;
    assert!(fired.load(Ordering::SeqCst), "live append never ran");
    let listed: Vec<_> = listed
        .unwrap()
        .into_iter()
        .map(|inspection| (inspection.owner_node, inspection.event))
        .collect();
    assert_eq!(listed, vec![(9, checkpoint), (8, child)]);
}

/// A foreign tip whose selected ancestry reaches this node's own records (a
/// handover) is accepted against the live owner, not a stale replay head.
#[tokio::test]
async fn inspect_foreign_handover_ancestry_survives_live_local_append() {
    let backend = Arc::new(Backend::default());
    let old = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let recipient = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let initial = intent();
    old.persist(&initial).await.unwrap();
    let unknown = transition(&initial, RecoveryState::LandedUnknown);
    let verdict = transition(&unknown, RecoveryState::VerdictNotLanded);
    recipient
        .adopt_verdict_selection(&attestation(&initial), &[unknown, verdict.clone()])
        .await
        .unwrap();
    let foreign = heads(&old.store).await.unwrap();
    assert_eq!(foreign.len(), 1);
    assert_eq!(foreign[0].0, initial.operation_id);
    assert_eq!(foreign[0].1.node, 8);
    let fired = on_nth_head_read(
        &backend,
        &old.journal,
        initial.operation_id,
        2,
        Interleave::Append,
    );
    let listed = old.inspect_foreign().await;
    assert!(fired.load(Ordering::SeqCst), "live append never ran");
    let listed = listed.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].owner_node, 8);
    assert_eq!(listed[0].event, verdict);
}

/// Admission loss during a listing still refuses; the live head is never
/// taken as authority by itself.
#[tokio::test]
async fn inspect_foreign_refuses_after_cold_cutover_mid_scan() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let fired = on_first_recovery_scan(&backend, &recovery.journal, Interleave::Cutover);
    let listed = recovery.inspect_foreign().await;
    assert!(fired.load(Ordering::SeqCst), "cutover never ran");
    assert!(matches!(listed, Err(RecoveryError::Unavailable(_))));

    let backend = Arc::new(Backend::default());
    let (recovery, _, child) = foreign_parent_and_child(&backend).await;
    let fired = on_nth_head_read(
        &backend,
        &recovery.journal,
        child.operation_id,
        2,
        Interleave::Cutover,
    );
    let listed = recovery.inspect_foreign().await;
    assert!(fired.load(Ordering::SeqCst), "cutover never ran");
    assert!(matches!(listed, Err(RecoveryError::Unavailable(_))));
}
