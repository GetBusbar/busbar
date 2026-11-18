// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use crate::persistence::journal::StoreJournal;
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
    ephemeral: AtomicBool,
    after_read: Mutex<Option<ReadHook>>,
    read_hook: Mutex<Option<AsyncReadHook>>,
    scan_hook: Mutex<Option<ScanHook>>,
    state: Mutex<State>,
    lose_reply: AtomicBool,
    hang: AtomicBool,
    // Park (never forward) the next recovery-row selection candidate.
    park_selection: AtomicBool,
    clock_seconds: AtomicU64,
    /// One-shot: the next commit that puts this selected row is a definite
    /// ConditionConflict with no effect.
    conflict_selection: Mutex<Option<Address>>,
    /// One-shot: the next read that includes this address fails Unavailable.
    fail_read_of: Mutex<Option<Address>>,
    /// One-shot: just before the next multi-row recovery selection applies, fence writer
    /// `[1; 16]`: `true` advances the dataset root's writer epoch past it (its control row still
    /// admits it), `false` ends its control row's admission of execution epoch 3.
    fence_batch: Mutex<Option<bool>>,
    /// One-shot: the same fence, just before the next recovery selection of any width applies.
    fence_select: Mutex<Option<bool>>,
    /// One-shot: the next commit that puts this row finds another candidate's value already
    /// there (written first), and is a definite ConditionConflict with no effect.
    steal_selection: Mutex<Option<(Address, Secret<Vec<u8>>)>>,
}
/// The control row that fences writer `[1; 16]`: `true` moves the dataset root's writer epoch past
/// it (its control row still admits it), `false` ends its control row's admission of epoch 3.
fn fence_row(root: bool) -> (Vec<u8>, Vec<u8>) {
    if root {
        (
            control::DATASET_KEY.to_vec(),
            control::Dataset {
                id: DatasetId([1; 16]),
                writer_epoch: 3,
            }
            .encode()
            .unwrap()
            .to_vec(),
        )
    } else {
        (
            control::writer_key([1; 16]).to_vec(),
            control::Writer {
                retired_through: 2,
                admitted_through: 2,
            }
            .encode()
            .unwrap()
            .to_vec(),
        )
    }
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
            physical_version: busbar_contract::persistence::PHYSICAL_VERSION,
            durability: if self.ephemeral.load(Ordering::SeqCst) {
                Durability::Ephemeral
            } else {
                Durability::Local
            },
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        {
            let mut fail = self.fail_read_of.lock().unwrap();
            if fail
                .as_ref()
                .is_some_and(|at| request.addresses.contains(at))
            {
                fail.take();
                return Box::pin(async { Err(Failure::Unavailable) });
            }
        }
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
    fn commit(
        &self,
        prepared: PreparedCandidate,
        _key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.clone());
        Box::pin(async move {
            control::admit(&prepared)?;
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if selects_recovery_row(&prepared) && self.park_selection.swap(false, Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let candidate = prepared.candidate();
            if selects_recovery_row(&prepared) && candidate.mutations.len() > 1 {
                if let Some(root) = self.fence_batch.lock().unwrap().take() {
                    let (key, value) = fence_row(root);
                    state.rows.insert(control_address(key), Secret::new(value));
                }
            }
            if selects_recovery_row(&prepared) {
                if let Some(root) = self.fence_select.lock().unwrap().take() {
                    let (key, value) = fence_row(root);
                    state.rows.insert(control_address(key), Secret::new(value));
                }
            }
            {
                let mut steal = self.steal_selection.lock().unwrap();
                let stolen = steal.as_ref().is_some_and(|(target, _)| {
                    candidate.mutations.iter().any(
                        |mutation| matches!(mutation, Mutation::Put { address, .. } if address == target),
                    )
                });
                if stolen {
                    if let Some((target, value)) = steal.take() {
                        state.rows.insert(target, value);
                    }
                    return Ok(Decision::ConditionConflict);
                }
            }
            {
                let mut conflict = self.conflict_selection.lock().unwrap();
                let selects = conflict.as_ref().is_some_and(|target| {
                    candidate.mutations.iter().any(
                        |mutation| matches!(mutation, Mutation::Put { address, .. } if address == target),
                    )
                });
                if selects {
                    conflict.take();
                    // The racing selector (another driver of the same exact candidate) lands
                    // the selection row first, so the row has moved when this driver reads it.
                    for mutation in &candidate.mutations {
                        if let Mutation::Put { address, value } = mutation {
                            state.rows.insert(address.clone(), value.clone());
                        }
                    }
                    return Ok(Decision::ConditionConflict);
                }
            }
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
                return Ok(Decision::Fenced);
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
                    Mutation::DeleteRange {
                        namespace,
                        prefix,
                        exact_key_length,
                    } => {
                        assert_eq!(*namespace, control::SLOT_NS);
                        assert_eq!(*exact_key_length, 20);
                        let writer: [u8; 16] = prefix.as_slice().try_into().unwrap();
                        let State { receipts, sent, .. } = &mut *state;
                        receipts.retain(|operation, _| {
                            !sent.iter().any(|prepared| {
                                let id = prepared.candidate().id;
                                id.writer == writer && id.operation == *operation
                            })
                        });
                    }
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

/// Node `node`'s recovery after a restart of writer `writer`: a fresh store attachment and journal
/// owner, so nothing is carried and opening the journal replays every original of it cold
/// (SHUTDOWN-HANG F1 leaves this as the path that reads the whole own journal).
async fn restarted(
    backend: &Arc<Backend>,
    writer: u8,
    node: u64,
) -> Result<StoreRecovery, crate::persistence::journal::RuntimeError> {
    let journal = RuntimeJournal::open(
        Arc::new(attach(backend.clone(), writer).await),
        node,
        crate::persistence::journal::runtime::BufferBudget {
            records: 64,
            bytes: 1024 * 1024,
        },
    )
    .await?;
    Ok(StoreRecovery::new(journal, crate::teller::Kernel::new().durability_token()).unwrap())
}

async fn native_usage(backend: Arc<Backend>, applied_head: bool) -> (RecoveryEvent, RecoveryEvent) {
    use crate::governance::{exact_debt::ExactUsageDelta, GovState};
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
        crate::store::now_ms(),
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
            json::parse(&initial.payload).unwrap();
        let remainder = GovState::usage_recovery_child(
            "imported",
            0,
            ExactUsageDelta {
                requests: 7,
                billable_requests: 7,
                ..Default::default()
            },
            Default::default(),
            crate::store::now_ms(),
        )
        .unwrap()
        .unwrap();
        custody.plain = Default::default();
        custody.handoffs.push(remainder);
        let mut event = transition(&initial, RecoveryState::Applied);
        event.payload = json::to_vec(&custody).unwrap();
        source.persist(&event).await.unwrap();
        event
    } else {
        initial.clone()
    };
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
        backend
            .commit(
                delayed,
                busbar_contract::persistence::CommitKey::slotted(
                    65_535,
                    1,
                    &busbar_contract::caps::SlotSeal::acquire_for_tests()
                )
                .unwrap()
            )
            .await
            .unwrap(),
        Decision::Fenced
    ));
}

#[tokio::test]
async fn native_writer_retirement_adopts_current_intent_without_migration_or_duplicate_charge() {
    let backend = Arc::new(Backend::default());
    let (initial, _) = native_usage(backend.clone(), false).await;
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
async fn native_writer_retirement_resolves_exact_applied_receipt_without_reapplying_chunk() {
    use crate::governance::GovState;
    let backend = Arc::new(Backend::default());
    let (initial, _) = native_usage(backend.clone(), false).await;
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
async fn dev_import_disposition_row_is_refused_before_native_adoption() {
    let backend = Arc::new(Backend::default());
    let (initial, _) = native_usage(backend.clone(), false).await;
    backend.state.lock().unwrap().rows.insert(
        Address {
            namespace: *b"busbar.recimp1\0\0",
            key: initial.operation_id.to_vec(),
        },
        Secret::new(b"dev import disposition".to_vec()),
    );
    native_writer_lease(&backend, 1, 10_000);
    let target = sink(Arc::new(attach(backend, 2).await), 8).await;
    assert!(
        matches!(target.replay_selections().await, Err(RecoveryError::Invalid(message)) if message.contains("unreleased 1.6.0-dev"))
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

/// Node 7's journal holding the selected chain initial -> Applied -> Settled, then an unselected
/// LandedUnknown fork of `initial` appended by a raw journal writer beside the live owner.
async fn own_journal_with_an_outside_fork() -> (
    Arc<Backend>,
    StoreRecovery,
    [RecoveryEvent; 3],
    RecoveryEvent,
) {
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
    (backend, recovery, [initial, applied_event, settled], fork)
}

/// WHO: a node restarted over a journal that holds an unselected fork of a selected operation.
/// DOES: cold recovery (no carried evidence: opening the journal replays every original) selects
/// each operation's complete ancestry from its original frames, refuses the fork as a checkpoint,
/// and replays and lists only the selected chain.
/// WHY: SHUTDOWN-HANG F1 (6426a6a085, ceab41b955) confirms the live owner's own head in one read
/// and no longer walks its journal; the whole-journal read is the restart's, so this is where
/// complete ancestry and an ignored fork are owed.
#[tokio::test]
async fn original_frames_select_complete_ancestry_and_ignore_unselected_forks_on_cold_recovery() {
    let (backend, recovery, [initial, applied_event, settled], fork) =
        own_journal_with_an_outside_fork().await;
    drop(recovery);
    let cold = restarted(&backend, 1, 7).await.unwrap();
    assert!(cold.verify_checkpoint(&fork).await.is_err());
    assert_eq!(
        cold.replay().await.unwrap(),
        vec![initial.clone(), applied_event, settled.clone()]
    );
    assert_eq!(
        cold.replay_selections().await.unwrap(),
        vec![RecoverySelection {
            initial,
            selected: settled
        }]
    );
}

/// WHO: the live journal owner when something other than it appended to its own journal.
/// DOES: (SHUTDOWN-HANG F1) the owner confirms its head against its own verified head, so the
/// moved head is refused as `Authority` by replay and by the selection listing: never accepted
/// and never silently ignored. The fork is still no checkpoint.
/// WHY: the live path reads no original to tell a fork from a lost writer; only the owner appends,
/// so any other append means its custody is no longer exclusive.
#[tokio::test]
async fn an_outside_append_under_the_live_owner_is_refused_as_authority() {
    let (_backend, recovery, _, fork) = own_journal_with_an_outside_fork().await;
    assert!(recovery.verify_checkpoint(&fork).await.is_err());
    let replayed = recovery.replay().await.unwrap_err().to_string();
    assert!(replayed.contains("Authority"), "replay: {replayed}");
    let listed = recovery.replay_selections().await.unwrap_err().to_string();
    assert!(listed.contains("Authority"), "replay_selections: {listed}");
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
    let template = json::json!({"physical":[1,2,3]});
    let mut parent = intent();
    parent.operation_id = [6; 16];
    parent.payload = b"{\"handoffs\":[]}".to_vec();
    let mut checkpoint = transition(&parent, RecoveryState::Applied);
    checkpoint.payload=json::to_vec(&json::json!({"handoffs":[{"operation_id":child.operation_id,"kind":child.kind,"body_fingerprint":child.body_fingerprint,"first_sent_at_ms":child.first_sent_at_ms,"payload":json::to_vec(&template).unwrap()}]})).unwrap();
    let mut physical = template;
    physical["origin"] = json::json!({"operation_id":checkpoint.operation_id,"event_fingerprint":checkpoint.fingerprint().unwrap()});
    child.payload = json::to_vec(&physical).unwrap();
    recovery.persist(&parent).await.unwrap();
    recovery.persist(&checkpoint).await.unwrap();
    let mut changed = child.clone();
    physical["physical"] = json::json!([1, 2, 99]);
    changed.payload = json::to_vec(&physical).unwrap();
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
    let mut raw: json::Value = json::parse_value(&changed_origin.payload).unwrap();
    raw["origin"] = json::Value::new();
    changed_origin.payload = json::to_vec(&raw).unwrap();
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

#[path = "usage_origin_final_fold_tests.rs"]
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

/// The foreign final guard is unchanged: a foreign owner's append after the
/// proof still invalidates it, through the store-observed head predicates.
#[tokio::test]
async fn history_foreign_proof_is_invalidated_by_foreign_append() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let foreign = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    let mut first = intent();
    first.operation_id = [21; 16];
    foreign.persist(&first).await.unwrap();
    let mut history = History::new(&recovery.store);
    history.proof(8).await.unwrap();
    let mut second = intent();
    second.operation_id = [22; 16];
    foreign.persist(&second).await.unwrap();
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
            Secret::new(json::to_vec(&head).unwrap()),
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
                                json::parse(page.rows[0].1.expose(&crate::seal::lend())).unwrap();
                            match fault {
                                6 => head.version = 2,
                                7 => head.node = 0,
                                _ => head.sequence = 0,
                            }
                            page.rows[0].1 = Secret::new(json::to_vec(&head).unwrap());
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
    let template = json::json!({"physical":[1,2,3]});
    let mut parent = intent();
    parent.operation_id = [6; 16];
    parent.payload = b"{\"handoffs\":[]}".to_vec();
    let mut checkpoint = transition(&parent, RecoveryState::Applied);
    checkpoint.payload=json::to_vec(&json::json!({"handoffs":[{"operation_id":child.operation_id,"kind":child.kind,"body_fingerprint":child.body_fingerprint,"first_sent_at_ms":child.first_sent_at_ms,"payload":json::to_vec(&template).unwrap()}]})).unwrap();
    let mut physical = template;
    physical["origin"] = json::json!({"operation_id":checkpoint.operation_id,"event_fingerprint":checkpoint.fingerprint().unwrap()});
    child.payload = json::to_vec(&physical).unwrap();
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

/// The observing History confirms this node's proof as a prefix of the live
/// owner's admitted head; a plain History still pins the exact head.
#[tokio::test]
async fn observing_history_confirms_extended_local_head() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    recovery.persist(&intent()).await.unwrap();
    let mut observing = History::observing(&recovery.store, &recovery.journal);
    let mut pinned = History::new(&recovery.store);
    observing.proof(7).await.unwrap();
    pinned.proof(7).await.unwrap();
    live_append(&recovery.journal).await;
    observing.finish().await.unwrap();
    assert!(pinned.finish().await.is_err());
    set_root_epoch(&backend, 3);
    assert!(matches!(
        observing.finish().await,
        Err(RecoveryError::Unavailable(_))
    ));
}

/// Before answering any read of `journal`'s original frames, commit one more
/// live record through that owner, as request-path audits do throughout a
/// replay. Reads the hook's own append makes are answered plainly.
fn append_on_every_original_read(
    backend: &Arc<Backend>,
    journal: &Arc<RuntimeJournal>,
) -> Arc<AtomicU64> {
    let appended = Arc::new(AtomicU64::new(0));
    let busy = Arc::new(AtomicBool::new(false));
    let node = journal.node().to_be_bytes();
    let (owner, journal, count) = (backend.clone(), journal.clone(), appended.clone());
    *backend.read_hook.lock().unwrap() = Some(Arc::new(move |request: Arc<Read>| {
        let (backend, journal, count, busy) =
            (owner.clone(), journal.clone(), count.clone(), busy.clone());
        let original = request.addresses.iter().any(|at| {
            at.key.starts_with(b"busbar.journal4\0")
                && at.key.get(16..24) == Some(&node[..])
                && at.key.get(24) == Some(&b'R')
        });
        Box::pin(async move {
            if original && !busy.swap(true, Ordering::SeqCst) {
                live_append(&journal).await;
                count.fetch_add(1, Ordering::SeqCst);
                busy.store(false, Ordering::SeqCst);
            }
            Ok(backend.read_rows(&request))
        })
    }));
    appended
}

/// PERFPASS-F2 T2: every own-node head compare in a persist (the preflight
/// History, the owned proof and the post-selection verification) is
/// interleaved with a request-path append on this node's own journal. None
/// of them may lose to it.
#[tokio::test]
async fn actual_store_usage_recovery_persists_while_request_audits_append() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        live_append(&recovery.journal).await;
        let appended = append_on_every_original_read(&backend, &recovery.journal);
        let event = intent();
        let first = recovery.persist(&event).await;
        assert!(first.is_ok(), "persist lost to a local append: {first:?}");
        let selected: Vec<_> = recovery
            .replay_selections()
            .await
            .unwrap()
            .into_iter()
            .map(|selection| selection.selected)
            .collect();
        assert_eq!(selected, vec![event.clone()]);
        let again = recovery.persist(&event).await;
        assert!(again.is_ok(), "already-selected verify lost: {again:?}");
        assert!(appended.load(Ordering::SeqCst) > 0, "no append interleaved");
    })
    .await
    .expect("no hang");
}

/// PERFPASS-F2 T2b: the read paths keep one pin and confirm it against the
/// live owner, so local appends during their replays cannot refuse them.
#[tokio::test]
async fn actual_store_usage_recovery_reads_while_request_audits_append() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let event = intent();
        recovery.persist(&event).await.unwrap();
        let appended = append_on_every_original_read(&backend, &recovery.journal);
        let selections = recovery.replay_selections().await;
        assert!(selections.is_ok(), "{selections:?}");
        let events = recovery.replay().await;
        assert!(events.is_ok(), "{events:?}");
        assert_eq!(events.unwrap(), vec![event]);
        let foreign = recovery.inspect_foreign().await;
        assert!(foreign.is_ok(), "{foreign:?}");
        assert!(appended.load(Ordering::SeqCst) > 0, "no append interleaved");
    })
    .await
    .expect("no hang");
}

/// PERFPASS-F2 T2c: after a definite no-effect selection, a transient failure
/// of the post-verification keeps the pending work and is reported as what it
/// is; the next persist completes it.
#[tokio::test]
async fn definite_no_effect_with_transient_verify_keeps_pending() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let event = intent();
    let selected = address(&event.operation_id);
    *backend.conflict_selection.lock().unwrap() = Some(selected.clone());
    // The ConditionConflict reply arms one failing read of the selected row,
    // which the post-verification makes first.
    let (owner, armed) = (backend.clone(), Arc::new(AtomicBool::new(false)));
    let flag = armed.clone();
    *backend.after_read.lock().unwrap() = Some(Arc::new(move |_: &Backend, _: &Read| {
        if owner.conflict_selection.lock().unwrap().is_none() && !flag.swap(true, Ordering::SeqCst)
        {
            *owner.fail_read_of.lock().unwrap() = Some(selected.clone());
        }
    }));
    let first = recovery.persist(&event).await;
    assert!(armed.load(Ordering::SeqCst), "the conflict never happened");
    assert!(
        matches!(first, Err(RecoveryError::Unavailable(_))),
        "a transient verify failure must not discard the pending selection: {first:?}"
    );
    assert!(recovery
        .state
        .lock()
        .unwrap()
        .pending
        .contains_key(&event.operation_id));
    backend.after_read.lock().unwrap().take();
    recovery.persist(&event).await.unwrap();
    recovery.confirm_owned_checkpoint(&event).await.unwrap();
}

/// A candidate that puts or deletes a recovery selected-head row.
fn selects_recovery_row(prepared: &PreparedCandidate) -> bool {
    prepared
        .candidate()
        .mutations
        .iter()
        .any(|mutation| match mutation {
            Mutation::Put { address, .. } | Mutation::Delete(address) => {
                address.key.starts_with(&RECOVERY.0)
            }
            Mutation::DeleteRange { .. } => false,
        })
}

/// `(operation id, expected selected-head bytes)` of every recovery-row
/// selection the backend received, in order.
fn recovery_selections(backend: &Backend, node: u64) -> Vec<([u8; 16], Vec<u8>)> {
    let head = [b"busbar.journal4\0".as_slice(), &node.to_be_bytes(), b"H"].concat();
    backend
        .state
        .lock()
        .unwrap()
        .sent
        .iter()
        .filter(|prepared| selects_recovery_row(prepared))
        .map(|prepared| {
            let candidate = prepared.candidate();
            let expected = candidate
                .predicates
                .iter()
                .find(|predicate| {
                    predicate.address.key.len() == head.len() + 8
                        && predicate.address.key.starts_with(&head)
                })
                .map(|predicate| match &predicate.expected {
                    ExpectedValue::Absent => Vec::new(),
                    ExpectedValue::Exact(value) => value.expose(&crate::seal::lend()).clone(),
                })
                .expect("a recovery selection pins the selected journal head");
            (candidate.id.operation, expected)
        })
        .collect()
}

/// Drop a recovery `persist` while its selection candidate is parked in the
/// backend, so the native crossing is cancelled with no backend effect.
async fn cancel_parked_selection(
    backend: &Backend,
    recovery: &StoreRecovery,
    event: &RecoveryEvent,
) {
    backend.park_selection.store(true, Ordering::SeqCst);
    tokio::select! {
        result = recovery.persist(event) => panic!("the parked selection must not return: {result:?}"),
        _ = async {
            while recovery_selections(backend, 7).is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        } => {}
    }
    assert_eq!(recovery_selections(backend, 7).len(), 1);
}

/// WHO: the recovery owner re-driving a selection whose crossing was cancelled.
/// DOES: the proof it selects against is retained before any native claim, so
/// the re-drive presents the exact same attempt (same operation id, same head
/// predicate) even after another append moved the head. (SHUTDOWN-HANG 8.4(c),
/// owner ruling 2026-11-16 "Re-select, after authority check") That re-drive's
/// condition conflict is a definitive no-effect: with our authority intact, the
/// same staged original is re-selected once under current custody, and no second
/// Reconciliation original is staged.
/// WHY: re-proving against the moved head on the re-drive would change the claim
/// digest for the same operation id and wedge it as an operation conflict; never
/// re-selecting after a definitive no-effect left the operation retained for ever.
#[tokio::test]
async fn cancelled_recovery_selection_resumes_exact_attempt() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let event = intent();
        cancel_parked_selection(&backend, &recovery, &event).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            live_append(&recovery.journal),
        )
        .await
        .expect("a cancelled selection releases the journal's publication driver");
        let staged = recovery.journal.next_seq();
        let resolved = recovery.persist(&event).await;
        assert!(resolved.is_ok(), "{resolved:?}");
        let selections = recovery_selections(&backend, 7);
        assert_eq!(selections.len(), 3, "the re-drive, then one re-select");
        assert_eq!(
            selections[1], selections[0],
            "the re-drive presents the exact retained attempt"
        );
        assert_ne!(
            selections[2].1, selections[0].1,
            "the re-select pins the current head"
        );
        assert_eq!(
            recovery.journal.next_seq(),
            staged,
            "the same staged original is re-selected: no second Reconciliation original"
        );
        assert!(recovery.state.lock().unwrap().pending.is_empty());
        recovery.confirm_owned_checkpoint(&event).await.unwrap();
        recovery.persist(&event).await.unwrap();
        assert_eq!(
            recovery_selections(&backend, 7).len(),
            3,
            "a selected original is verified, never selected again"
        );
    })
    .await
    .expect("no hang");
}

/// WHO: the recovery owner re-driving a cancelled selection whose head did
/// not move. DOES: the exact retained attempt applies. WHY: a cancelled
/// selection that can still apply must apply, exactly once.
#[tokio::test]
async fn cancelled_recovery_selection_without_append_applies() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let event = intent();
        cancel_parked_selection(&backend, &recovery, &event).await;
        recovery.persist(&event).await.unwrap();
        let selections = recovery_selections(&backend, 7);
        assert_eq!(selections.len(), 2);
        assert_eq!(selections[1], selections[0]);
        assert!(recovery.state.lock().unwrap().pending.is_empty());
        recovery.confirm_owned_checkpoint(&event).await.unwrap();
    })
    .await
    .expect("no hang");
}

/// WHO: a recovery write or observation beside this node's live journal owner.
/// DOES: accepting the owner's head as an extension of an earlier proof reads
/// the originals appended after that proof; one later forked (a validly
/// resealed different original at the same sequence) or damaged in the Store
/// refuses, though the selected head, owner row and admission are unchanged.
/// WHY: a same-owner, no-later-sequence check alone would accept a rewritten
/// journal tail as this owner's history.
#[tokio::test]
async fn observing_history_refuses_a_forked_or_damaged_tail_after_its_proof() {
    for fork in [true, false] {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        recovery.persist(&intent()).await.unwrap();
        let mut observing = History::observing(&recovery.store, &recovery.journal);
        observing.proof(7).await.unwrap();
        live_append(&recovery.journal).await;
        {
            let mut state = backend.state.lock().unwrap();
            let (at, mut tail) = state
                .rows
                .iter()
                .filter_map(|(at, raw)| {
                    let record = JournalRecord::decode(raw.expose(&crate::seal::lend())).ok()?;
                    (record.node == 7).then(|| (at.clone(), record))
                })
                .max_by_key(|(_, record)| record.node_seq)
                .expect("appended tail original");
            let replaced = if fork {
                tail.body = b"a different original at the same sequence".to_vec();
                tail.body_hash = tail.digest_of_body();
                tail.hash = tail.digest_of_chain();
                tail.encode()
            } else {
                b"corrupt original".to_vec()
            };
            state.rows.insert(at, Secret::new(replaced));
        }
        assert!(
            observing.finish().await.is_err(),
            "a rewritten tail after the proof is not this owner's history (fork: {fork})"
        );
    }
}

/// A store whose per-call limit holds a whole recovery batch.
async fn attach_wide(backend: Arc<Backend>, writer: u8) -> CoreStore {
    CoreStore::attach(
        backend,
        WriterAuthority {
            writer_epoch: 2,
            writer: [writer; 16],
            execution_epoch: 3,
        },
        Limits {
            pending_operations: 32,
            conflict_retries: 1,
            scan_items: 64,
            scan_bytes: 1024 * 1024,
        },
    )
    .await
    .unwrap()
}

/// The Intent of operation `n`.
fn numbered_intent(n: u8) -> RecoveryEvent {
    RecoveryEvent {
        operation_id: [n; 16],
        ..intent()
    }
}

/// Appends of node `node`'s journal the backend received: candidates that put its head row.
fn journal_appends(backend: &Backend, node: u64) -> usize {
    let node = node.to_be_bytes();
    backend
        .state
        .lock()
        .unwrap()
        .sent
        .iter()
        .filter(|prepared| {
            prepared.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. }
                    if address.key.starts_with(b"busbar.journal4\0")
                        && address.key.get(16..24) == Some(&node[..])
                        && address.key.get(24) == Some(&b'H'))
            })
        })
        .count()
}

/// WHO: the settlement flusher keeping one recovery phase for several operations.
/// DOES: (SHUTDOWN-HANG F3.2, F1, 8.3) the batch is one append of its originals and one
/// selection CAS; each original's sequence and hash are carried from its append, so the next
/// revision of every member reads its own originals by that evidence with no journal replay,
/// whatever the journal length; `release` drops the evidence.
/// WHY: one append and one CAS per operation per state capped a drain at about one operation per
/// store round trip, and every own-node replay grew with uptime (SHUTDOWN-HANG 1.7).
#[tokio::test]
async fn a_recovery_batch_is_one_append_and_one_selection_and_carries_its_originals() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach_wide(backend.clone(), 1).await), 7).await;
    let events: Vec<RecoveryEvent> = (1..=8u8).map(numbered_intent).collect();
    let first = recovery.journal.next_seq();
    let appends = journal_appends(&backend, 7);
    for result in recovery.persist_batch(&events).await {
        result.unwrap();
    }
    assert_eq!(
        recovery_selections(&backend, 7).len(),
        1,
        "one selection CAS for the whole batch"
    );
    assert_eq!(
        journal_appends(&backend, 7) - appends,
        1,
        "one append for the batch's originals"
    );
    for (at, event) in events.iter().enumerate() {
        let tip = head(&recovery.store, &event.operation_id)
            .await
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(tip.sequence, first + at as u64);
        assert!(
            recovery.carried(tip.sequence).is_some(),
            "the append confirmation carries each original"
        );
    }
    for _ in 0..20 {
        live_append(&recovery.journal).await;
    }
    let applied: Vec<RecoveryEvent> = events
        .iter()
        .map(|event| transition(event, RecoveryState::Applied))
        .collect();
    let replays = crate::persistence::journal::replays_on_this_thread();
    for result in recovery.persist_batch(&applied).await {
        result.unwrap();
    }
    assert_eq!(
        crate::persistence::journal::replays_on_this_thread(),
        replays,
        "no journal replay on the live path"
    );
    assert_eq!(recovery_selections(&backend, 7).len(), 2);
    for event in &applied {
        recovery.confirm_owned_checkpoint(event).await.unwrap();
    }
    recovery.release(events[0].operation_id);
    assert!(
        recovery.carried(first).is_none(),
        "release drops the operation's evidence"
    );
    assert!(recovery.carried(first + 1).is_some());
}

/// SHUTDOWN-HANG F1: shared ancestry remains carried until its last unsettled owner releases it.
/// Re-observing the same chain for one operation must not create an extra ownership reference.
#[tokio::test]
async fn shared_carried_evidence_survives_until_the_last_operation_releases() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend, 1).await), 7).await;
    let evidence = Carried {
        seq: 1,
        hash: [9; 32],
    };
    recovery.carry([1; 16], Some(evidence));
    recovery.carry([1; 16], Some(evidence));
    recovery.carry([2; 16], Some(evidence));
    recovery.carry(
        [1; 16],
        Some(Carried {
            seq: 2,
            hash: [8; 32],
        }),
    );
    recovery.release([1; 16]);
    assert!(recovery.carried(2).is_none());
    assert_eq!(
        recovery.carried(1).map(|value| value.hash),
        Some(evidence.hash)
    );
    recovery.release([1; 16]);
    assert_eq!(
        recovery.carried(1).map(|value| value.hash),
        Some(evidence.hash)
    );
    recovery.release([2; 16]);
    assert!(recovery.carried(1).is_none());
    assert!(recovery.state.lock().unwrap().carried_by_op.is_empty());
}

/// SF-6 test 30(c): release the last operation's pin so settled usage cannot stop cuts forever.
#[tokio::test]
async fn recovery_original_is_pinned_until_its_last_operation_releases() {
    use crate::persistence::journal::{CutProgress, CUT_BATCH, RETAIN_TAIL};
    let backend = Arc::new(Backend::default());
    backend.ephemeral.store(true, Ordering::SeqCst);
    let recovery = sink(Arc::new(attach(backend, 1).await), 7).await;
    let journal = recovery.journal.clone();
    let run = journal
        .stage_run(&[Entry::new(RecordClass::Reconciliation, vec![1])])
        .unwrap();
    journal.confirm(&run).await.unwrap();
    let evidence = run.carried().next().unwrap();
    recovery.carry([1; 16], Some(evidence));
    recovery.carry([2; 16], Some(evidence));
    drop(run);
    for _ in 0..(2 * RETAIN_TAIL + CUT_BATCH) {
        let run = journal
            .stage_run(&[Entry::new(RecordClass::Transaction, vec![2])])
            .unwrap();
        journal.confirm(&run).await.unwrap();
    }
    let mut cut = journal.cutter().unwrap();
    assert_eq!(cut.truncate_through(u64::MAX).await, CutProgress::Idle);
    recovery.release([1; 16]);
    assert_eq!(cut.truncate_through(u64::MAX).await, CutProgress::Idle);
    assert_eq!(
        journal.record(evidence).await.unwrap().node_seq,
        evidence.seq
    );
    assert_eq!(journal.locate_truncated(), 0);
    recovery.release([2; 16]);
    assert!(
        matches!(
            cut.truncate_through(u64::MAX).await,
            CutProgress::Cut { .. }
        ),
        "the last release must not retain a process-lifetime pin"
    );
}

/// SF-6 test 30(d): a recovery proof restarts when a cut lands after its base snapshot.
#[tokio::test]
async fn recovery_history_restarts_from_the_cut_base() {
    use crate::persistence::journal::{journal_walk_restarts, CUT_BATCH, RETAIN_TAIL};
    let backend = Arc::new(Backend::default());
    backend.ephemeral.store(true, Ordering::SeqCst);
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let journal = recovery.journal.clone();
    for _ in 0..(RETAIN_TAIL + 3 * CUT_BATCH) {
        let run = journal
            .stage_run(&[Entry::new(RecordClass::Transaction, vec![2])])
            .unwrap();
        journal.confirm(&run).await.unwrap();
    }
    let before = backend.state.lock().unwrap().rows.clone();
    journal.cutter().unwrap().truncate_through(u64::MAX).await;
    let after = Mutex::new(Some(backend.state.lock().unwrap().rows.clone()));
    let mut fresh = History::observing(&recovery.store, &journal);
    let expected = fresh.proof(journal.node()).await.unwrap();
    backend.state.lock().unwrap().rows = before;
    *backend.after_read.lock().unwrap() = Some(Arc::new(move |backend, read| {
        if read
            .addresses
            .iter()
            .any(|address| address.key.get(24) == Some(&b'B'))
        {
            if let Some(rows) = after.lock().unwrap().take() {
                backend.state.lock().unwrap().rows = rows;
            }
        }
    }));
    let restarts = journal_walk_restarts();
    let mut racing = History::observing(&recovery.store, &journal);
    let actual = racing.proof(journal.node()).await.unwrap();
    assert!(actual.same_head(&expected));
    assert_eq!(actual.records_seal(), expected.records_seal());
    assert!(
        journal_walk_restarts() > restarts,
        "recovery uses the shared journal restart accounting"
    );
    *backend.after_read.lock().unwrap() = None;
}

/// WHO: a metering flush driving one operation while the settlement flusher's recovery batch
/// that holds it is in doubt (its select crossed and its reply was lost).
/// DOES: (SHUTDOWN-HANG F3.2, 8.4(g)) the single driver gets `Unavailable` and stages nothing;
/// the next pass resolves the batch with exactly its membership, and each operation is selected
/// once, with one Reconciliation original per (operation, revision).
/// WHY: a second staged original for the same revision is a fork the adopter cannot tell apart.
#[tokio::test]
async fn an_in_doubt_recovery_batch_owns_its_members() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach_wide(backend.clone(), 1).await), 7).await;
        let events: Vec<RecoveryEvent> = (1..=3u8).map(numbered_intent).collect();
        backend.park_selection.store(true, Ordering::SeqCst);
        tokio::select! {
            result = recovery.persist_batch(&events) => {
                panic!("the parked selection must not return: {result:?}")
            }
            _ = async {
                while recovery_selections(&backend, 7).is_empty() {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            } => {}
        }
        let staged = recovery.journal.next_seq();
        let refused = recovery.persist(&events[1]).await.unwrap_err().to_string();
        assert!(refused.contains("unresolved batch"), "{refused}");
        assert_eq!(
            recovery.journal.next_seq(),
            staged,
            "nothing is staged twice"
        );
        assert_eq!(
            recovery_selections(&backend, 7).len(),
            1,
            "the member is never selected alone"
        );
        for result in recovery.persist_batch(&events).await {
            result.unwrap();
        }
        let selections = recovery_selections(&backend, 7);
        assert_eq!(selections.len(), 2);
        assert_eq!(
            selections[1], selections[0],
            "the batch is resolved with exactly its membership"
        );
        assert_eq!(
            recovery.journal.next_seq(),
            staged,
            "one Reconciliation original per (operation, revision)"
        );
        for event in &events {
            recovery.confirm_owned_checkpoint(event).await.unwrap();
        }
    })
    .await
    .expect("no hang");
}

/// WHO: the settlement flusher's recovery batch when this writer was fenced before its select:
/// its control row no longer admits our execution epoch, or the dataset root's writer epoch has
/// moved past ours while the control row still admits us.
/// DOES: (SHUTDOWN-HANG F3.2 step 4, 8.4(h1), 8.4(h2)) the whole-batch no-effect is checked
/// against our authority in one read and every member answers `Authority`; nothing is
/// re-selected, the batch is not halved, and its members stay owned by it (nothing re-staged).
/// WHY: a fenced send and a size refusal answer alike; treating a fence as a size refusal
/// re-selected every member under lost authority.
#[tokio::test]
async fn a_fenced_writer_fails_a_recovery_batch_as_authority() {
    for root in [false, true] {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach_wide(backend.clone(), 1).await), 7).await;
        let events: Vec<RecoveryEvent> = (1..=3u8).map(numbered_intent).collect();
        *backend.fence_batch.lock().unwrap() = Some(root);
        for result in recovery.persist_batch(&events).await {
            let why = result.unwrap_err().to_string();
            assert!(why.contains("Authority"), "root moved {root}: {why}");
        }
        assert_eq!(
            recovery_selections(&backend, 7).len(),
            1,
            "root moved {root}: never re-selected, never halved"
        );
        let staged = recovery.journal.next_seq();
        let held = recovery.persist(&events[0]).await.unwrap_err().to_string();
        assert!(
            held.contains("unresolved batch"),
            "root moved {root}: {held}"
        );
        assert_eq!(recovery.journal.next_seq(), staged, "root moved {root}");
    }
}

/// WHO: recovery custody when one of its own Reconciliation originals was rewritten in the store
/// with a self-consistent frame (same sequence, valid hash, H untouched).
/// DOES: (SHUTDOWN-HANG F1, 8.5b) the next revision's persist refuses with the carried-evidence
/// mismatch and selects nothing.
/// WHY: without the carried hash, a rewritten own original below the last proof passed as
/// history, and the next replay only failed after the ledger had applied it.
#[tokio::test]
async fn a_rewritten_recovery_original_is_refused_against_carried_evidence() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let event = intent();
    recovery.persist(&event).await.unwrap();
    let seq = head(&recovery.store, &event.operation_id)
        .await
        .unwrap()
        .unwrap()
        .0
        .sequence;
    {
        let mut state = backend.state.lock().unwrap();
        let (at, mut record) = state
            .rows
            .iter()
            .find_map(|(at, raw)| {
                let record = JournalRecord::decode(raw.expose(&crate::seal::lend())).ok()?;
                (record.node == 7 && record.node_seq == seq).then(|| (at.clone(), record))
            })
            .expect("the selected original");
        record.wall += 1;
        record.hash = record.digest_of_chain();
        state.rows.insert(at, Secret::new(record.encode()));
    }
    let refused = recovery
        .persist(&transition(&event, RecoveryState::Applied))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("carried"), "{refused}");
    assert_eq!(
        head(&recovery.store, &event.operation_id)
            .await
            .unwrap()
            .unwrap()
            .0
            .sequence,
        seq,
        "nothing is selected over the rewritten original"
    );
}

/// WHO: the settlement flusher keeping recovery phases while four request-path writers keep
/// appending to the same node journal.
/// DOES: (SHUTDOWN-HANG 8.1, at the recovery sink) every batch selects on its first pass, with no
/// `Authority`, condition conflict or lost selection, and confirmations almost never fall back to
/// the publication driver.
/// WHY: proofs replayed outside the append lane lost every CAS an interleaved own append made
/// stale, and the misreported `Authority` stalled settlement under load.
#[tokio::test]
async fn recovery_batches_drain_during_concurrent_appends() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach_wide(backend.clone(), 1).await), 7).await;
        live_append(&recovery.journal).await;
        let stop = Arc::new(AtomicBool::new(false));
        let mut appenders = Vec::new();
        for _ in 0..4 {
            let (journal, stop) = (recovery.journal.clone(), stop.clone());
            appenders.push(tokio::spawn(async move {
                while !stop.load(Ordering::SeqCst) {
                    live_append(&journal).await;
                    tokio::task::yield_now().await;
                }
            }));
        }
        for round in 0..10u8 {
            let events: Vec<RecoveryEvent> =
                (1..=8u8).map(|n| numbered_intent(round * 8 + n)).collect();
            for result in recovery.persist_batch(&events).await {
                result.unwrap();
            }
            let applied: Vec<RecoveryEvent> = events
                .iter()
                .map(|event| transition(event, RecoveryState::Applied))
                .collect();
            for result in recovery.persist_batch(&applied).await {
                result.unwrap();
            }
            tokio::task::yield_now().await;
        }
        stop.store(true, Ordering::SeqCst);
        for appender in appenders {
            appender.await.unwrap();
        }
        assert_eq!(
            recovery_selections(&backend, 7).len(),
            20,
            "every batch selected on its first pass"
        );
        let fallbacks = recovery.journal.lane_fallbacks();
        assert!(
            fallbacks <= 10,
            "{fallbacks} confirmations fell back to the driver"
        );
    })
    .await
    .expect("no hang");
}

/// Selection candidates the backend received that put `operation`'s selected-head row.
fn selections_of(backend: &Backend, operation: &[u8; 16]) -> usize {
    let row = address(operation);
    backend
        .state
        .lock()
        .unwrap()
        .sent
        .iter()
        .filter(|prepared| {
            prepared.candidate().mutations.iter().any(
                |mutation| matches!(mutation, Mutation::Put { address, .. } if *address == row),
            )
        })
        .count()
}

/// Fence writer `[1; 16]` now (see [`fence_row`]).
fn fence_writer(backend: &Backend, root: bool) {
    let (key, value) = fence_row(root);
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(control_address(key), Secret::new(value));
}

/// WHO: the settlement flusher re-driving a recovery batch whose select crossed and was
/// cancelled, after another append moved the node's head.
/// DOES: (SHUTDOWN-HANG 8.4(c), F3.2, owner ruling 2026-11-16 "Re-select, after authority
/// check") the re-drive presents the exact retained attempt; its condition conflict is a
/// definitive no-effect, so with our authority intact every member's staged original is
/// re-selected once, whole, against the current head. No second Reconciliation original.
/// WHY: a batch that is never re-selected after a definitive no-effect retains its members for
/// ever, and the single drivers they block (metering, raw recovery) can never stage them either.
#[tokio::test]
async fn an_in_doubt_recovery_batch_replayed_after_the_head_moved_is_reselected_whole() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach_wide(backend.clone(), 1).await), 7).await;
        let events: Vec<RecoveryEvent> = (1..=3u8).map(numbered_intent).collect();
        backend.park_selection.store(true, Ordering::SeqCst);
        tokio::select! {
            result = recovery.persist_batch(&events) => {
                panic!("the parked selection must not return: {result:?}")
            }
            _ = async {
                while recovery_selections(&backend, 7).is_empty() {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            } => {}
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            live_append(&recovery.journal),
        )
        .await
        .expect("a cancelled selection releases the journal's publication driver");
        let staged = recovery.journal.next_seq();
        for result in recovery.persist_batch(&events).await {
            assert!(result.is_ok(), "{result:?}");
        }
        let selections = recovery_selections(&backend, 7);
        assert_eq!(
            selections.len(),
            3,
            "the re-drive, then one whole re-select"
        );
        assert_eq!(
            selections[1], selections[0],
            "the batch is re-driven with exactly its retained attempt"
        );
        assert_ne!(
            selections[2].1, selections[0].1,
            "the re-select pins the current head"
        );
        assert_eq!(
            recovery.journal.next_seq(),
            staged,
            "one Reconciliation original per (operation, revision)"
        );
        for event in &events {
            recovery.confirm_owned_checkpoint(event).await.unwrap();
        }
    })
    .await
    .expect("no hang");
}

/// WHO: the recovery owner re-driving a cancelled selection after this writer was fenced.
/// DOES: (SHUTDOWN-HANG 8.4(c), F2.1(1), owner ruling 2026-11-16) the store answers the in-doubt
/// re-drive fenced; our authority is read first and is lost, so it answers `Authority`, keeps
/// the staged original for the successor, and every later drive repeats only the authority read:
/// the attempt is never resubmitted and nothing is re-staged.
/// WHY: a fenced writer re-selecting, or resubmitting, under lost authority races the successor
/// that adopts the operation.
#[tokio::test]
async fn an_in_doubt_recovery_selection_under_lost_authority_is_never_resubmitted() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let event = intent();
        cancel_parked_selection(&backend, &recovery, &event).await;
        fence_writer(&backend, false);
        let staged = recovery.journal.next_seq();
        for attempt in 0..2 {
            let lost = recovery.persist(&event).await.unwrap_err().to_string();
            assert!(lost.contains("Authority"), "attempt {attempt}: {lost}");
        }
        assert_eq!(
            recovery_selections(&backend, 7).len(),
            2,
            "the in-doubt attempt is re-driven once, then never resubmitted"
        );
        assert_eq!(recovery.journal.next_seq(), staged, "nothing is re-staged");
        assert!(recovery
            .state
            .lock()
            .unwrap()
            .pending
            .contains_key(&event.operation_id));
    })
    .await
    .expect("no hang");
}

/// WHO: the recovery owner selecting one operation when this writer was fenced just before the
/// select (never in doubt): its control row no longer admits our execution epoch, or the dataset
/// root's writer epoch moved past ours.
/// DOES: (SHUTDOWN-HANG F2.1(1), F3.2 step 4 for a batch of one, owner ruling 2026-11-16) the
/// no-effect is checked against our authority first, in one read, and answers `Authority`; the
/// next drive repeats only that read, so the candidate is never resubmitted and its staged
/// original is kept.
/// WHY: a fenced send and a size refusal answer alike; a refusal read as benign resubmitted the
/// candidate under lost authority on every tick.
#[tokio::test]
async fn a_fenced_writer_fails_a_single_recovery_selection_as_authority() {
    for root in [false, true] {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let event = intent();
        *backend.fence_select.lock().unwrap() = Some(root);
        let lost = recovery.persist(&event).await.unwrap_err().to_string();
        assert!(lost.contains("Authority"), "root moved {root}: {lost}");
        let staged = recovery.journal.next_seq();
        let again = recovery.persist(&event).await.unwrap_err().to_string();
        assert!(again.contains("Authority"), "root moved {root}: {again}");
        assert_eq!(
            recovery_selections(&backend, 7).len(),
            1,
            "root moved {root}: never resubmitted"
        );
        assert_eq!(recovery.journal.next_seq(), staged, "root moved {root}");
        assert!(
            recovery
                .state
                .lock()
                .unwrap()
                .pending
                .contains_key(&event.operation_id),
            "root moved {root}: the staged original is kept"
        );
    }
}

/// WHO: the recovery owner whose selection lost to another candidate on the same row.
/// DOES: (SHUTDOWN-HANG F2.1(2), 8.4(b)) the definite conflict is classified by one read of the
/// selection row: neither our head nor our predecessor, so another candidate won; the entry is
/// discarded and nothing is re-selected, whether the winner is another node's candidate or one
/// this node's evidence cannot vouch for.
/// WHY: proving the winner's ancestry as if it were ours turned a lost selection into an
/// unrelated read error and kept a candidate that can never apply.
#[tokio::test]
async fn a_selection_won_by_another_candidate_is_discarded() {
    for foreign in [true, false] {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let event = intent();
        let winner = Head {
            version: 1,
            node: if foreign { 8 } else { 7 },
            sequence: 999,
            revision: 0,
            event_digest: [7; 32],
        };
        *backend.steal_selection.lock().unwrap() = Some((
            address(&event.operation_id),
            Secret::new(busbar_contract::json::to_vec(&winner).unwrap()),
        ));
        let lost = recovery.persist(&event).await.unwrap_err();
        assert!(
            matches!(&lost, RecoveryError::Conflict(why) if why.contains("another recovery candidate won selection")),
            "foreign {foreign}: {lost:?}"
        );
        assert!(
            !recovery
                .state
                .lock()
                .unwrap()
                .pending
                .contains_key(&event.operation_id),
            "foreign {foreign}: the entry is discarded"
        );
        assert_eq!(
            selections_of(&backend, &event.operation_id),
            1,
            "foreign {foreign}: never re-selected"
        );
    }
}

/// WHO: recovery custody after another writer took this node's journal owner row.
/// DOES: (SHUTDOWN-HANG 8.4(a)) the next persist's lane-free custody read sees O changed and
/// answers `Authority`; nothing is selected.
/// WHY: a changed owner is lost authority, never a conflict to retry or a corruption to report.
#[tokio::test]
async fn a_changed_journal_owner_is_authority() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let event = intent();
    recovery.persist(&event).await.unwrap();
    {
        let owner = [
            b"busbar.journal4\0".as_slice(),
            &7u64.to_be_bytes(),
            b"O",
            &0u64.to_be_bytes(),
        ]
        .concat();
        let mut state = backend.state.lock().unwrap();
        let (at, value) = state
            .rows
            .iter()
            .find(|(at, _)| at.key == owner)
            .map(|(at, value)| (at.clone(), value.expose(&crate::seal::lend()).clone()))
            .expect("the journal owner row");
        let mut other = value;
        let last = other.len() - 1;
        other[last] ^= 0xff;
        state.rows.insert(at, Secret::new(other));
    }
    let next = transition(&event, RecoveryState::Applied);
    let lost = recovery.persist(&next).await.unwrap_err();
    assert!(
        matches!(&lost, RecoveryError::Unavailable(why) if why.contains("Authority")),
        "{lost:?}"
    );
    assert_eq!(
        selections_of(&backend, &event.operation_id),
        1,
        "nothing is selected under another owner"
    );
}

/// WHO: recovery custody when its own append's reply is lost once (the store applied it).
/// DOES: (SHUTDOWN-HANG 8.4(e)) the persist answers unresolved custody, never `Authority`; the
/// next persist reuses the same staged original and selects it.
/// WHY: an in-doubt own append is this owner's pending work, not lost authority.
#[tokio::test]
async fn an_uncertain_own_append_is_pending_never_authority() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let event = intent();
    let before = recovery.journal.next_seq();
    backend.lose_reply.store(true, Ordering::SeqCst);
    let first = recovery.persist(&event).await.unwrap_err();
    assert!(
        matches!(&first, RecoveryError::Unavailable(why) if !why.contains("Authority")),
        "{first:?}"
    );
    recovery.persist(&event).await.unwrap();
    assert_eq!(
        recovery.journal.next_seq(),
        before + 1,
        "one Reconciliation original"
    );
    recovery.confirm_owned_checkpoint(&event).await.unwrap();
}

/// Parent `[6; 16]`'s Intent, its Applied checkpoint with one handoff, and child `[9; 16]`, whose
/// origin is that checkpoint.
fn origin_family() -> (RecoveryEvent, RecoveryEvent, RecoveryEvent) {
    let mut child = intent();
    child.operation_id = [9; 16];
    child.body_fingerprint = [8; 32];
    let template = busbar_contract::json::json!({"physical":[1,2,3]});
    let mut parent = intent();
    parent.operation_id = [6; 16];
    parent.payload = b"{\"handoffs\":[]}".to_vec();
    let mut checkpoint = transition(&parent, RecoveryState::Applied);
    checkpoint.payload =
        busbar_contract::json::to_vec(&busbar_contract::json::json!({"handoffs":[{
            "operation_id": child.operation_id,
            "kind": child.kind,
            "body_fingerprint": child.body_fingerprint,
            "first_sent_at_ms": child.first_sent_at_ms,
            "payload": busbar_contract::json::to_vec(&template).unwrap()
        }]}))
        .unwrap();
    let mut physical = template;
    physical["origin"] = busbar_contract::json::json!({
        "operation_id": checkpoint.operation_id,
        "event_fingerprint": checkpoint.fingerprint().unwrap()
    });
    child.payload = busbar_contract::json::to_vec(&physical).unwrap();
    (parent, checkpoint, child)
}

/// Once `child`'s selection was sent, answer the next read of `parent`'s selection row as it
/// is, then put `older` there: a later read of the same verification sees the parent moved.
fn move_parent_after_child_selects(
    backend: &Arc<Backend>,
    child: [u8; 16],
    parent: [u8; 16],
    older: Secret<Vec<u8>>,
) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let (child_row, parent_row) = (address(&child), address(&parent));
    let (owner, done) = (backend.clone(), fired.clone());
    *backend.read_hook.lock().unwrap() = Some(Arc::new(move |request: Arc<Read>| {
        let (backend, done) = (owner.clone(), done.clone());
        let selected = backend.state.lock().unwrap().sent.iter().any(|prepared| {
            prepared.candidate().mutations.iter().any(
                |mutation| matches!(mutation, Mutation::Put { address, .. } if *address == child_row),
            )
        });
        let trigger = selected && request.addresses.contains(&parent_row);
        if trigger {
            backend.read_hook.lock().unwrap().take();
        }
        let (parent_row, older) = (parent_row.clone(), older.clone());
        Box::pin(async move {
            let answer = backend.read_rows(&request);
            if trigger {
                backend.state.lock().unwrap().rows.insert(parent_row, older);
                done.store(true, Ordering::SeqCst);
            }
            Ok(answer)
        })
    }));
    fired
}

/// WHO: recovery custody selecting a child whose origin parent moves after the child's
/// pre-check, on this node (`foreign == false`) or on another node.
/// DOES: (SHUTDOWN-HANG F2.1(3), 8.4(d), 8.4(f)) the CAS carries no guard on the parent, so the
/// select applies; the kept post-write verification re-reads the parent and answers `Conflict`,
/// and the child is never re-selected.
/// WHY: re-selecting on a moved origin would hide that the child's authorization changed.
#[tokio::test]
async fn an_origin_parent_moved_after_the_pre_check_fails_the_post_write_verification() {
    for foreign in [false, true] {
        let backend = Arc::new(Backend::default());
        let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
        let parent_owner = if foreign {
            Some(sink(Arc::new(attach(backend.clone(), 3).await), 9).await)
        } else {
            None
        };
        let origin = parent_owner.as_ref().unwrap_or(&recovery);
        let (parent, checkpoint, child) = origin_family();
        origin.persist(&parent).await.unwrap();
        let older = backend
            .state
            .lock()
            .unwrap()
            .rows
            .get(&address(&parent.operation_id))
            .cloned()
            .expect("the parent's Intent is selected");
        origin.persist(&checkpoint).await.unwrap();
        let fired = move_parent_after_child_selects(
            &backend,
            child.operation_id,
            parent.operation_id,
            older,
        );
        let refused = recovery.persist(&child).await.unwrap_err();
        assert!(
            fired.load(Ordering::SeqCst),
            "foreign {foreign}: the parent never moved"
        );
        assert!(
            matches!(&refused, RecoveryError::Conflict(_)),
            "foreign {foreign}: {refused:?}"
        );
        assert_eq!(
            selections_of(&backend, &child.operation_id),
            1,
            "foreign {foreign}: no re-select"
        );
    }
}

/// WHO: recovery code holding this node's journal owner.
/// DOES: (SHUTDOWN-HANG F1, R15) the read-only foreign view refuses this node; another node's
/// journal is proved through it, and that proof's predicates hold until the other node appends.
/// WHY: an own-node proof taken outside custody goes stale under the next request-path append,
/// which is the misreported `Authority` R15 removes by construction.
#[tokio::test]
async fn the_foreign_view_refuses_this_node() {
    let backend = Arc::new(Backend::default());
    let recovery = sink(Arc::new(attach(backend.clone(), 1).await), 7).await;
    let other = sink(Arc::new(attach(backend.clone(), 2).await), 8).await;
    other.persist(&intent()).await.unwrap();
    assert!(matches!(
        recovery.journal.foreign(7),
        Err(RuntimeError::Authority)
    ));
    let view = recovery.journal.foreign(8).unwrap();
    let mut replay = view.proof().await.unwrap();
    while replay.next().await.unwrap().is_some() {}
    let proof = replay.finish().unwrap();
    check(&recovery.store, view.predicates(&proof).unwrap())
        .await
        .unwrap();
    let mut next = intent();
    next.operation_id = [2; 16];
    other.persist(&next).await.unwrap();
    assert!(check(&recovery.store, view.predicates(&proof).unwrap())
        .await
        .is_err());
}
