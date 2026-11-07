// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{
    Address, AttemptId, Candidate, Decision, ExpectedValue, Mutation, PersistenceBackend,
    Predicate, PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
};
use busbar_contract::{Count, Secret};
use busbar_kernel::governance::recovery::{
    RecoveryError, RecoveryEvent, RecoveryResolution, RecoverySink, RecoveryState, RecoveryVerdict,
};
use busbar_kernel::governance::unit_checkpoint::UnitTarget;
use busbar_kernel::governance::unit_checkpoint_store::UnitCheckpointEvidence;
use busbar_kernel::governance::GovState;
use busbar_kernel::persistence::{
    facade::{CoreStore, Limits as CoreLimits},
    journal::runtime::{BufferBudget, RuntimeJournal},
    startup::{Progress, Startup},
};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};

/// Actual product plugin/native storage, with governor restart under ONE already
/// admitted CoreStore. This does not claim cold writer-handover qualification.
struct ActualStore {
    path: std::path::PathBuf,
    core: OnceLock<Arc<CoreStore>>,
    backend: OnceLock<Arc<crate::root::loader::store_v4::LoadedPersistence>>,
}
impl ActualStore {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-unit-checkpoint-{}",
            hex::encode(busbar_kernel::door::op_id().0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self {
            path,
            core: OnceLock::new(),
            backend: OnceLock::new(),
        }
    }
    async fn open(&self) -> Arc<CoreStore> {
        if let Some(core) = self.core.get() {
            return core.clone();
        }
        use crate::root::loader::dispatch::{
            kinds::store_v4::StoreV4, load_dropped, rendering_of_library, Bind, ConnTable,
            DispatchConfig, Dispatcher, NoSink,
        };
        use crate::root::loader::store_v4::{Limits, LoadedPersistence};
        let path = crate::root::test_plugins::application_store_library();
        let stated = rendering_of_library(&path).unwrap().unwrap();
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load_dropped::<StoreV4>(
            &path,
            &stated,
            Bind {
                instance: format!("checkpoint-{}", hex::encode(busbar_kernel::door::op_id().0))
                    .into(),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        let settings=serde_json::to_vec(&serde_json::json!({"db_path":self.path.join("application.sqlite"),"input_budget_bytes":16*1024*1024})).unwrap();
        let backend = Arc::new(
            LoadedPersistence::open(
                plugin,
                dispatcher,
                &settings,
                Limits {
                    descriptor_bytes: 16 * 1024 * 1024,
                    output_items: 1024,
                    output_bytes: 16 * 1024 * 1024,
                    decode_bytes: 16 * 1024 * 1024,
                },
            )
            .await
            .unwrap(),
        );
        let mut startup = Startup::new(
            backend.clone(),
            CoreLimits {
                pending_operations: 128,
                conflict_retries: 4,
                scan_items: 256,
                scan_bytes: 16 * 1024 * 1024,
            },
            true,
        )
        .unwrap();
        for _ in 0..8 {
            if startup.advance().await.unwrap() == Progress::Admitted {
                break;
            }
        }
        let core = startup.store().expect("native startup admitted");
        assert!(self.backend.set(backend).is_ok());
        assert!(self.core.set(core.clone()).is_ok());
        core
    }
}
impl Drop for ActualStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
struct TestBook {
    book: Arc<Mutex<Durability>>,
    journal: Arc<RuntimeJournal>,
    evidence: Arc<UnitCheckpointEvidence>,
    sink: Arc<dyn UnitCheckpointSink>,
}
impl std::ops::Deref for TestBook {
    type Target = Arc<Mutex<Durability>>;
    fn deref(&self) -> &Self::Target {
        &self.book
    }
}
async fn opened(core: Arc<CoreStore>, host: &str) -> TestBook {
    let digest = busbar_contract::abi::sdk::digest::sha256(host.as_bytes());
    let node = u64::from_le_bytes(digest[..8].try_into().unwrap()).max(1);
    let journal = RuntimeJournal::open(
        core.clone(),
        node,
        BufferBudget {
            records: 4096,
            bytes: 16 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    let mut book = super::super::build_on_store(
        &super::super::DurabilityConfig { data_dir: None },
        node,
        journal.clone(),
        None,
        BufferBudget {
            records: 4096,
            bytes: 16 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    book.record = std::mem::take(&mut book.record)
        .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[0x53; 32]));
    let book = Arc::new(Mutex::new(book));
    let sink = super::unit_checkpoint_sink(&book, journal.clone()).unwrap();
    let evidence = Arc::new(UnitCheckpointEvidence::new(
        journal.clone(),
        busbar_kernel::teller::Kernel::new().durability_token(),
    ));
    TestBook {
        book,
        journal,
        evidence,
        sink,
    }
}
fn unit_checkpoint_sink(book: &TestBook) -> Arc<dyn UnitCheckpointSink> {
    book.sink.clone()
}
fn recovery_sink(book: &TestBook) -> Arc<dyn RecoverySink> {
    super::super::usage_recovery_sink(book.journal.clone()).unwrap()
}
fn stop(_book: &TestBook) { /* All persistence crossings are awaited; no background writer. */
}

fn error(message: impl ToString) -> RecordStoreError {
    RecordStoreError(message.to_string())
}

fn unit() -> UnitCheckpoint {
    busbar_kernel::Registration::new()
        .key("work")
        .expect("test meter class registered");
    let audit = super::super::RunningAudit {
        incarnation: 7,
        principal: "checkpoint-principal".into(),
        op_class: "checkpoint.actual".into(),
        origin: "client".into(),
        parent: None,
        wall: 1_700_000_000,
        mono: 91,
        destination: Some("verified-destination".into()),
        rate_card: None,
        policy_epoch: 3,
        hooks: vec![("verified-hook".into(), "pass".into(), false)],
    };
    UnitCheckpoint {
        id: busbar_kernel::door::op_id().0,
        revision: 0,
        unit: 17,
        principal: "checkpoint-principal".into(),
        group: String::new(),
        arrived: 1_700_000_000,
        lane: format!(
            "checkpoint{}lane",
            busbar_kernel::governance::PLANE_LANE_SEP
        ),
        provider: Some("checkpoint".into()),
        era_at: 42,
        era_entry: None,
        units: BTreeMap::from([("work".into(), Count::parse("0.125").unwrap())]),
        targets: vec![UnitTarget {
            bucket: "checkpoint-principal".into(),
            window: 0,
            group: None,
        }],
        metered: true,
        ended: false,
        terminal: None,
        audit: Some(serde_json::to_vec(&audit).unwrap()),
    }
}

async fn total(store: &CoreStore, unit: &UnitCheckpoint) -> Count {
    let ledger = store.ledger().get_usage(&unit.principal, 0).await.unwrap();
    assert_eq!(
        ledger.requests, 0,
        "recovery must not reconstruct admission"
    );
    assert_eq!(
        ledger.billable_requests, 0,
        "recovery must not duplicate flat fees"
    );
    ledger
        .models
        .iter()
        .filter(|model| model.model == unit.lane)
        .fold(Count::ZERO, |sum, model| {
            sum.checked_add(
                Count::from_stored(
                    model.usage_units.get("work").copied().unwrap_or(0),
                    model.scale,
                )
                .unwrap(),
            )
            .unwrap()
        })
}
async fn governor(store: Arc<CoreStore>, book: &TestBook) -> GovState {
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    gov.attach_recovery_sink(recovery_sink(book)).await.unwrap();
    gov.attach_unit_checkpoint_sink(unit_checkpoint_sink(book))
        .await
        .unwrap();
    gov
}

#[tokio::test]
async fn actual_store_running_reports_coalesce_and_restart_settles_once() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-running-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &book).await;
    let mut report = unit();
    for n in 1..=8 {
        report
            .units
            .insert("work".into(), Count::from_micros(n * 125_000));
        gov.stage_unit_checkpoint(report.clone());
    }
    assert!(
        unit_checkpoint_sink(&book)
            .replay()
            .await
            .unwrap()
            .is_empty(),
        "reports cannot write per piece"
    );
    gov.flush_unit_checkpoints().await.unwrap();
    let stored = unit_checkpoint_sink(&book).replay().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].units, report.units);
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::ZERO,
        "running checkpoint is not a ledger row"
    );
    gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(
        unit_checkpoint_sink(&book).replay().await.unwrap()[0].revision,
        stored[0].revision
    );
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open().await;
    let resumed = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &resumed).await;
    assert_eq!(total(store.as_ref(), &report).await, Count::ONE);
    assert!(unit_checkpoint_sink(&resumed)
        .replay()
        .await
        .unwrap()
        .is_empty());
    assert_recovered_audit(&resumed, &report).await;
    gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(total(store.as_ref(), &report).await, Count::ONE);
    stop(&resumed);
}

async fn assert_recovered_audit(book: &TestBook, report: &UnitCheckpoint) {
    let audit = book
        .evidence
        .find_audit(report.unit, 7)
        .await
        .unwrap()
        .expect("original native unit audit");
    let audit = &audit;
    assert_eq!(audit.what.op_class.as_str(), "checkpoint.actual");
    assert_eq!(
        audit.what.destination.as_deref(),
        Some("verified-destination")
    );
    assert_eq!(audit.controls.policy_epoch, 3);
    assert_eq!(audit.controls.hooks_applied.len(), 1);
    assert_eq!(audit.usage.lines[0].quantity, report.units["work"]);
    assert_eq!(audit.usage.fee_count, 0);
    assert_eq!(audit.mono, 91);
    assert_eq!(audit.wall, report.arrived);
    let keys = super::super::keyset_of(&book.lock().unwrap().record);
    busbar_kernel_audit::AuditChain::verify_signature(
        audit,
        keys.get(audit.key_id.as_deref().unwrap()).unwrap(),
    )
    .unwrap();
}

struct LoseAppliedAck {
    inner: Arc<dyn RecoverySink>,
    armed: AtomicBool,
}

#[async_trait::async_trait]
impl RecoverySink for LoseAppliedAck {
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        self.inner.replay().await
    }
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        // The Store raw mutation has returned success; its custody ACK has not been selected.
        if event.state == RecoveryState::Applied && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RecoveryError::Unavailable(
                "planted terminal post-apply/pre-ack crash".into(),
            ));
        }
        self.inner.persist(event).await
    }
}

#[tokio::test]
async fn actual_store_terminal_replay_after_apply_before_ack_does_not_double_charge() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-terminal-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(Arc::new(LoseAppliedAck {
        inner: recovery_sink(&book),
        armed: AtomicBool::new(true),
    }))
    .await
    .unwrap();
    gov.attach_unit_checkpoint_sink(unit_checkpoint_sink(&book))
        .await
        .unwrap();
    let mut report = unit();
    busbar_kernel::Registration::new().key("input").unwrap();
    report
        .units
        .insert("input".into(), Count::parse("0.25").unwrap());
    assert!(gov.finish_unit_checkpoint(report.clone()));
    assert!(gov.flush_unit_checkpoints().await.is_err());
    let terminal = unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .pop()
        .unwrap();
    let operation_ids: Vec<_> = terminal
        .terminal
        .as_ref()
        .unwrap()
        .iter()
        .map(|event| event.operation_id)
        .collect();
    assert!(!operation_ids.is_empty());
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open().await;
    let resumed = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &resumed).await;
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    // An old process's monotonic dedupe age cannot be reconstructed from a wall-clock stamp.
    // The admin surface remains available, while the affected admission waits for a verdict.
    let cost = busbar_kernel::cost::CostModel::resolve_parts(None, 0, &Default::default());
    let key = busbar_contract::records::VirtualKey {
        id: report.principal.clone(),
        enabled: true,
        ..Default::default()
    };
    assert!(gov.try_admit(&cost, &key, "", report.arrived).is_err());
    let unknown = gov.recovery().list(None, 100).await.unwrap();
    assert!(unknown
        .iter()
        .any(|event| event.state == RecoveryState::LandedUnknown));
    for event in unknown
        .into_iter()
        .filter(|event| event.state == RecoveryState::LandedUnknown)
    {
        gov.recovery()
            .resolve(
                &cost,
                RecoveryResolution {
                    operation_id: event.operation_id,
                    body_fingerprint: event.body_fingerprint,
                    expected_revision: event.revision,
                    verdict: RecoveryVerdict::Landed,
                    sender_quiesced: true,
                    backend_quiesced: true,
                    actor: "checkpoint-test-owner".into(),
                    reason: "actual Store readback proves the planted write landed".into(),
                },
            )
            .await
            .unwrap();
    }
    gov.flush_unit_checkpoints().await.unwrap();
    let events = recovery_sink(&resumed).replay().await.unwrap();
    for id in operation_ids {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.operation_id == id && event.revision == 0)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .rev()
                .find(|event| event.operation_id == id)
                .unwrap()
                .state,
            RecoveryState::Settled
        );
    }
    assert!(unit_checkpoint_sink(&resumed)
        .replay()
        .await
        .unwrap()
        .is_empty());
    gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    assert_eq!(
        gov.derived_bucket_usage_async(&cost, &report.principal, "total", true, report.arrived)
            .await
            .unwrap()
            .tokens,
        Count::parse("0.25").unwrap(),
        "late recovery refreshes the exact hot budget counts"
    );
    assert!(
        gov.try_admit(&cost, &key, "", report.arrived).is_ok(),
        "durable settlement refreshes hot targets before unblocking"
    );
    stop(&resumed);
}

#[tokio::test]
async fn actual_store_rejects_checkpoint_head_whose_evidence_was_changed() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-tamper-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let sink = unit_checkpoint_sink(&book);
    let report = unit();
    sink.persist(&report).await.unwrap();
    let family = *b"busbar.unitcp.v1";
    let node = book.journal.node().to_be_bytes();
    let mut framing = b"busbar.persistence.partition/1\0".to_vec();
    framing.extend_from_slice(&family);
    framing.extend_from_slice(&1u64.to_be_bytes());
    framing.extend_from_slice(&8u64.to_be_bytes());
    framing.extend_from_slice(&node);
    let digest = busbar_contract::abi::sdk::digest::sha256(&framing);
    let mut namespace: [u8; 16] = digest[..16].try_into().unwrap();
    namespace[0] |= 0x80;
    let mut key = family.to_vec();
    key.extend_from_slice(&node);
    key.extend_from_slice(&report.id);
    let address = Address { namespace, key };
    let backend = fixture.backend.get().unwrap();
    let ReadResult::Values { mut values, .. } = backend
        .read(Arc::new(Read {
            dataset: store.info().dataset,
            addresses: vec![address.clone()],
            time: None,
        }))
        .await
        .unwrap()
    else {
        panic!("native head read");
    };
    let raw = values.pop().flatten().unwrap();
    let mut head: serde_json::Value =
        serde_json::from_slice(raw.expose(&busbar_kernel::seal::lend())).unwrap();
    head["revision"] = serde_json::json!(head["revision"].as_u64().unwrap() + 1);
    let authority = store.authority().unwrap();
    let candidate = PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: store.info().dataset,
            writer: authority.writer,
            writer_epoch: authority.writer_epoch,
            execution_epoch: authority.execution_epoch,
            operation: busbar_kernel::door::op_id().0,
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![Predicate {
            address: address.clone(),
            expected: ExpectedValue::Exact(raw),
        }],
        mutations: vec![Mutation::Put {
            address,
            value: Secret::new(serde_json::to_vec(&head).unwrap()),
        }],
        time: None,
        result: Secret::default(),
    })
    .unwrap();
    assert!(matches!(
        backend.commit(candidate).await,
        Ok(Decision::Applied(_))
    ));
    assert!(
        sink.replay().await.is_err(),
        "tampered selected state cannot recover as zero"
    );
    stop(&book);
}

struct LoseRemoval {
    inner: Arc<dyn UnitCheckpointSink>,
}

struct StopAfterRecoveredAudit {
    inner: Arc<dyn UnitCheckpointSink>,
}
#[async_trait::async_trait]
impl UnitCheckpointSink for StopAfterRecoveredAudit {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.persist(snapshot).await
    }
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.remove(snapshot).await
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        self.inner.replay().await
    }
    async fn recover_audit(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.recover_audit(snapshot).await?;
        Err(error(
            "planted crash after recovered audit ACK before terminal intent",
        ))
    }
}

#[tokio::test]
async fn actual_store_recovered_audit_replay_after_append_is_one_original_unit_line() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-audit-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let report = unit();
    unit_checkpoint_sink(&book).persist(&report).await.unwrap();
    stop(&book);
    drop(book);
    drop(store);

    let store = fixture.open().await;
    let book = opened(store.clone(), &host).await;
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(recovery_sink(&book))
        .await
        .unwrap();
    assert!(gov
        .attach_unit_checkpoint_sink(Arc::new(StopAfterRecoveredAudit {
            inner: unit_checkpoint_sink(&book)
        }))
        .await
        .is_err());
    assert_recovered_audit(&book, &report).await;
    assert_eq!(total(store.as_ref(), &report).await, Count::ZERO);
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open().await;
    let book = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &book).await;
    assert_recovered_audit(&book, &report).await;
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    assert!(unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .is_empty());
    gov.flush_unit_checkpoints().await.unwrap();
    assert_recovered_audit(&book, &report).await;
    stop(&book);
}

#[tokio::test]
async fn actual_store_live_terminal_keeps_custody_until_fixed_audit_is_durable() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-audit-gate-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &book).await;
    let report = unit();
    assert!(gov.finish_unit_checkpoint(report.clone()));
    assert!(
        gov.flush_unit_checkpoints().await.is_err(),
        "raw ACK cannot retire custody before the fixed audit line"
    );
    let pending = unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    unit_checkpoint_sink(&book)
        .recover_audit(&pending)
        .await
        .unwrap();
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    assert_recovered_audit(&book, &report).await;
    stop(&book);
}

#[async_trait::async_trait]
impl UnitCheckpointSink for LoseRemoval {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.persist(snapshot).await
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        self.inner.replay().await
    }
    async fn remove(&self, _snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        Err(error("planted post-ACK/pre-delete crash"))
    }
}

#[tokio::test]
async fn actual_store_terminal_replay_after_ack_before_delete_uses_settled_receipt() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-delete-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(recovery_sink(&book))
        .await
        .unwrap();
    gov.attach_unit_checkpoint_sink(Arc::new(LoseRemoval {
        inner: unit_checkpoint_sink(&book),
    }))
    .await
    .unwrap();
    let report = unit();
    assert!(gov.finish_unit_checkpoint(report.clone()));
    assert!(gov.flush_unit_checkpoints().await.is_err());
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    assert_eq!(unit_checkpoint_sink(&book).replay().await.unwrap().len(), 1);
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open().await;
    let resumed = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &resumed).await;
    assert!(unit_checkpoint_sink(&resumed)
        .replay()
        .await
        .unwrap()
        .is_empty());
    gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(
        total(store.as_ref(), &report).await,
        Count::parse("0.125").unwrap()
    );
    stop(&resumed);
}
