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
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_kernel::host_services::caller_binding(),
        ));
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
        measurement: None,
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

async fn measurement_total(gov: &GovState, report: &UnitCheckpoint, class: &str) -> Count {
    measurement_total_at(gov, &report.principal, &report.lane, report.arrived, class).await
}

async fn measurement_total_at(
    gov: &GovState,
    principal: &str,
    lane: &str,
    arrived: u64,
    class: &str,
) -> Count {
    gov.metering_for_async(busbar_kernel::governance::metering_bucket(arrived))
        .await
        .unwrap()
        .iter()
        .filter(|row| row.key_id == principal && row.model == lane)
        .fold(Count::ZERO, |total, row| {
            assert_eq!(row.requests, 0);
            assert_eq!(row.billable_requests, 0);
            assert_eq!(
                (
                    row.tokens_input,
                    row.tokens_output,
                    row.tokens_cache_read,
                    row.tokens_cache_write
                ),
                (0, 0, 0, 0)
            );
            total
                .checked_add(
                    Count::from_stored(row.usage_units.get(class).copied().unwrap_or(0), row.scale)
                        .unwrap(),
                )
                .unwrap()
        })
}

fn measurement_binding(
    kind: busbar_contract::abi::mechanism::KindCode,
) -> busbar_kernel::host_measurement::MeasurementBinding {
    busbar_kernel::host_measurement::MeasurementBinding {
        caller: busbar_contract::services::Caller::issue(
            &busbar_kernel::seal::acquire(),
            "neutral-measurement".into(),
            kind,
        ),
        statement_digest: [0x71; 32],
        classes: vec!["work".into(), "input".into()],
    }
}

#[tokio::test]
async fn actual_store_measurement_cumulative_cancel_and_restart_keep_original_request() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_kernel::host_measurement::{MeasurementContext, MeasurementRuntime, Refusal};
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "measurement-request-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = Arc::new(governor(store.clone(), &book).await);
    let seal = busbar_kernel::seal::acquire();
    let runtime = MeasurementRuntime::new(&seal, gov.clone(), 1).unwrap();
    let context = MeasurementContext::request(
        &seal,
        73,
        "original-user".into(),
        "original-group".into(),
        vec![UnitTarget {
            bucket: "original-user".into(),
            window: 0,
            group: Some("original-group".into()),
        }],
        1_700_000_000,
        Default::default(),
    )
    .unwrap();
    let operation = runtime
        .reserve(&seal, measurement_binding(KindCode::Hook), &context, 11)
        .unwrap();
    assert_eq!(operation.revision(), 1);
    assert!(matches!(
        runtime.reserve(&seal, measurement_binding(KindCode::Hook), &context, 11),
        Err(Refusal::Unavailable)
    ));
    operation.capture(1, [(0, Count::ONE)]).unwrap();
    operation.capture(1, [(0, Count::ONE)]).unwrap();
    assert_eq!(
        operation.capture(1, [(0, Count::from_micros(2_000_000))]),
        Err(Refusal::Conflict)
    );
    assert_eq!(
        operation.capture(2, [(0, Count::ZERO)]),
        Err(Refusal::Conflict)
    );
    assert_eq!(
        operation.capture(2, [(0, Count::ONE), (0, Count::ONE)]),
        Err(Refusal::Malformed)
    );
    assert!(unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .is_empty());
    operation.released(false);
    gov.flush_unit_checkpoints().await.unwrap();
    let first = unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(first.audit.is_none());
    assert!(first.measurement.is_some());
    assert!(
        !first.units.contains_key("input"),
        "unreported classes are not invented zeros"
    );
    assert_eq!(first.principal, "original-user");
    assert_eq!(total(&store, &first).await, Count::ZERO);
    operation
        .capture(
            2,
            [
                (1, Count::parse("0.25").unwrap()),
                (0, Count::from_micros(2_000_000)),
            ],
        )
        .unwrap();
    operation.released(true); // Cancellation preserves the last accepted cumulative snapshot.
    operation.released(true);
    assert_eq!(operation.revision(), 0);
    assert_eq!(
        operation.capture(3, [(0, Count::from_micros(3_000_000))]),
        Err(Refusal::Conflict)
    );
    gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(runtime.pending(), 0);
    assert_eq!(
        measurement_total(&gov, &first, "work").await,
        Count::from_micros(2_000_000)
    );
    assert_eq!(
        measurement_total(&gov, &first, "input").await,
        Count::parse("0.25").unwrap()
    );
    assert_eq!(total(&store, &first).await, Count::from_micros(2_000_000));
    let rows = store.ledger().get_usage("original-user", 0).await.unwrap();
    let row = rows
        .models
        .iter()
        .find(|row| row.model == first.lane)
        .unwrap();
    assert_eq!(
        Count::from_stored(row.usage_units["input"], row.scale).unwrap(),
        Count::parse("0.25").unwrap()
    );
    drop(operation);
    drop(runtime);
    drop(gov);
    drop(book);
    let reopened = opened(store.clone(), &host).await;
    let resumed = governor(store.clone(), &reopened).await;
    resumed.flush_unit_checkpoints().await.unwrap();
    assert_eq!(total(&store, &first).await, Count::from_micros(2_000_000));
}

#[tokio::test]
async fn actual_store_measurement_system_origins_recover_without_admission_or_user_budget() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_kernel::host_measurement::{MeasurementContext, MeasurementRuntime};
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "measurement-system-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = Arc::new(governor(store.clone(), &book).await);
    let seal = busbar_kernel::seal::acquire();
    let runtime = MeasurementRuntime::new(&seal, gov.clone(), 7).unwrap();
    let context = MeasurementContext::system(&seal, 1_700_000_000, Default::default());
    for kind in [
        KindCode::Auth,
        KindCode::Store,
        KindCode::Secret,
        KindCode::Export,
        KindCode::Hook,
        KindCode::Transport,
        KindCode::Plane,
    ] {
        let operation = runtime
            .reserve(&seal, measurement_binding(kind), &context, 5)
            .unwrap();
        operation
            .capture(1, [(0, Count::parse("0.125").unwrap())])
            .unwrap();
        operation.released(false);
    }
    gov.flush_unit_checkpoints().await.unwrap();
    let reports = unit_checkpoint_sink(&book).replay().await.unwrap();
    assert_eq!(reports.len(), 7);
    let principals: std::collections::BTreeSet<_> = reports.iter().map(|r| &r.principal).collect();
    assert_eq!(principals.len(), 7);
    for report in &reports {
        assert!(report.principal.starts_with("system-measurement:"));
        assert_eq!(report.unit, 0);
        assert!(report.targets.is_empty());
        assert!(report.audit.is_none());
        let mut forged = report.clone();
        forged.targets.push(UnitTarget {
            bucket: "arbitrary-user".into(),
            window: 0,
            group: None,
        });
        assert!(forged.validate().is_err());
        assert!(unit_checkpoint_sink(&book).persist(&forged).await.is_err());
    }
    drop(runtime);
    drop(gov);
    drop(book);
    let reopened = opened(store.clone(), &host).await;
    let resumed = governor(store.clone(), &reopened).await;
    for report in &reports {
        assert_eq!(
            total(&store, report).await,
            Count::ZERO,
            "system work has no user budget row"
        );
        assert_eq!(
            measurement_total(&resumed, report, "work").await,
            Count::parse("0.125").unwrap()
        );
    }
    resumed.flush_unit_checkpoints().await.unwrap();
    for report in &reports {
        assert_eq!(
            total(&store, report).await,
            Count::ZERO,
            "system work has no user budget row"
        );
        assert_eq!(
            measurement_total(&resumed, report, "work").await,
            Count::parse("0.125").unwrap()
        );
    }
    assert!(store
        .ledger()
        .get_usage("arbitrary-user", 0)
        .await
        .unwrap()
        .models
        .is_empty());
}

#[tokio::test]
async fn actual_store_measurement_lost_applied_ack_replays_exact_raw_identity_once() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_kernel::host_measurement::{MeasurementContext, MeasurementRuntime};
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "measurement-ack-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap(),
    );
    gov.attach_recovery_sink(Arc::new(LoseAppliedAck {
        inner: recovery_sink(&book),
        armed: AtomicBool::new(true),
    }))
    .await
    .unwrap();
    gov.attach_unit_checkpoint_sink(unit_checkpoint_sink(&book))
        .await
        .unwrap();
    let seal = busbar_kernel::seal::acquire();
    let runtime = MeasurementRuntime::new(&seal, gov.clone(), 1).unwrap();
    let context = MeasurementContext::system(&seal, 1_700_000_000, Default::default());
    let operation = runtime
        .reserve(&seal, measurement_binding(KindCode::Secret), &context, 2)
        .unwrap();
    operation.capture(1, [(0, Count::ONE)]).unwrap();
    operation.released(true);
    assert!(gov.flush_unit_checkpoints().await.is_err());
    let terminal = unit_checkpoint_sink(&book)
        .replay()
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        runtime.pending(),
        1,
        "uncertain ACK cannot release reserved custody"
    );
    assert_eq!(measurement_total(&gov, &terminal, "work").await, Count::ONE);
    let identities: Vec<_> = terminal
        .terminal
        .as_ref()
        .unwrap()
        .iter()
        .map(|e| e.operation_id)
        .collect();
    assert!(!identities.is_empty());
    drop(operation);
    drop(runtime);
    drop(gov);
    drop(book);
    let reopened = opened(store.clone(), &host).await;
    let replay = unit_checkpoint_sink(&reopened)
        .replay()
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        replay, terminal,
        "restart retains the exact signed cumulative evidence and raw identities"
    );
    let resumed = governor(store.clone(), &reopened).await;
    assert!(
        resumed.flush_unit_checkpoints().await.is_err(),
        "restart cannot reconstruct the previous process's monotonic dedupe age"
    );
    assert_eq!(
        measurement_total(&resumed, &terminal, "work").await,
        Count::ONE
    );
    let cost = busbar_kernel::cost::CostModel::resolve_parts(None, 0, &Default::default());
    let unknown = resumed.recovery().list(None, 100).await.unwrap();
    assert!(unknown
        .iter()
        .any(|event| event.state == RecoveryState::LandedUnknown));
    for event in unknown
        .into_iter()
        .filter(|event| event.state == RecoveryState::LandedUnknown)
    {
        assert!(identities.contains(&event.operation_id));
        resumed
            .recovery()
            .resolve(
                &cost,
                RecoveryResolution {
                    operation_id: event.operation_id,
                    body_fingerprint: event.body_fingerprint,
                    expected_revision: event.revision,
                    verdict: RecoveryVerdict::Landed,
                    sender_quiesced: true,
                    backend_quiesced: true,
                    actor: "measurement-test-owner".into(),
                    reason: "actual native metering readback proves the planted write landed"
                        .into(),
                },
            )
            .await
            .unwrap();
    }
    resumed.flush_unit_checkpoints().await.unwrap();
    let events = recovery_sink(&reopened).replay().await.unwrap();
    for id in identities {
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
    assert_eq!(
        measurement_total(&resumed, &terminal, "work").await,
        Count::ONE
    );
    assert!(unit_checkpoint_sink(&reopened)
        .replay()
        .await
        .unwrap()
        .is_empty());
}

/// A neutral SDK callback: the only reported fact is a quarter of a named unit
/// across two separate invocations. It has no account/rate/operation ID input.
mod measurement_secret_fixture {
    use busbar_contract::abi::{
        measurement::{BillableClass, UnitCount, UNITS_REPORTED_MICROS},
        mechanism::{call::Outcome, door::Statement},
        sdk::{
            life::{Held, Life, Refreshed, Refusal},
            Instance, Lent, Out, SafeSlot,
        },
    };
    pub struct Witness;
    impl Life for Witness {
        type Kind = busbar_contract::plugin::markers::SecretKind;
        const CANCEL: u32 = busbar_contract::abi::secret::cancel::ABORTED;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self)
        }
        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }
    pub struct Resolve;
    impl SafeSlot for Resolve {
        type Kind = busbar_contract::plugin::markers::SecretKind;
        type State = Held<Witness>;
        type In = busbar_contract::abi::secret::ResolveIn;
        type Out = busbar_contract::abi::secret::ResolveOut;
        fn call(
            instance: Instance<'_, Self::State, Self::Kind>,
            input: Lent<'_, Self::In>,
            mut out: Out<'_, Self::Out>,
        ) -> Outcome {
            if instance.get().is_none() {
                return Outcome::Refused;
            }
            out.measurements(
                &input.head,
                &[UnitCount {
                    class: 0,
                    source: UNITS_REPORTED_MICROS,
                    amount: 125_000,
                }],
            )
            .unwrap();
            busbar_contract::abi::sdk::cred::resolved(
                input,
                &mut out,
                busbar_contract::abi::sdk::cred::Held::new(b"fixture-value".to_vec()),
            )
        }
    }
    const CLASSES: &[BillableClass] = &[BillableClass {
        class: busbar_contract::abi::sdk::door::abi_str("work"),
        family: busbar_contract::abi::sdk::door::abi_str("units"),
    }];
    const fn statement() -> Statement {
        let mut statement =
            busbar_contract::abi::sdk::door::statement("measurement-native-witness", "1.6.0", 4);
        statement.measurement_classes = CLASSES.as_ptr();
        statement.measurement_classes_len = CLASSES.len();
        statement
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: statement(),
        lifecycle: life(Witness),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
    }
}

#[tokio::test]
async fn measurement_root_loader_callback_preserves_early_and_admitted_attribution_in_signed_store()
{
    use crate::root::loader::dispatch::{
        self, kinds::secret::Secret as SecretKind, Bind, ConnTable, DispatchConfig, Dispatcher,
        Frame, LinkedRow, NoSink,
    };
    use busbar_contract::abi::mechanism::{
        call::Outcome,
        lifecycle::{slot, OpenIn, OpenOut},
    };
    use busbar_kernel::plane_driver::{EndPost, FeeRefund, PlaneMoney, UnitMoney};
    struct Post(Vec<u8>);
    impl EndPost for Post {
        fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
        fn checkpoint_facts(&self, _: busbar_contract::UnitKey) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
    }
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "measurement-root-callback-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = Arc::new(governor(store.clone(), &book).await);
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let authority =
        crate::root::measurements::local_authority(gov.clone(), Default::default()).unwrap();
    assert!(dispatcher.set_measurement_authority(authority).is_ok());
    let plugin = dispatch::load_linked::<SecretKind>(
        &LinkedRow::of(measurement_secret_fixture::door).unwrap(),
        Bind {
            instance: "measured-root-secret".into(),
            max_inflight_cap: 4,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let mut opening = Frame::new(
        OpenIn {
            head: dispatch::in_head(),
            host: std::ptr::null(),
            settings: dispatch::NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: dispatch::out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    assert_eq!(
        plugin.call(slot::OPEN, &mut opening).outcome,
        Outcome::Ready
    );
    let key = Arc::new(busbar_contract::records::VirtualKey {
        id: "checkpoint-principal".into(),
        enabled: true,
        ..Default::default()
    });
    let money = Arc::new(PlaneMoney::new(
        gov.clone(),
        Arc::new(Post(unit().audit.unwrap())),
    ));
    let cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        None,
        0,
        &Default::default(),
    ));
    let unit_key = busbar_contract::UnitKey::new(17);
    let arrived = 1_700_000_000;
    let lane = busbar_kernel_ledger::cost::measurement_lane("secret", "measured-root-secret");
    let scope = crate::root::measurements::RequestScope::new(
        &money,
        unit_key,
        &busbar_contract::caps::PrincipalId::new(key.id.clone()),
        Some(&key),
        crate::root::plane_node::Arrived::at(arrived * 1000, 91),
    )
    .unwrap();
    let invoke = || {
        let mut bytes = [0u8; 32];
        let mut frame = Frame::new(
            busbar_contract::abi::secret::ResolveIn {
                head: dispatch::in_head(),
                settings: dispatch::NO_BLOB,
                secret_buf: bytes.as_mut_ptr(),
                secret_cap: bytes.len(),
            },
            busbar_contract::abi::secret::ResolveOut {
                head: dispatch::out_head(),
                secret: dispatch::NO_BLOB,
                error_kind: 0,
                _reserved: 0,
                needed: 0,
            },
        );
        let called = plugin.call(busbar_contract::abi::secret::slot::RESOLVE, &mut frame);
        assert_eq!(
            called.outcome,
            Outcome::Ready,
            "actual SDK callback and root custody accepted"
        );
        assert_eq!(&bytes[..13], b"fixture-value");
        if called.lease != 0 {
            let mut release = Frame::new(
                busbar_contract::abi::mechanism::lifecycle::ReleaseIn {
                    head: dispatch::in_head(),
                    lease: called.lease,
                },
                dispatch::out_head(),
            );
            assert_eq!(
                plugin.call(slot::RELEASE, &mut release).outcome,
                Outcome::Ready
            );
        }
    };
    crate::root::measurements::request(scope, async {
        invoke();
        gov.flush_unit_checkpoints().await.unwrap();
        assert_eq!(
            measurement_total_at(&gov, &key.id, &lane, arrived, "work").await,
            Count::parse("0.125").unwrap()
        );
        assert!(
            store
                .ledger()
                .get_usage(&key.id, 0)
                .await
                .unwrap()
                .models
                .is_empty(),
            "pre-admission facts never invent budget targets"
        );
        let grant = Arc::new(gov.try_admit(&cost, &key, "", arrived).unwrap());
        money.open_admitted(
            unit_key,
            UnitMoney {
                key: key.clone(),
                cost: cost.clone(),
                pool: String::new(),
                lane: String::new(),
                classes: Vec::<String>::new().into(),
                arrived,
                mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                fee: FeeRefund::CallerStatus,
                charge: Default::default(),
            },
            grant,
        );
        invoke();
        gov.flush_unit_checkpoints().await.unwrap();
        assert_eq!(
            measurement_total_at(&gov, &key.id, &lane, arrived, "work").await,
            Count::parse("0.25").unwrap()
        );
        let usage = store.ledger().get_usage(&key.id, 0).await.unwrap();
        let target = usage
            .models
            .iter()
            .find(|model| model.model == lane)
            .unwrap();
        assert_eq!(
            Count::from_stored(target.usage_units["work"], target.scale).unwrap(),
            Count::parse("0.125").unwrap(),
            "only work reserved after actual admission charges its targets"
        );
        money.settle_end(unit_key, 200);
        // This fixture stops before the normal end-post audit append. The actual
        // admission must retain its signed checkpoint until restart seals it;
        // successful generic usage cannot bypass that independent audit guard.
        let audit_pending = gov.flush_unit_checkpoints().await.unwrap_err();
        assert!(audit_pending.0.contains("sealed audit line"));
        let pending = unit_checkpoint_sink(&book).replay().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].measurement.is_none());
        assert!(pending[0].audit.is_some());
        gov.flush_budgets_final().await;
        gov.flush_metering_final().await;
    })
    .await;
    drop(plugin);
    drop(dispatcher);
    drop(money);
    drop(gov);
    drop(book);
    let reopened = opened(store.clone(), &host).await;
    let resumed = governor(store.clone(), &reopened).await;
    resumed.flush_unit_checkpoints().await.unwrap();
    assert_eq!(
        measurement_total_at(&resumed, &key.id, &lane, arrived, "work").await,
        Count::parse("0.25").unwrap()
    );
    let usage = store.ledger().get_usage(&key.id, 0).await.unwrap();
    let target = usage
        .models
        .iter()
        .find(|model| model.model == lane)
        .unwrap();
    assert_eq!(
        Count::from_stored(target.usage_units["work"], target.scale).unwrap(),
        Count::parse("0.125").unwrap()
    );
    assert!(unit_checkpoint_sink(&reopened)
        .replay()
        .await
        .unwrap()
        .is_empty());
}
