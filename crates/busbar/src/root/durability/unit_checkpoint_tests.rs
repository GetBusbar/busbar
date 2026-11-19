// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json;
use busbar_contract::json::JsonValueTrait as _;
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
    backend: OnceLock<Arc<dyn PersistenceBackend>>,
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
        self.open_wrapped(|backend| backend).await
    }
    /// Open with `wrap` inserted between the product Store and native startup.
    async fn open_wrapped(
        &self,
        wrap: impl FnOnce(Arc<dyn PersistenceBackend>) -> Arc<dyn PersistenceBackend>,
    ) -> Arc<CoreStore> {
        if let Some(core) = self.core.get() {
            return core.clone();
        }
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        // The actual application Store is a native MIN-3 image: stage it signed and open it through the
        // root's native boot (Registry::open_store), named by its stamp.
        let library = crate::root::test_plugins::application_store_library();
        let module = crate::root::test_plugins::native_image(&library).name;
        let release = crate::root::test_plugins::key(0x5a);
        let manifest = crate::root::test_plugins::native_manifest(
            "store",
            &library,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        std::fs::write(
            self.path.join("store.tar.gz"),
            crate::root::test_plugins::signed(
                &release,
                manifest,
                &std::fs::read(&library).expect("the actual Store image reads"),
            ),
        )
        .expect("stage the actual Store");
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            serde_json::json!({
                "providers": {}, "models": {}, "auth": {"chain": []},
                "store": {"module": module, "settings": {
                    "db_path": self.path.join("application.sqlite"),
                    "input_budget_bytes": 16 * 1024 * 1024,
                }},
            }),
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the checkpoint deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the checkpoint deployment resolves");
        let plugins = crate::root::test_plugins::trusted_config_with_key(&self.path, &release);
        let crate::root::min3_boot::fixture::Fixture { backend, .. } =
            crate::root::min3_boot::fixture::open(
                &cfg,
                &plugins,
                Arc::new(crate::root::door_steps::Rules::default()),
            )
            .await
            .expect("the actual Store opens natively");
        let mut startup = Startup::new(
            wrap(backend.clone()),
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
    let digest = busbar_contract::digest::sha256(host.as_bytes());
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
    let sink = super::unit_checkpoint_sink(&book, journal.clone(), None).unwrap();
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
    RecordStoreError::from(message.to_string())
}

fn unit() -> UnitCheckpoint {
    busbar_kernel::Registration::new()
        .key("work")
        .expect("test meter class registered");
    let audit = super::super::RunningAudit {
        selected_identity: None,
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
        audit: Some(json::to_vec(&audit).unwrap().into()),
        measurement: None,
        unread: None,
        partitions: None,
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

/// WASTE-CORE-LIFECYCLE W1 steps 1-2: persisting a running checkpoint (first revision and a
/// later one over a selected head) proves the head from the runtime journal's own verified head and
/// locates frames by sequence arithmetic, so it opens no whole-journal replay.
#[tokio::test]
async fn checkpoint_persist_opens_no_journal_replay() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-replays-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    let gov = governor(store.clone(), &book).await;
    let mut report = unit();
    report
        .units
        .insert("work".into(), Count::from_micros(125_000));
    let before = busbar_kernel::persistence::journal::replays_on_this_thread();
    gov.stage_unit_checkpoint(report.clone());
    gov.flush_unit_checkpoints().await.unwrap();
    report
        .units
        .insert("work".into(), Count::from_micros(250_000));
    gov.stage_unit_checkpoint(report.clone());
    gov.flush_unit_checkpoints().await.unwrap();
    let replays = busbar_kernel::persistence::journal::replays_on_this_thread() - before;
    let stored = unit_checkpoint_sink(&book).replay().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].units, report.units,
        "the later revision is selected"
    );
    assert_eq!(
        replays, 0,
        "two checkpoint persists must not replay the node journal ({replays} replays)"
    );
    stop(&book);
}

async fn assert_recovered_audit(book: &TestBook, report: &UnitCheckpoint) {
    let (_node_seq, audit) = book
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

#[tokio::test]
async fn recovered_audit_reappend_preserves_wal_custody_position() {
    let fixture = ActualStore::new();
    let store = fixture.open().await;
    let host = format!(
        "unit-checkpoint-position-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store, &host).await;
    let report = unit();
    unit_checkpoint_sink(&book).persist(&report).await.unwrap();
    unit_checkpoint_sink(&book)
        .recover_audit(&report)
        .await
        .unwrap();
    let (found_node_seq, audit) = book
        .evidence
        .find_audit(report.unit, 7)
        .await
        .unwrap()
        .unwrap();
    let node_seq = book.evidence.append_audit(audit.clone()).await.unwrap();
    assert_eq!(node_seq, found_node_seq);
    assert_ne!(
        node_seq, 0,
        "an existing original must retain its WAL position"
    );
    assert_ne!(
        node_seq, audit.seq,
        "checkpoint records separate WAL and audit positions"
    );
    let carried = Carried {
        seq: node_seq,
        hash: busbar_kernel_audit::Fingerprint::from_hex(&audit.hash)
            .unwrap()
            .0,
    };
    assert_eq!(book.evidence.find_audit_at(carried).await.unwrap(), audit);
    assert_eq!(book.evidence.append_audit(audit).await.unwrap(), node_seq);
    stop(&book);
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
    let digest = busbar_contract::digest::sha256(&framing);
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
    let mut head: json::Value =
        json::parse_value(raw.expose(&busbar_kernel::seal::lend())).unwrap();
    head["revision"] = json::json!(head["revision"].as_u64().unwrap() + 1);
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
            value: Secret::new(json::to_vec(&head).unwrap()),
        }],
        time: None,
        result: Secret::default(),
    })
    .unwrap();
    assert!(matches!(
        backend.commit(candidate, test_commit_key()).await,
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
    kind: busbar_contract::kinds::codes::KindCode,
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
    use busbar_contract::kinds::codes::KindCode;
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
    use busbar_contract::kinds::codes::KindCode;
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
    use busbar_contract::kinds::codes::KindCode;
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

/// A request-path audit append on this node's own journal lands before every
/// read of its original frames while enabled, as audits do throughout a
/// checkpoint flush. Reads the append itself makes are answered plainly.
struct AppendDuringReplay {
    actual: Arc<dyn PersistenceBackend>,
    journal: OnceLock<Arc<RuntimeJournal>>,
    enabled: AtomicBool,
    busy: AtomicBool,
    appended: std::sync::atomic::AtomicUsize,
}
impl PersistenceBackend for AppendDuringReplay {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.actual.info()
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.actual.clock(dataset)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.actual.scan(request)
    }
    fn commit(
        &self,
        candidate: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> busbar_contract::persistence::Call<'_, Decision> {
        self.actual.commit(candidate, key)
    }
    fn read(&self, request: Arc<Read>) -> busbar_contract::persistence::Call<'_, ReadResult> {
        Box::pin(async move {
            let original = self.enabled.load(Ordering::SeqCst)
                && request.addresses.iter().any(|at| {
                    at.key.starts_with(b"busbar.journal4\0") && at.key.get(24) == Some(&b'R')
                });
            if original && !self.busy.swap(true, Ordering::SeqCst) {
                if let Some(journal) = self.journal.get() {
                    let run = journal.stage_run(&[busbar_kernel_wal::Entry::new(
                        busbar_kernel_wal::RecordClass::Transaction,
                        b"request-path audit".to_vec(),
                    )]);
                    if let Ok(run) = run {
                        if journal.confirm(&run).await.is_ok() {
                            self.appended.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                self.busy.store(false, Ordering::SeqCst);
            }
            self.actual.read(request).await
        })
    }
}

/// PERFPASS-F2 T1: a running checkpoint persists while request-path audits
/// append to the same node journal throughout its replays. Before the fix
/// every attempt lost to the append ("unit checkpoint: Authority").
#[tokio::test]
async fn actual_store_checkpoint_persists_while_request_audits_append() {
    let fixture = ActualStore::new();
    let view = OnceLock::<Arc<AppendDuringReplay>>::new();
    let store = fixture
        .open_wrapped(|actual| {
            let wrapped = Arc::new(AppendDuringReplay {
                actual,
                journal: OnceLock::new(),
                enabled: AtomicBool::new(false),
                busy: AtomicBool::new(false),
                appended: Default::default(),
            });
            assert!(view.set(wrapped.clone()).is_ok());
            wrapped as Arc<dyn PersistenceBackend>
        })
        .await;
    let view = view.get().expect("wrapped store").clone();
    let host = format!(
        "unit-checkpoint-append-race-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host).await;
    assert!(view.journal.set(book.journal.clone()).is_ok());
    let sink = unit_checkpoint_sink(&book);
    let snapshot = unit();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        view.enabled.store(true, Ordering::SeqCst);
        let mut last = Err(error("no attempt"));
        for _ in 0..3 {
            last = sink.persist(&snapshot).await;
            if last.is_ok() {
                break;
            }
        }
        if let Err(why) = &last {
            panic!("checkpoint lost to request-path appends: {}", why.0);
        }
        assert!(
            view.appended.load(Ordering::SeqCst) > 0,
            "no append interleaved"
        );
        let stored = sink.replay().await.unwrap();
        assert!(
            stored == vec![snapshot.clone()],
            "the persisted checkpoint replays"
        );
        view.enabled.store(false, Ordering::SeqCst);
    })
    .await
    .expect("no hang");
    stop(&book);
}

/// A slotted key for a raw commit a test sends past the store facade.
fn test_commit_key() -> busbar_contract::persistence::CommitKey {
    busbar_contract::persistence::CommitKey::slotted(
        0,
        1,
        &busbar_contract::caps::SlotSeal::acquire_for_tests(),
    )
    .expect("slot 0, seq 1 is a valid key")
}

#[tokio::test]
async fn selected_recovery_keeps_signed_partition_and_rejects_replayed_attribution_change() {
    let fixture = ActualStore::new();
    let core = fixture.open().await;
    let host = format!(
        "selected-audit-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(core, &host).await;
    let mut report = crate::root::selected_report_tests::terminal();
    let facts = super::super::RunningAudit {
        selected_identity: Some(super::super::SelectedAuditIdentity {
            node: book.lock().unwrap().record.node(),
            boot_nonce: [7; 16],
            user: Some("original-user".into()),
            labels: vec![("purpose".into(), "original".into())],
        }),
        incarnation: 7,
        principal: report.principal.clone(),
        op_class: "checkpoint.selected".into(),
        origin: "client".into(),
        parent: None,
        wall: report.arrived,
        mono: 91,
        destination: None,
        rate_card: None,
        policy_epoch: 3,
        hooks: Vec::new(),
    };
    report.audit = Some(json::to_vec(&facts).unwrap().into());
    let sink = unit_checkpoint_sink(&book);
    sink.recover_audit(&report).await.unwrap();
    let (_, audit) = book
        .evidence
        .find_audit(report.unit, 7)
        .await
        .unwrap()
        .unwrap();
    let view = busbar_kernel::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint::try_from(&report).unwrap();
    let expected = crate::root::selected_report::selected_billing(&view).unwrap();
    assert_eq!(audit.unit.billing.as_ref(), Some(&expected));
    assert!(audit.usage.lines.is_empty());
    assert_eq!(audit.unit.boot_nonce, [7; 16]);
    assert_eq!(audit.unit.records.user.as_deref(), Some("original-user"));
    sink.recover_audit(&report).await.unwrap();
    report.partitions.as_mut().unwrap().attempts[0]
        .usage
        .provider = Some("another-provider".into());
    assert!(
        sink.recover_audit(&report).await.is_err(),
        "same identity cannot adopt a different partition"
    );
    stop(&book);
}
