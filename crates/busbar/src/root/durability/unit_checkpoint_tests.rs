// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::RecordStore;
use busbar_contract::store_calls::StoreCalls;
use busbar_contract::Count;
use busbar_kernel::governance::recovery::{
    RecoveryError, RecoveryEvent, RecoveryResolution, RecoverySink, RecoveryState, RecoveryVerdict,
};
use busbar_kernel::governance::unit_checkpoint::UnitTarget;
use busbar_kernel::governance::GovState;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Open a new product plugin handle on the same on-disk SQLite database on every restart.
struct ActualStore(std::path::PathBuf);
impl ActualStore {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-unit-checkpoint-{}",
            hex::encode(busbar_kernel::door::op_id().0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn open(&self) -> Arc<crate::root::loader::store_v3::LoadedStore> {
        use crate::root::loader::dispatch::{
            load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
        };
        let path = crate::root::test_plugins::application_store_library();
        let stated = rendering_of_library(&path).unwrap().unwrap();
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load_dropped::<crate::root::loader::dispatch::kinds::store::Store>(
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
        let settings = serde_json::to_vec(&crate::root::test_plugins::application_store_settings(
            &self.0,
        ))
        .unwrap();
        Arc::new(
            crate::root::loader::store_v3::LoadedStore::open(
                plugin,
                dispatcher,
                &settings,
                busbar_kernel::door::op_id,
            )
            .unwrap(),
        )
    }
}
impl Drop for ActualStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn opened(calls: Arc<dyn StoreCalls>, host: &str) -> Arc<Mutex<Durability>> {
    let taken = super::super::take_node(calls.as_ref(), host).unwrap();
    let lane = JournalLane::start(calls, "unit-checkpoint-actual-store").unwrap();
    if let Some(lease) = taken.lease {
        lane.hold_lease(lease);
    }
    lane.bind_recovery_identity(host, taken.id).unwrap();
    let mut book = super::super::build_on_store(
        &super::super::DurabilityConfig { data_dir: None },
        taken.id,
        lane,
        None,
    )
    .unwrap();
    book.record = std::mem::take(&mut book.record)
        .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[0x53; 32]));
    Arc::new(Mutex::new(book))
}

fn stop(book: &Arc<Mutex<Durability>>) {
    let lane = book.lock().unwrap().lane().cloned().unwrap();
    assert!(lane.drain(std::time::Duration::from_secs(5)));
    lane.release_held_lease();
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

fn total(store: &dyn RecordStore, unit: &UnitCheckpoint) -> Count {
    let ledger = store.get_usage(&unit.principal, 0).unwrap();
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
                    i128::from(model.usage_units.get("work").copied().unwrap_or(0)),
                    model.scale,
                )
                .unwrap(),
            )
            .unwrap()
        })
}

fn governor(store: Arc<dyn RecordStore>, book: &Arc<Mutex<Durability>>) -> GovState {
    let gov = GovState::new(store, None).unwrap();
    gov.attach_recovery_sink(super::super::usage_recovery_sink(book))
        .unwrap();
    gov.attach_unit_checkpoint_sink(unit_checkpoint_sink(book))
        .unwrap();
    gov
}

#[test]
fn actual_store_running_reports_coalesce_and_restart_settles_once() {
    let fixture = ActualStore::new();
    let store = fixture.open();
    let host = format!(
        "unit-checkpoint-running-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host);
    let gov = governor(store.clone(), &book);
    let mut report = unit();
    for n in 1..=8 {
        report
            .units
            .insert("work".into(), Count::from_micros(n * 125_000));
        gov.stage_unit_checkpoint(report.clone());
    }
    assert!(
        unit_checkpoint_sink(&book).replay().unwrap().is_empty(),
        "reports cannot write per piece"
    );
    gov.flush_unit_checkpoints().unwrap();
    let stored = unit_checkpoint_sink(&book).replay().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].units, report.units);
    assert_eq!(
        total(store.as_ref(), &report),
        Count::ZERO,
        "running checkpoint is not a ledger row"
    );
    gov.flush_unit_checkpoints().unwrap();
    assert_eq!(
        unit_checkpoint_sink(&book).replay().unwrap()[0].revision,
        stored[0].revision
    );
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open();
    let resumed = opened(store.clone(), &host);
    let gov = governor(store.clone(), &resumed);
    assert_eq!(total(store.as_ref(), &report), Count::ONE);
    assert!(unit_checkpoint_sink(&resumed).replay().unwrap().is_empty());
    assert_recovered_audit(&resumed, &report);
    gov.flush_unit_checkpoints().unwrap();
    assert_eq!(total(store.as_ref(), &report), Count::ONE);
    stop(&resumed);
}

fn assert_recovered_audit(book: &Arc<Mutex<Durability>>, report: &UnitCheckpoint) {
    let records = book.lock().unwrap().chain().unwrap().unwrap();
    let audits: Vec<_> = records
        .iter()
        .filter_map(|record| super::super::decode_audit(record).unwrap())
        .filter(|audit| audit.what.unit_key.get() == report.unit && audit.what.incarnation == 7)
        .collect();
    assert_eq!(
        audits.len(),
        1,
        "restart seals one fixed line for the original unit identity"
    );
    let audit = &audits[0];
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

impl RecoverySink for LoseAppliedAck {
    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        self.inner.replay()
    }
    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        // The Store raw mutation has returned success; its custody ACK has not been selected.
        if event.state == RecoveryState::Applied && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RecoveryError::Unavailable(
                "planted terminal post-apply/pre-ack crash".into(),
            ));
        }
        self.inner.persist(event)
    }
}

#[test]
fn actual_store_terminal_replay_after_apply_before_ack_does_not_double_charge() {
    let fixture = ActualStore::new();
    let store = fixture.open();
    let host = format!(
        "unit-checkpoint-terminal-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host);
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(Arc::new(LoseAppliedAck {
        inner: super::super::usage_recovery_sink(&book),
        armed: AtomicBool::new(true),
    }))
    .unwrap();
    gov.attach_unit_checkpoint_sink(unit_checkpoint_sink(&book))
        .unwrap();
    let mut report = unit();
    busbar_kernel::Registration::new().key("input").unwrap();
    report
        .units
        .insert("input".into(), Count::parse("0.25").unwrap());
    assert!(gov.finish_unit_checkpoint(report.clone()));
    assert!(gov.flush_unit_checkpoints().is_err());
    let terminal = unit_checkpoint_sink(&book).replay().unwrap().pop().unwrap();
    let operation_ids: Vec<_> = terminal
        .terminal
        .as_ref()
        .unwrap()
        .iter()
        .map(|event| event.operation_id)
        .collect();
    assert!(!operation_ids.is_empty());
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open();
    let resumed = opened(store.clone(), &host);
    let gov = governor(store.clone(), &resumed);
    assert_eq!(
        total(store.as_ref(), &report),
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
    let unknown = gov.recovery().list(None, 100).unwrap();
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
            .unwrap();
    }
    gov.flush_unit_checkpoints().unwrap();
    let events = super::super::usage_recovery_sink(&resumed)
        .replay()
        .unwrap();
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
    assert!(unit_checkpoint_sink(&resumed).replay().unwrap().is_empty());
    gov.flush_unit_checkpoints().unwrap();
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    assert_eq!(
        gov.derived_bucket_usage(&cost, &report.principal, "total", true, report.arrived)
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

#[test]
fn actual_store_rejects_checkpoint_head_whose_evidence_was_changed() {
    let fixture = ActualStore::new();
    let store = fixture.open();
    let host = format!(
        "unit-checkpoint-tamper-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host);
    let sink = unit_checkpoint_sink(&book);
    let report = unit();
    sink.persist(&report).unwrap();
    let raw = wait_for(store.record_get(SCHEMA, &report.id))
        .unwrap()
        .unwrap();
    let mut head: Head = serde_json::from_slice(raw.as_slice()).unwrap();
    head.revision += 1;
    let changed =
        busbar_contract::kinds::RecordBytes::new(serde_json::to_vec(&head).unwrap()).unwrap();
    wait_for(store.record_put(SCHEMA, &report.id, &changed)).unwrap();
    assert!(
        sink.replay().is_err(),
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
impl UnitCheckpointSink for StopAfterRecoveredAudit {
    fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.persist(snapshot)
    }
    fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.remove(snapshot)
    }
    fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        self.inner.replay()
    }
    fn recover_audit(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.recover_audit(snapshot)?;
        Err(error(
            "planted crash after recovered audit ACK before terminal intent",
        ))
    }
}

#[test]
fn actual_store_recovered_audit_replay_after_append_is_one_original_unit_line() {
    let fixture = ActualStore::new();
    let store = fixture.open();
    let host = format!(
        "unit-checkpoint-audit-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host);
    let report = unit();
    unit_checkpoint_sink(&book).persist(&report).unwrap();
    stop(&book);
    drop(book);
    drop(store);

    let store = fixture.open();
    let book = opened(store.clone(), &host);
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(super::super::usage_recovery_sink(&book))
        .unwrap();
    assert!(gov
        .attach_unit_checkpoint_sink(Arc::new(StopAfterRecoveredAudit {
            inner: unit_checkpoint_sink(&book)
        }))
        .is_err());
    assert_recovered_audit(&book, &report);
    assert_eq!(total(store.as_ref(), &report), Count::ZERO);
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open();
    let book = opened(store.clone(), &host);
    let gov = governor(store.clone(), &book);
    assert_recovered_audit(&book, &report);
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    assert!(unit_checkpoint_sink(&book).replay().unwrap().is_empty());
    gov.flush_unit_checkpoints().unwrap();
    assert_recovered_audit(&book, &report);
    stop(&book);
}

#[test]
fn actual_store_live_terminal_keeps_custody_until_fixed_audit_is_durable() {
    let fixture = ActualStore::new();
    let store = fixture.open();
    let host = format!(
        "unit-checkpoint-audit-gate-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host);
    let gov = governor(store.clone(), &book);
    let report = unit();
    assert!(gov.finish_unit_checkpoint(report.clone()));
    assert!(
        gov.flush_unit_checkpoints().is_err(),
        "raw ACK cannot retire custody before the fixed audit line"
    );
    let pending = unit_checkpoint_sink(&book).replay().unwrap().pop().unwrap();
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    unit_checkpoint_sink(&book).recover_audit(&pending).unwrap();
    gov.flush_unit_checkpoints().unwrap();
    assert!(unit_checkpoint_sink(&book).replay().unwrap().is_empty());
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    assert_recovered_audit(&book, &report);
    stop(&book);
}

impl UnitCheckpointSink for LoseRemoval {
    fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.inner.persist(snapshot)
    }
    fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        self.inner.replay()
    }
    fn remove(&self, _snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        Err(error("planted post-ACK/pre-delete crash"))
    }
}

#[test]
fn actual_store_terminal_replay_after_ack_before_delete_uses_settled_receipt() {
    let fixture = ActualStore::new();
    let store = fixture.open();
    let host = format!(
        "unit-checkpoint-delete-{}",
        hex::encode(busbar_kernel::door::op_id().0)
    );
    let book = opened(store.clone(), &host);
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(super::super::usage_recovery_sink(&book))
        .unwrap();
    gov.attach_unit_checkpoint_sink(Arc::new(LoseRemoval {
        inner: unit_checkpoint_sink(&book),
    }))
    .unwrap();
    let report = unit();
    assert!(gov.finish_unit_checkpoint(report.clone()));
    assert!(gov.flush_unit_checkpoints().is_err());
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    assert_eq!(unit_checkpoint_sink(&book).replay().unwrap().len(), 1);
    stop(&book);
    drop(gov);
    drop(book);
    drop(store);

    let store = fixture.open();
    let resumed = opened(store.clone(), &host);
    let gov = governor(store.clone(), &resumed);
    assert!(unit_checkpoint_sink(&resumed).replay().unwrap().is_empty());
    gov.flush_unit_checkpoints().unwrap();
    assert_eq!(
        total(store.as_ref(), &report),
        Count::parse("0.125").unwrap()
    );
    stop(&resumed);
}
