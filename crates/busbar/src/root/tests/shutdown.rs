// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shutdown drain over the real native Store: `finish` (SHUTDOWN-HANG F4) joins every owner
//! of a write before it retires the writer, never retires one it could not drain, and returns
//! the exit code instead of exiting. Ported from the deleted `tail`/`tail_after_flusher` tests:
//! every behaviour they asserted that still exists is asserted here through `finish`.

use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Mutation, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::records::{VirtualKey, UNIT_INPUT};
use busbar_kernel::cost::CostModel;
use busbar_kernel::persistence::{
    boot_identity::BootIdentity,
    facade::{CoreStore, Limits},
    journal::runtime::{BufferBudget, RuntimeError},
    startup::{Progress, Startup},
};
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use tokio::sync::{Notify, Semaphore};

const WAIT: Duration = Duration::from_secs(5);
const INPUT_USED: u64 = 17;
/// A budget no step of these tests comes near: every phase ends on its own work.
const ROOMY: Duration = Duration::from_secs(30);

async fn fixture_with_running_cut(clock: Arc<DrainClock>) -> (Fixture, Arc<FlushGate>) {
    use crate::root::durability::{
        audit_services::AuditServices,
        tests::{audit_inputs, audit_pass, token},
        Durability,
    };
    use busbar_kernel::persistence::journal::{CUT_BATCH, RETAIN_TAIL};
    use busbar_kernel_audit::{AuditSigningKey, BootstrapSigner, LiveSigner, Notary};
    let mut fixture = Fixture::with_ephemeral(8192, true).await;
    let (live, boot) = AuditSigningKey::from_seed(&[0x75; 32])
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let (feed, start) = {
        let held = fixture.book.durability.lock().unwrap();
        (held.head.clone(), held.notary_start())
    };
    let (audit, _) = AuditServices::spawn(
        Notary::new(live),
        BootstrapSigner::new(boot),
        fixture.seen.journal.node(),
        fixture.seen.journal.clone(),
        feed,
        start,
    )
    .unwrap();
    let audit = Arc::new(audit);
    let gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.cut.lock().unwrap() = Some(gate.clone());
    audit.start_notary(1, clock, None, Arc::clone(&fixture.book.durability));
    fixture.book.audit = Some(audit);
    for unit in 1..=(RETAIN_TAIL + 3 * CUT_BATCH) {
        Durability::seal_unit(
            &fixture.book.durability,
            audit_inputs(unit),
            audit_pass(),
            &token(),
        )
        .await
        .unwrap();
    }
    gate.entered().await;
    assert!(
        fixture.book.audit.as_ref().unwrap().cut_retained(),
        "an in-flight cut is reported retained before its first Store answer"
    );
    (fixture, gate)
}

/// SF-6 test 30(e): exact cut settlement participates in the real shutdown/retirement path.
#[tokio::test]
async fn retained_cut_at_shutdown_returns_75_and_keeps_the_writer_admitted() {
    let clock = DrainClock::new(Duration::from_millis(500));
    let (fixture, gate) = fixture_with_running_cut(clock.clone()).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let drain = ShutdownDrain::new(clock.clone());
    clock.arm(tokio::time::Instant::now() + clock.budget());
    let code = tokio::time::timeout(WAIT, finish(post, &drain))
        .await
        .unwrap();
    assert_eq!(
        code, 75,
        "an undecided cut refuses writer retirement without a spend failure"
    );
    assert!(drain.detached() > 0);
    seen.still_admitted().await;
    gate.release();
}

#[tokio::test]
async fn a_cut_settled_during_shutdown_allows_exit_zero() {
    let clock = DrainClock::new(ROOMY);
    let (fixture, gate) = fixture_with_running_cut(clock.clone()).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, _) = fixture.post(false, None, &shutdown_tx, None);
    let drain = ShutdownDrain::new(clock.clone());
    clock.arm(tokio::time::Instant::now() + clock.budget());
    let mut finishing = std::pin::pin!(finish(post, &drain));
    still_running(finishing.as_mut()).await;
    gate.release();
    assert_eq!(tokio::time::timeout(WAIT, finishing).await.unwrap(), 0);
    assert_eq!(drain.detached(), 0);
}

/// SF-6 test 30(c): real governance holds a streamed checkpoint and a usage write across cuts.
#[tokio::test]
async fn governed_checkpoint_and_usage_originals_survive_retention_pressure() {
    use busbar_kernel::persistence::journal::{CutProgress, RETAIN_TAIL};
    let fixture = Fixture::with_ephemeral(8192, true).await;
    fixture.attach_sinks().await;
    let mut unit = fixture.unit();
    fixture.seen.gov.stage_unit_checkpoint(unit.clone());
    fixture.seen.gov.flush_unit_checkpoints().await.unwrap();
    let budget_gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.budget.lock().unwrap() = Some(budget_gate.clone());
    fixture.accrue();
    let gov = fixture.seen.gov.clone();
    let flushing = tokio::spawn(async move { gov.flush_budgets().await });
    budget_gate.entered().await;
    let journal = fixture.seen.journal.clone();
    for _ in 0..(3 * RETAIN_TAIL) {
        let run = journal
            .stage_run(&[Entry::new(RecordClass::Load, vec![4])])
            .unwrap();
        journal.confirm(&run).await.unwrap();
    }
    let mut cut = journal.cutter().unwrap();
    assert_eq!(
        cut.truncate_through(u64::MAX).await,
        CutProgress::Idle,
        "live checkpoint and usage ancestry keep their original rows"
    );
    unit.units.insert(
        "work".into(),
        busbar_contract::Count::parse("0.250").unwrap(),
    );
    fixture.seen.gov.stage_unit_checkpoint(unit.clone());
    fixture.seen.gov.flush_unit_checkpoints().await.unwrap();
    budget_gate.release();
    assert!(tokio::time::timeout(WAIT, flushing).await.unwrap().unwrap() > 0);
    assert_eq!(fixture.seen.requests().await, 1);
    assert!(fixture.seen.gov.finish_unit_checkpoint(unit));
    fixture.seen.gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(
        journal.locate_truncated(),
        0,
        "persist, usage settlement and checkpoint removal never lose carried originals"
    );
    assert!(
        matches!(
            cut.truncate_through(u64::MAX).await,
            CutProgress::Cut { .. }
        ),
        "settled governance releases its old pins"
    );
    assert!(
        matches!(
            RuntimeJournal::open(
                fixture.seen.core.clone(),
                journal.node(),
                fixture.seen.budget
            )
            .await,
            Err(RuntimeError::Truncated)
        ),
        "a same-holder retake after a cut is refused"
    );
}

pub(super) struct FlushGate {
    entered: Notify,
    released: Semaphore,
}
impl Default for FlushGate {
    fn default() -> Self {
        Self {
            entered: Notify::new(),
            released: Semaphore::new(0),
        }
    }
}
impl FlushGate {
    async fn wait(&self) {
        self.entered.notify_one();
        self.released.acquire().await.unwrap().forget();
    }
    pub(super) fn release(&self) {
        self.released.add_permits(1);
    }
    pub(super) async fn entered(&self) {
        tokio::time::timeout(WAIT, self.entered.notified())
            .await
            .expect("actual native commit reached the gate");
    }
}

/// Faults intercept the real product's primitive commit. Key/ledger/journal
/// encoding, guarded mutation planning, and retained attempts stay in CoreStore.
pub(super) struct FlushBackend {
    inner: Arc<dyn PersistenceBackend>,
    ephemeral: bool,
    cut: Mutex<Option<Arc<FlushGate>>>,
    pub(super) budget: Mutex<Option<Arc<FlushGate>>>,
    pub(super) metering: Mutex<Option<Arc<FlushGate>>>,
    pub(super) journal: Mutex<Option<Arc<FlushGate>>>,
    /// A unit checkpoint selection or delete (`busbar.unitcp.v1` rows).
    pub(super) unitcp: Mutex<Option<Arc<FlushGate>>>,
    /// A usage recovery selection (`busbar.recover1` rows).
    pub(super) recovery: Mutex<Option<Arc<FlushGate>>>,
    /// Every other commit (the lease release, retirement, identity rows).
    pub(super) other: Mutex<Option<Arc<FlushGate>>>,
    pub(super) fail_accounting: AtomicBool,
    pub(super) panic_budget: AtomicBool,
}
impl PersistenceBackend for FlushBackend {
    fn info(&self) -> BackendInfo {
        let mut info = self.inner.info();
        if self.ephemeral {
            info.durability = busbar_contract::persistence::Durability::Ephemeral;
        }
        info
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        candidate: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            let is = |prefix: &[u8]| {
                candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put {address,..} if address.key.starts_with(prefix))
            })
            };
            let budget = is(b"U");
            let metering = is(b"M");
            let journal = is(b"busbar.journal4\0");
            let unitcp = candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. } | Mutation::Delete(address)
                    if address.key.starts_with(b"busbar.unitcp.v1"))
            });
            let recovery = is(b"busbar.recover1\0");
            let cut = candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. }
                    if address.key.starts_with(b"busbar.journal4\0") && address.key.get(24) == Some(&b'B'))
            });
            let gate = if cut {
                self.cut.lock().unwrap().take()
            } else if budget {
                self.budget.lock().unwrap().take()
            } else if metering {
                self.metering.lock().unwrap().take()
            } else if unitcp {
                self.unitcp.lock().unwrap().take()
            } else if recovery {
                self.recovery.lock().unwrap().take()
            } else if journal {
                self.journal.lock().unwrap().take()
            } else {
                self.other.lock().unwrap().take()
            };
            if let Some(gate) = gate {
                gate.wait().await;
            }
            if budget && self.panic_budget.swap(false, Ordering::AcqRel) {
                panic!("planted panic while the native budget attempt is owned");
            }
            if (budget || metering) && self.fail_accounting.load(Ordering::Acquire) {
                return Err(Failure::Unknown);
            }
            self.inner.commit(candidate, key).await
        })
    }
}

/// What a test reads after `finish` has taken the fixture's book and Store admission.
pub(super) struct Observed {
    pub(super) backend: Arc<FlushBackend>,
    pub(super) core: Arc<CoreStore>,
    pub(super) journal: Arc<RuntimeJournal>,
    pub(super) gov: Arc<GovState>,
    pub(super) key: VirtualKey,
    pub(super) day: u64,
    pub(super) budget: BufferBudget,
}
impl Observed {
    pub(super) async fn requests(&self) -> u64 {
        self.core
            .ledger()
            .get_usage(&self.key.id, 0)
            .await
            .unwrap()
            .requests
    }
    pub(super) async fn metered(&self) -> Vec<busbar_contract::records::MeteringRow> {
        self.core.ledger().list_metering(self.day).await.unwrap()
    }
    /// The writer was not retired: the native authority still admits a write.
    pub(super) async fn still_admitted(&self) {
        self.core
            .identity()
            .put_key(&VirtualKey {
                id: format!(
                    "writer-remains-admitted-{}",
                    busbar_kernel::door::op_id().counter()
                ),
                enabled: true,
                ..Default::default()
            })
            .await
            .expect("native authority remains admitted for exact reconciliation");
    }
}

pub(super) struct Fixture {
    pub(super) seen: Observed,
    startup: Startup,
    book: crate::root::durability::NodeBook,
}
impl Fixture {
    pub(super) async fn new(capacity: usize) -> Self {
        Self::with_ephemeral(capacity, false).await
    }
    async fn with_ephemeral(capacity: usize, ephemeral: bool) -> Self {
        let backend = Arc::new(FlushBackend {
            inner: crate::root::real_store::native_backend().await,
            ephemeral,
            cut: Mutex::new(None),
            budget: Mutex::new(None),
            metering: Mutex::new(None),
            journal: Mutex::new(None),
            unitcp: Mutex::new(None),
            recovery: Mutex::new(None),
            other: Mutex::new(None),
            fail_accounting: AtomicBool::new(false),
            panic_budget: AtomicBool::new(false),
        });
        let mut startup = Startup::new(
            backend.clone(),
            Limits {
                pending_operations: 1024,
                conflict_retries: 8,
                scan_items: 128,
                scan_bytes: 1024 * 1024,
            },
            true,
        )
        .unwrap();
        loop {
            match startup.advance().await.expect("native Store startup") {
                Progress::Advanced => {}
                Progress::Admitted => break,
                other => panic!("native startup did not admit: {other:?}"),
            }
        }
        let core = startup.store().unwrap();
        let identity = Arc::new(BootIdentity::new(core.clone()).unwrap());
        let taken = identity
            .take_node(&format!(
                "shutdown-{}",
                busbar_kernel::door::op_id().counter()
            ))
            .await
            .unwrap();
        let budget = BufferBudget {
            records: capacity,
            bytes: 16 * 1024 * 1024,
        };
        let runtime = RuntimeJournal::open(core.clone(), taken.id, budget)
            .await
            .unwrap();
        let mut book = crate::root::durability::node_book(runtime, budget)
            .await
            .unwrap();
        book.node_lease = taken.lease.map(Arc::new);
        let key = VirtualKey {
            id: format!("vk_shutdown_{}", busbar_kernel::door::op_id().counter()),
            enabled: true,
            ..Default::default()
        };
        core.identity().put_key(&key).await.unwrap();
        let gov = Arc::new(
            GovState::new_with_core(core.clone(), None, None)
                .await
                .unwrap(),
        );
        let day = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now());
        Self {
            seen: Observed {
                backend,
                core,
                journal: book.runtime_journal.clone(),
                gov,
                key,
                day,
                budget,
            },
            startup,
            book,
        }
    }
    pub(super) fn accrue(&self) {
        let seen = &self.seen;
        let cost = CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
        let now = busbar_kernel::store::now();
        let units = [(UNIT_INPUT.to_owned(), INPUT_USED)].into_iter().collect();
        drop(seen.gov.try_admit(&cost, &seen.key, "", now).unwrap());
        seen.gov
            .record_usage(&cost, &seen.key, "", "shutdown-model", &units, now);
        seen.gov.record_lane_metering(
            &seen.key.id,
            "shutdown-model",
            Some("shutdown-provider"),
            &units,
            now,
        );
    }
    /// Attaches the store-backed usage recovery and unit checkpoint sinks over this fixture's own
    /// node journal, as boot does, with a deployment signing key for `unit.accrued`.
    pub(super) async fn attach_sinks(&self) {
        {
            let mut durability = self
                .book
                .durability
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            durability.record = std::mem::take(&mut durability.record)
                .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[0x53; 32]));
        }
        let journal = self.book.runtime_journal.clone();
        self.seen
            .gov
            .attach_recovery_sink(
                crate::root::durability::usage_recovery_sink(journal.clone()).unwrap(),
            )
            .await
            .unwrap();
        self.seen
            .gov
            .attach_unit_checkpoint_sink(
                crate::root::durability::unit_checkpoint_sink(&self.book.durability, journal, None)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(self.seen.gov.unit_checkpoints_enabled());
    }
    /// One governed unit's checkpoint with its captured admission audit facts.
    pub(super) fn unit(&self) -> busbar_kernel::governance::unit_checkpoint::UnitCheckpoint {
        busbar_kernel::Registration::new()
            .key("work")
            .expect("test meter class registered");
        let audit = crate::root::durability::RunningAudit {
            selected_identity: None,
            incarnation: 7,
            principal: self.seen.key.id.clone(),
            op_class: "shutdown.drain".into(),
            origin: "client".into(),
            parent: None,
            wall: 1_700_000_000,
            mono: 91,
            destination: Some("verified-destination".into()),
            rate_card: None,
            policy_epoch: 3,
            hooks: Vec::new(),
        };
        busbar_kernel::governance::unit_checkpoint::UnitCheckpoint {
            id: busbar_kernel::door::op_id().0,
            revision: 0,
            unit: 17,
            principal: self.seen.key.id.clone(),
            group: String::new(),
            arrived: 1_700_000_000,
            lane: format!("shutdown{}lane", busbar_kernel::governance::PLANE_LANE_SEP),
            provider: Some("shutdown".into()),
            era_at: 42,
            era_entry: None,
            units: std::collections::BTreeMap::from([(
                "work".into(),
                busbar_contract::Count::parse("0.125").unwrap(),
            )]),
            targets: vec![busbar_kernel::governance::unit_checkpoint::UnitTarget {
                bucket: self.seen.key.id.clone(),
                window: 0,
                group: None,
            }],
            metered: true,
            ended: false,
            terminal: None,
            audit: Some(serde_json::to_vec(&audit).unwrap()),
            measurement: None,
            unread: None,
            partitions: None,
        }
    }
    pub(super) fn stage(&self, count: usize) {
        let entries: Vec<_> = (0..count)
            .map(|_| Entry::new(RecordClass::Load, vec![7; 24]))
            .collect();
        self.seen.journal.stage_run(&entries).unwrap();
    }
    /// The serve phase's leftovers as `finish` takes them from boot: no listener and no thread,
    /// this fixture's book and Store admission, its governance when `governed`, and the money
    /// driver `flusher`. `lines` stands in for a line server whose input ended.
    pub(super) fn post(
        self,
        governed: bool,
        flusher: Option<JoinHandle<()>>,
        _shutdown_tx: &tokio::sync::broadcast::Sender<()>,
        lines: Option<i32>,
    ) -> (PostServe<'static>, Observed) {
        let Fixture {
            seen,
            startup,
            book,
        } = self;
        let export_observers = crate::root::export_observer::ExportObservers::new();
        let post = PostServe {
            admin: None,
            lines: lines
                .map(|code| Box::pin(async move { code }) as Pin<Box<dyn Future<Output = i32>>>),
            threads: Vec::new(),
            work_recovery: tokio::spawn(async {}),
            generation_workers: crate::root::boot::workers::PreparedWorkers::new().start(),
            exports: crate::root::exports::ports::Exports::new(Vec::new())
                .expect("no configured exports"),
            export_captures: Arc::default(),
            export_observer_retry: ExportRetry::start(Arc::clone(&export_observers)),
            export_observers,
            control_drain: Box::pin(async {}),
            node_lease: None,
            flusher,
            governance: governed.then(|| seen.gov.clone()),
            late: Services::bootstrap(),
            book: Some(book),
            startup,
            predecessor: None,
        };
        (post, seen)
    }
}

/// The money driver [M] as `run` starts it: the flusher in drain mode on the drain's own clock.
pub(super) fn money_driver(
    gov: &Arc<GovState>,
    clock: &Arc<DrainClock>,
    shutdown_tx: &tokio::sync::broadcast::Sender<()>,
) -> JoinHandle<()> {
    tokio::spawn(crate::root::measurements::maintenance(
        busbar_kernel::governance::run_budget_flusher(
            gov.clone(),
            shutdown_tx.subscribe(),
            None,
            Some(Arc::clone(clock)),
        ),
    ))
}

/// `finish` has not returned while `gate` holds its write: still pending 50 ms later.
pub(super) async fn still_running<F: Future<Output = i32>>(finishing: Pin<&mut F>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(50), finishing)
            .await
            .is_err(),
        "the drain joins the owner of the held write"
    );
}

/// Drives `finish` until `gate` is entered; `finish` returning first is a failure.
pub(super) async fn until_entered<F: Future<Output = i32>>(
    mut finishing: Pin<&mut F>,
    gate: &FlushGate,
) {
    tokio::select! {
        biased;
        code = finishing.as_mut() => panic!("finish returned {code} before the held write"),
        () = gate.entered() => {}
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_drain_flushes_the_journal_lane_before_it_retires() {
    let fixture = Fixture::new(16).await;
    fixture.stage(4);
    let gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.journal.lock().unwrap() = Some(gate.clone());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let drain = ShutdownDrain::new(DrainClock::new(ROOMY));
    coordinate_test(&drain, &shutdown_tx);
    let mut finishing = std::pin::pin!(finish(post, &drain));
    until_entered(finishing.as_mut(), &gate).await;
    still_running(finishing.as_mut()).await;
    assert_eq!(seen.journal.pending_records(), 4);
    assert!(seen
        .journal
        .read_records(seen.budget)
        .await
        .unwrap()
        .is_empty());
    gate.release();
    let code = tokio::time::timeout(WAIT, finishing)
        .await
        .expect("the drain returns once the journal write lands");
    assert_eq!(code, 0, "a drained writer retires");
    assert_eq!(seen.journal.pending_records(), 0);
    assert_eq!(
        seen.journal.read_records(seen.budget).await.unwrap().len(),
        4
    );
    assert_eq!(drain.detached(), 0, "nothing was cut");
}

#[tokio::test(flavor = "current_thread")]
async fn the_drain_hands_the_store_every_accepted_original_at_capacity() {
    let fixture = Fixture::new(4).await;
    fixture.stage(4);
    assert!(matches!(
        fixture
            .seen
            .journal
            .stage_run(&[Entry::new(RecordClass::Load, Vec::new())]),
        Err(RuntimeError::Budget)
    ));
    // A rejected reservation is not an acknowledged hidden buffer. All four
    // originals accepted by the native owner must reach their selected head.
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let drain = ShutdownDrain::new(DrainClock::new(ROOMY));
    coordinate_test(&drain, &shutdown_tx);
    let code = tokio::time::timeout(WAIT, finish(post, &drain))
        .await
        .expect("all accepted originals drain");
    assert_eq!(code, 0);
    assert_eq!(
        seen.journal.read_records(seen.budget).await.unwrap().len(),
        4
    );
    assert_eq!(seen.journal.pending_records(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn the_money_driver_lets_the_runtime_progress_and_waits_for_each_store_write() {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    let budget = Arc::new(FlushGate::default());
    let metering = Arc::new(FlushGate::default());
    *fixture.seen.backend.budget.lock().unwrap() = Some(budget.clone());
    *fixture.seen.backend.metering.lock().unwrap() = Some(metering.clone());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let clock = DrainClock::new(ROOMY);
    let flusher = money_driver(&fixture.seen.gov, &clock, &shutdown_tx);
    let (post, seen) = fixture.post(true, Some(flusher), &shutdown_tx, None);
    let drain = ShutdownDrain::new(clock);
    coordinate_test(&drain, &shutdown_tx);
    let mut finishing = std::pin::pin!(finish(post, &drain));
    until_entered(finishing.as_mut(), &budget).await;
    still_running(finishing.as_mut()).await;
    assert_eq!(seen.requests().await, 0);
    assert!(seen.metered().await.is_empty());
    budget.release();
    until_entered(finishing.as_mut(), &metering).await;
    still_running(finishing.as_mut()).await;
    assert_eq!(seen.requests().await, 1);
    assert!(seen.metered().await.is_empty());
    metering.release();
    let code = tokio::time::timeout(WAIT, finishing)
        .await
        .expect("actual accounting drivers drain");
    assert_eq!(code, 0, "the writer retires once every write landed");
    assert!(!seen.gov.has_unsettled_persistence());
    assert_eq!(
        seen.core
            .ledger()
            .get_usage(&seen.key.id, 0)
            .await
            .unwrap()
            .total_input(),
        i128::from(INPUT_USED) * 1_000_000
    );
    assert_eq!(
        seen.metered()
            .await
            .iter()
            .map(|row| row.tokens_input)
            .sum::<i128>(),
        i128::from(INPUT_USED) * 1_000_000
    );
}

/// Uncertain budget and metering writes are reported, never retired over: the exit says spend
/// is unsaved (70), the writer stays admitted for exact reconciliation, and nothing is dropped.
#[tokio::test(flavor = "current_thread")]
async fn the_drain_reports_uncertain_budget_and_metering_writes_and_does_not_retire() {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    fixture
        .seen
        .backend
        .fail_accounting
        .store(true, Ordering::Release);
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    // A short budget: the settle wait is cut at C2 because the writes never land.
    let clock = DrainClock::new(Duration::from_secs(2));
    let flusher = money_driver(&fixture.seen.gov, &clock, &shutdown_tx);
    let (post, seen) = fixture.post(true, Some(flusher), &shutdown_tx, None);
    let drain = ShutdownDrain::new(clock);
    coordinate_test(&drain, &shutdown_tx);
    let code = tokio::time::timeout(WAIT, finish(post, &drain))
        .await
        .expect("the drain ends by its own cuts, before the deadline");
    assert_eq!(
        code, 70,
        "no clean-drain proof exists after uncertain native writes: spend unsaved"
    );
    assert!(seen.gov.has_unsettled_persistence());
    assert_eq!(seen.requests().await, 0);
    assert!(seen.metered().await.is_empty());
    seen.still_admitted().await;
}

/// A money driver that panics mid-write is replaced by the fallback; metering and the journal
/// still drain, nothing is aborted, and the writer is not retired.
#[tokio::test(flavor = "current_thread")]
async fn a_panicking_money_driver_is_reported_and_metering_and_journal_still_drain() {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    fixture.stage(1);
    fixture
        .seen
        .backend
        .panic_budget
        .store(true, Ordering::Release);
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let clock = DrainClock::new(Duration::from_secs(4));
    let flusher = money_driver(&fixture.seen.gov, &clock, &shutdown_tx);
    let (post, seen) = fixture.post(true, Some(flusher), &shutdown_tx, None);
    let drain = ShutdownDrain::new(clock);
    coordinate_test(&drain, &shutdown_tx);
    let code = tokio::time::timeout(Duration::from_secs(10), finish(post, &drain))
        .await
        .expect("the drain ends by its own cuts");
    assert!(
        code == 70 || code == 75,
        "a failed driver cannot yield retirement proof; never 1: {code}"
    );
    assert_eq!(
        seen.metered()
            .await
            .iter()
            .map(|row| row.tokens_input)
            .sum::<i128>(),
        i128::from(INPUT_USED) * 1_000_000,
        "the fallback's final metering flush ran"
    );
    assert_eq!(seen.journal.pending_records(), 0);
    assert_eq!(
        seen.journal.read_records(seen.budget).await.unwrap().len(),
        1
    );
    seen.still_admitted().await;
}

async fn the_money_driver_finishes_before_journal_retirement(signal_first: bool) {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    let gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.budget.lock().unwrap() = Some(gate.clone());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let clock = DrainClock::new(ROOMY);
    let flusher = money_driver(&fixture.seen.gov, &clock, &shutdown_tx);
    // A signal before the drain owner runs, or the line server's input ending (its code 0).
    let lines = (!signal_first).then_some(0);
    let (post, seen) = fixture.post(true, Some(flusher), &shutdown_tx, lines);
    if signal_first {
        shutdown_tx.send(()).unwrap();
        gate.entered().await;
    }
    let drain = ShutdownDrain::new(clock);
    coordinate_test(&drain, &shutdown_tx);
    let mut finishing = std::pin::pin!(finish(post, &drain));
    if !signal_first {
        until_entered(finishing.as_mut(), &gate).await;
    }
    still_running(finishing.as_mut()).await;
    assert_eq!(seen.requests().await, 0);
    assert!(
        seen.journal.refuses_money().is_none(),
        "staging stays open while accounting is active"
    );
    gate.release();
    let code = tokio::time::timeout(WAIT, finishing)
        .await
        .expect("periodic owner joined and final queues drained");
    assert_eq!(code, 0, "the drained writer retires");
    assert_eq!(seen.requests().await, 1);
    assert!(!seen.metered().await.is_empty());
    assert!(
        seen.journal.refuses_money().is_some(),
        "the final drain closes staging"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_joins_inflight_background_accounting_before_retiring_journal() {
    the_money_driver_finishes_before_journal_retirement(true).await;
}
#[tokio::test(flavor = "current_thread")]
async fn line_eof_stops_and_joins_background_accounting_before_retiring_journal() {
    the_money_driver_finishes_before_journal_retirement(false).await;
}

/// Real shutdown coordinator for native settlement tests, without a process-global refresher.
pub(super) fn coordinate_test(
    drain: &ShutdownDrain,
    listeners: &tokio::sync::broadcast::Sender<()>,
) {
    let (workers, safety) = tokio::sync::watch::channel(false);
    drain.start_deregister_with(
        Duration::ZERO,
        Arc::new(busbar_kernel::endpoints::ProbeState::new(None)),
        ShutdownSignals {
            safety,
            support: workers.clone(),
            workers,
            listeners: listeners.clone(),
        },
        || {},
    );
}
