// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Notify, Semaphore};

const WAIT: std::time::Duration = std::time::Duration::from_secs(5);
const INPUT_USED: u64 = 17;

struct FlushGate {
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
    fn release(&self) {
        self.released.add_permits(1);
    }
    async fn entered(&self) {
        tokio::time::timeout(WAIT, self.entered.notified())
            .await
            .expect("actual native commit reached the gate");
    }
}

/// Faults intercept the real product's primitive commit. Key/ledger/journal
/// encoding, guarded mutation planning, and retained attempts stay in CoreStore.
struct FlushBackend {
    inner: Arc<dyn PersistenceBackend>,
    budget: Mutex<Option<Arc<FlushGate>>>,
    metering: Mutex<Option<Arc<FlushGate>>>,
    journal: Mutex<Option<Arc<FlushGate>>>,
    fail_accounting: AtomicBool,
    panic_budget: AtomicBool,
}
impl PersistenceBackend for FlushBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
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
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let is = |prefix: &[u8]| {
                candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put {address,..} if address.key.starts_with(prefix))
            })
            };
            let budget = is(b"U");
            let metering = is(b"M");
            let journal = is(b"busbar.journal4\0");
            let gate = if budget {
                self.budget.lock().unwrap().take()
            } else if metering {
                self.metering.lock().unwrap().take()
            } else if journal {
                self.journal.lock().unwrap().take()
            } else {
                None
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
            self.inner.commit(candidate).await
        })
    }
}

struct Fixture {
    backend: Arc<FlushBackend>,
    startup: Startup,
    core: Arc<CoreStore>,
    book: crate::root::durability::NodeBook,
    gov: Arc<GovState>,
    key: VirtualKey,
    day: u64,
    budget: BufferBudget,
}
impl Fixture {
    async fn new(capacity: usize) -> Self {
        let backend = Arc::new(FlushBackend {
            inner: crate::root::real_store::native_backend().await,
            budget: Mutex::new(None),
            metering: Mutex::new(None),
            journal: Mutex::new(None),
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
            backend,
            startup,
            core,
            book,
            gov,
            key,
            day,
            budget,
        }
    }
    fn accrue(&self) {
        let cost = CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
        let now = busbar_kernel::store::now();
        let units = [(UNIT_INPUT.to_owned(), INPUT_USED)].into_iter().collect();
        self.gov.try_admit(&cost, &self.key, "", now).unwrap();
        self.gov
            .record_usage(&cost, &self.key, "", "shutdown-model", &units, now);
        self.gov.record_lane_metering(
            &self.key.id,
            "shutdown-model",
            Some("shutdown-provider"),
            &units,
            now,
        );
    }
    fn stage(&self, count: usize) {
        let entries: Vec<_> = (0..count)
            .map(|_| Entry::new(RecordClass::Load, vec![7; 24]))
            .collect();
        self.book.runtime_journal.stage_run(&entries).unwrap();
    }
    async fn requests(&self) -> u64 {
        self.core
            .ledger()
            .get_usage(&self.key.id, 0)
            .await
            .unwrap()
            .requests
    }
    async fn metered(&self) -> Vec<busbar_contract::records::MeteringRow> {
        self.core.ledger().list_metering(self.day).await.unwrap()
    }
    async fn retire(&mut self, drained: Drained) {
        retire_storage(&mut self.startup, Some(&self.book), drained)
            .await
            .expect("drained native writer retires");
        assert!(self.startup.store().is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_shutdown_tail_drains_the_journal_lane_before_it_returns() {
    let mut fixture = Fixture::new(16).await;
    fixture.stage(4);
    let gate = Arc::new(FlushGate::default());
    *fixture.backend.journal.lock().unwrap() = Some(gate.clone());
    let book = fixture.book.durability.clone();
    let task = tokio::spawn(async move { tail(None, &LateServices::new(), Some(&book)).await });
    gate.entered().await;
    assert!(!task.is_finished());
    assert_eq!(fixture.book.runtime_journal.pending_records(), 4);
    assert!(fixture
        .book
        .runtime_journal
        .read_records(fixture.budget)
        .await
        .unwrap()
        .is_empty());
    gate.release();
    let drained = tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .expect("journal queue drained");
    assert_eq!(fixture.book.runtime_journal.pending_records(), 0);
    assert_eq!(
        fixture
            .book
            .runtime_journal
            .read_records(fixture.budget)
            .await
            .unwrap()
            .len(),
        4
    );
    fixture.retire(drained).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_shutdown_tail_hands_the_store_every_accepted_original_at_capacity() {
    let mut fixture = Fixture::new(4).await;
    fixture.stage(4);
    assert!(matches!(
        fixture
            .book
            .runtime_journal
            .stage_run(&[Entry::new(RecordClass::Load, Vec::new())]),
        Err(RuntimeError::Budget)
    ));
    // A rejected reservation is not an acknowledged hidden buffer. All four
    // originals accepted by the native owner must reach their selected head.
    let drained = tail(None, &LateServices::new(), Some(&fixture.book.durability))
        .await
        .expect("all accepted originals drain");
    assert_eq!(
        fixture
            .book
            .runtime_journal
            .read_records(fixture.budget)
            .await
            .unwrap()
            .len(),
        4
    );
    assert_eq!(fixture.book.runtime_journal.pending_records(), 0);
    fixture.retire(drained).await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_flushes_allow_runtime_progress_and_wait_for_each_store_write() {
    let mut fixture = Fixture::new(16).await;
    fixture.accrue();
    let budget = Arc::new(FlushGate::default());
    let metering = Arc::new(FlushGate::default());
    *fixture.backend.budget.lock().unwrap() = Some(budget.clone());
    *fixture.backend.metering.lock().unwrap() = Some(metering.clone());
    let gov = fixture.gov.clone();
    let book = fixture.book.durability.clone();
    let task =
        tokio::spawn(async move { tail(Some(gov), &LateServices::new(), Some(&book)).await });
    budget.entered().await;
    assert!(!task.is_finished());
    assert_eq!(fixture.requests().await, 0);
    assert!(fixture.metered().await.is_empty());
    budget.release();
    metering.entered().await;
    assert!(!task.is_finished());
    assert_eq!(fixture.requests().await, 1);
    assert!(fixture.metered().await.is_empty());
    metering.release();
    let drained = tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .expect("actual accounting drivers drain");
    assert!(!fixture.gov.has_unsettled_persistence());
    assert_eq!(
        fixture
            .core
            .ledger()
            .get_usage(&fixture.key.id, 0)
            .await
            .unwrap()
            .total_input(),
        i128::from(INPUT_USED) * 1_000_000
    );
    assert_eq!(
        fixture
            .metered()
            .await
            .iter()
            .map(|row| row.tokens_input)
            .sum::<i128>(),
        i128::from(INPUT_USED) * 1_000_000
    );
    fixture.retire(drained).await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_tail_reports_terminal_budget_and_metering_store_failures() {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    fixture
        .backend
        .fail_accounting
        .store(true, Ordering::Release);
    let result = tail(
        Some(fixture.gov.clone()),
        &LateServices::new(),
        Some(&fixture.book.durability),
    )
    .await;
    assert!(
        result.is_err(),
        "no clean-drain proof exists after uncertain native writes"
    );
    assert!(fixture.gov.has_unsettled_persistence());
    assert_eq!(fixture.requests().await, 0);
    assert!(fixture.metered().await.is_empty());
    assert!(
        fixture.startup.store().is_some(),
        "failure does not enter writer retirement"
    );
    fixture
        .core
        .identity()
        .put_key(&VirtualKey {
            id: "writer-remains-admitted".into(),
            enabled: true,
            ..Default::default()
        })
        .await
        .expect("native authority remains admitted for exact reconciliation");
}

#[tokio::test(flavor = "current_thread")]
async fn a_panicking_budget_flush_is_reported_and_metering_and_journal_still_drain() {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    fixture.stage(1);
    fixture.backend.panic_budget.store(true, Ordering::Release);
    let result = tail(
        Some(fixture.gov.clone()),
        &LateServices::new(),
        Some(&fixture.book.durability),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("a failed driver cannot yield retirement proof"),
        Err(error) => error,
    };
    assert!(error.contains("budget final driver failed"));
    assert_eq!(
        fixture
            .metered()
            .await
            .iter()
            .map(|row| row.tokens_input)
            .sum::<i128>(),
        i128::from(INPUT_USED) * 1_000_000
    );
    assert_eq!(fixture.book.runtime_journal.pending_records(), 0);
    assert_eq!(
        fixture
            .book
            .runtime_journal
            .read_records(fixture.budget)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(fixture.gov.has_unsettled_persistence());
    assert!(fixture.startup.store().is_some());
}

async fn background_flusher_finishes_before_journal_retirement(signal_first: bool) {
    let mut fixture = Fixture::new(16).await;
    fixture.accrue();
    let gate = Arc::new(FlushGate::default());
    *fixture.backend.budget.lock().unwrap() = Some(gate.clone());
    let (shutdown, receiver) = tokio::sync::broadcast::channel(1);
    let flusher =
        busbar_kernel::governance::spawn_budget_flusher(fixture.gov.clone(), receiver, None);
    if signal_first {
        shutdown.send(()).unwrap();
        gate.entered().await;
    }
    let gov = fixture.gov.clone();
    let book = fixture.book.durability.clone();
    let task = tokio::spawn(async move {
        tail_after_flusher(
            Some(gov),
            &LateServices::new(),
            Some(&book),
            &shutdown,
            Some(flusher),
        )
        .await
    });
    if !signal_first {
        gate.entered().await;
    }
    assert!(
        !task.is_finished(),
        "shutdown joins the owner of the dirty cell"
    );
    assert_eq!(fixture.requests().await, 0);
    assert!(
        fixture.book.runtime_journal.refuses_money().is_none(),
        "staging stays open while accounting is active"
    );
    gate.release();
    let drained = tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .expect("periodic owner joined and final queues drained");
    assert_eq!(fixture.requests().await, 1);
    assert!(!fixture.metered().await.is_empty());
    assert!(
        fixture.book.runtime_journal.refuses_money().is_some(),
        "final drain closes staging"
    );
    assert!(
        fixture.startup.store().is_some(),
        "native retirement requires the drain proof explicitly"
    );
    fixture.retire(drained).await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_joins_inflight_background_accounting_before_retiring_journal() {
    background_flusher_finishes_before_journal_retirement(true).await;
}
#[tokio::test(flavor = "current_thread")]
async fn line_eof_stops_and_joins_background_accounting_before_retiring_journal() {
    background_flusher_finishes_before_journal_retirement(false).await;
}
