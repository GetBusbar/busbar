// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE SHUTDOWN TAIL (audit busbar-src #1; ruling H2 U10; BUSBAR-1.6.0.md THE DESIGN, §7): it
//! returns only once the journal records queued for the configured store have reached it, and both
//! of the process's tails — the listener path's and the line-serve mode's — are this one function.

use busbar_contract::caps::{DurableWrite, StepName};
use busbar_contract::records::{
    MeteringDelta, MeteringRow, RecordStore, RecordStoreError, RecordStoreResult, UsageDelta,
    UsageLedger, VirtualKey, UNIT_INPUT,
};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::metering_bucket;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use busbar_kernel_wal::{Entry, Record, RecordClass};

use super::*;
use crate::root::durability::{build_on_store, read_chain, DurabilityConfig, JournalLane};
use crate::root::store_double::RecordSlots;

/// The node the test book is built as.
const NODE: u64 = 31;

/// How long the store refuses before it recovers: long enough that a tail which does not wait has
/// returned well before, short enough to sit far inside [`RECORD_DRAIN`].
const OUTAGE: std::time::Duration = std::time::Duration::from_millis(300);

/// How long a test waits on the lane outside the tail.
const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A book over `slots` with no data directory (the production boot's shape for a child process
/// with no disk), and a handle on the same lane its journal ships through.
fn store_book(slots: &RecordSlots) -> (Arc<Mutex<Durability>>, JournalLane) {
    store_book_bounded(slots, busbar_kernel_wal::MEMORY_BUFFER_RECORDS)
}

/// [`store_book`], its lane to the store bounded at `capacity` records.
fn store_book_bounded(
    slots: &RecordSlots,
    capacity: usize,
) -> (Arc<Mutex<Durability>>, JournalLane) {
    let lane =
        JournalLane::with_capacity(slots.calls(), "test-store", capacity).expect("the lane starts");
    let durability = build_on_store(
        &DurabilityConfig { data_dir: None },
        NODE,
        lane.clone(),
        None,
    )
    .expect("the store reads back");
    (Arc::new(Mutex::new(durability)), lane)
}

/// **THE SHUTDOWN TAIL DRAINS THE JOURNAL'S LANE BEFORE IT RETURNS.** Journal records wait in the
/// lane while the store refuses; the store recovers a moment into the tail. The tail returns only
/// once the store took every one of them, so the process that exits right after it (the line-serve
/// mode's `std::process::exit`) leaves nothing queued.
///
/// RED before the fix: there was no shared tail (`root::shutdown` did not exist), and the line-serve
/// mode's own tail flushed the budget and metering write-behind and exited, never touching the
/// lane: the records it held at stdin EOF were lost with the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_shutdown_tail_drains_the_journal_lane_before_it_returns() {
    let slots = RecordSlots::new();
    let (book, lane) = store_book(&slots);
    slots.refuse(true);
    let before = slots.puts();
    let queued: Vec<Record> = (1..=4)
        .map(|seq| Record::new(NODE + 1, seq, vec![7u8; 24]))
        .collect();
    lane.shipper()
        .ship(&queued)
        .expect("a refusing store does not refuse the hand-off: the lane has room");
    assert!(lane.pending() > 0, "the records wait for the store");

    let recovers = {
        let slots = slots.clone();
        std::thread::spawn(move || {
            std::thread::sleep(OUTAGE);
            slots.refuse(false);
        })
    };
    let late = LateServices::new();
    tail(None, &late, Some(&book)).await;

    assert_eq!(
        lane.pending(),
        0,
        "the tail returned with journal records still queued for the store"
    );
    assert!(
        slots.puts() >= before + queued.len(),
        "every queued record reached the store before the tail returned"
    );
    recovers.join().expect("the recovery thread");
}

/// **THE SHUTDOWN TAIL HANDS THE STORE WHAT THE JOURNAL HELD BACK, TOO** (audit root r4 B-6;
/// BUSBAR-1.6.0.md THE DESIGN §7, l.991-998: the kernel writes exactly what it is told, one sealed
/// line per unit; `root::shutdown`'s docs: what the caller was answered for has to reach the store
/// before the process is gone). The lane is full while the store refuses, so the journal's last
/// records were turned away and are retained by the journal, outside the lane. The store recovers a
/// moment into the tail. The tail returns only once those records reached the store as well.
///
/// RED before the fix: the tail drained only the lane's queue and never re-offered the journal's
/// retained batch, so the process exited with settled records the store never saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_shutdown_tail_hands_the_store_what_the_journal_held_back() {
    let slots = RecordSlots::new();
    let (book, lane) = store_book_bounded(&slots, 4);
    assert!(lane.drain(WAIT), "the boot's records reach the store");
    slots.refuse(true);
    let token = busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>();
    let written = {
        let mut durability = book.lock().expect("the book");
        // Past the lane's bound: the lane holds four, the journal retains the rest.
        for _ in 0..6 {
            let _ = durability.journal.append(
                &token,
                StepName::Meter,
                &[Entry::new(RecordClass::Load, Vec::new())],
            );
        }
        assert!(
            durability.journal.buffered() > 0,
            "the journal holds back what the full lane turned away"
        );
        durability.journal.next_seq() - 1
    };

    let recovers = {
        let slots = slots.clone();
        std::thread::spawn(move || {
            std::thread::sleep(OUTAGE);
            slots.refuse(false);
        })
    };
    let late = LateServices::new();
    tail(None, &late, Some(&book)).await;

    assert_eq!(
        book.lock().expect("the book").journal.buffered(),
        0,
        "the tail returned with records the journal still held back from the store"
    );
    assert_eq!(lane.pending(), 0, "the tail returned with records queued");
    assert_eq!(
        read_chain(slots.calls().as_ref(), NODE)
            .expect("the store reads back")
            .len() as u64,
        written,
        "every record the journal sealed reached the store before the tail returned"
    );
    recovers.join().expect("the recovery thread");
}

const SHUTDOWN_KEY: &str = "vk_shutdown_tail";
const SHUTDOWN_MODEL: &str = "shutdown-model";
const SHUTDOWN_PROVIDER: &str = "shutdown-provider";
const INPUT_USED: u64 = 17;
const STORE_DOWN: &str = "the shutdown test store is unavailable";

/// A store write requires the single-threaded runtime to release it. The fixture watchdog only
/// unhangs a broken inline tail; assertions inspect the write results after all gates are released.
#[derive(Default)]
struct FlushGate {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    changed: std::sync::Condvar,
    timed_out: std::sync::atomic::AtomicBool,
}

impl FlushGate {
    fn wait(&self) -> RecordStoreResult<()> {
        self.entered.notify_one();
        let (released, _) = self
            .changed
            .wait_timeout_while(self.released.lock().expect("gate lock"), WAIT, |open| {
                !*open
            })
            .expect("gate wait");
        if !*released {
            self.timed_out
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(RecordStoreError(
                "runtime did not release the store write".into(),
            ));
        }
        Ok(())
    }

    fn release(&self) {
        *self.released.lock().expect("gate lock") = true;
        self.changed.notify_all();
    }
}

#[derive(Clone, Copy)]
enum FlushOutcome {
    Commit,
    Fail,
    PanicBudget,
}

/// The real governance store seam, delegating persistence/readback to the shared memory double.
/// It keeps legacy-store behavior, so these controls also cover stores without deduped batches.
struct FlushStore {
    inner: MemoryStore,
    budget: Option<Arc<FlushGate>>,
    metering: Option<Arc<FlushGate>>,
    outcome: FlushOutcome,
}

impl FlushStore {
    fn new(outcome: FlushOutcome) -> Self {
        Self {
            inner: MemoryStore::new(),
            budget: None,
            metering: None,
            outcome,
        }
    }
}

impl RecordStore for FlushStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket, window)
    }
    fn put_usage(&self, bucket: &str, window: u64, ledger: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket, window, ledger)
    }
    fn add_usage(&self, bucket: &str, window: u64, delta: &UsageDelta) -> RecordStoreResult<()> {
        if let Some(gate) = &self.budget {
            gate.wait()?;
        }
        match self.outcome {
            FlushOutcome::Fail => Err(RecordStoreError(STORE_DOWN.into())),
            FlushOutcome::PanicBudget => panic!("planted budget store panic"),
            FlushOutcome::Commit => self.inner.add_usage(bucket, window, delta),
        }
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        if let Some(gate) = &self.metering {
            gate.wait()?;
        }
        match self.outcome {
            FlushOutcome::Fail => Err(RecordStoreError(STORE_DOWN.into())),
            FlushOutcome::Commit | FlushOutcome::PanicBudget => self.inner.add_metering(delta),
        }
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

fn accrued_governance(store: Arc<FlushStore>) -> (Arc<GovState>, u64) {
    let key = VirtualKey {
        id: SHUTDOWN_KEY.into(),
        name: SHUTDOWN_KEY.into(),
        enabled: true,
        ..Default::default()
    };
    store.put_key(&key).expect("key persists before the outage");
    let gov = Arc::new(GovState::new(store, None).expect("governance boots"));
    let cost = CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    let now = busbar_kernel::store::now();
    let units = [(UNIT_INPUT.to_owned(), INPUT_USED)].into_iter().collect();
    gov.try_admit(&cost, &key, "", now).expect("request admits");
    gov.record_usage(&cost, &key, "", SHUTDOWN_MODEL, &units, now);
    gov.record_lane_metering(
        SHUTDOWN_KEY,
        SHUTDOWN_MODEL,
        Some(SHUTDOWN_PROVIDER),
        &units,
        now,
    );
    (gov, metering_bucket(now))
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_flushes_allow_runtime_progress_and_wait_for_each_store_write() {
    let budget = Arc::new(FlushGate::default());
    let metering = Arc::new(FlushGate::default());
    let store = Arc::new(FlushStore {
        budget: Some(budget.clone()),
        metering: Some(metering.clone()),
        ..FlushStore::new(FlushOutcome::Commit)
    });
    let (gov, bucket) = accrued_governance(store.clone());
    let task = tokio::spawn(async move { tail(Some(gov), &LateServices::new(), None).await });

    let budget_entered = tokio::time::timeout(WAIT, budget.entered.notified())
        .await
        .is_ok();
    let waiting_for_budget = !task.is_finished();
    let before_budget = store.get_usage(SHUTDOWN_KEY, 0).expect("usage reads");
    let before_metering = store.list_metering(bucket).expect("metering reads");
    budget.release();
    let metering_entered = tokio::time::timeout(WAIT, metering.entered.notified())
        .await
        .is_ok();
    let waiting_for_metering = !task.is_finished();
    let budget_at_metering = store.get_usage(SHUTDOWN_KEY, 0).expect("usage reads");
    let metering_before_return = store.list_metering(bucket).expect("metering reads");
    metering.release();
    tokio::time::timeout(WAIT, task)
        .await
        .expect("tail completes")
        .expect("tail joins");

    assert!(
        budget_entered && metering_entered,
        "both real store writes ran"
    );
    assert!(
        waiting_for_budget && waiting_for_metering,
        "tail waits for each store write"
    );
    assert_eq!(
        before_budget.requests, 0,
        "the gated budget write has not landed"
    );
    assert!(
        before_metering.is_empty(),
        "metering follows the completed budget flush"
    );
    assert_eq!(
        budget_at_metering.requests, 1,
        "budget completes before metering starts"
    );
    assert!(
        metering_before_return.is_empty(),
        "the gated metering write has not landed"
    );
    assert_eq!(
        store
            .get_usage(SHUTDOWN_KEY, 0)
            .expect("usage reads")
            .total_input(),
        INPUT_USED
    );
    let rows = store.list_metering(bucket).expect("metering reads");
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).sum::<u64>(),
        INPUT_USED
    );
    assert!(!budget.timed_out.load(std::sync::atomic::Ordering::Acquire));
    assert!(!metering
        .timed_out
        .load(std::sync::atomic::Ordering::Acquire));
}

#[test]
fn shutdown_tail_reports_terminal_budget_and_metering_store_failures() {
    use busbar_kernel_testkit::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    let store = Arc::new(FlushStore::new(FlushOutcome::Fail));
    let (gov, bucket) = accrued_governance(store.clone());
    let captured = WarnCapture::default();
    tracing::subscriber::with_default(
        tracing_subscriber::registry().with(captured.clone()),
        || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(tail(Some(gov), &LateServices::new(), None));
        },
    );
    let lines = captured.messages();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("shutdown budget flush:") && line.contains(SHUTDOWN_KEY)),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("shutdown metering flush:") && line.contains(SHUTDOWN_KEY)),
        "{lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("will retry next tick")),
        "{lines:?}"
    );
    assert_eq!(
        store
            .get_usage(SHUTDOWN_KEY, 0)
            .expect("usage reads")
            .requests,
        0
    );
    assert!(store
        .list_metering(bucket)
        .expect("metering reads")
        .is_empty());
}

#[test]
fn a_panicking_budget_flush_is_logged_and_metering_and_journal_still_drain() {
    use busbar_kernel_testkit::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    let store = Arc::new(FlushStore::new(FlushOutcome::PanicBudget));
    let (gov, bucket) = accrued_governance(store.clone());
    let slots = RecordSlots::new();
    let (book, lane) = store_book(&slots);
    let queued = Record::new(NODE + 1, 1, vec![7u8; 24]);
    lane.shipper()
        .ship(&[queued])
        .expect("journal record queues");
    let captured = WarnCapture::default();
    tracing::subscriber::with_default(
        tracing_subscriber::registry().with(captured.clone()),
        || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async { tail(Some(gov), &LateServices::new(), Some(&book)).await });
        },
    );
    assert!(
        captured.contains("budget shutdown flush task failed"),
        "{:?}",
        captured.messages()
    );
    assert_eq!(
        store
            .list_metering(bucket)
            .expect("metering reads")
            .iter()
            .map(|row| row.tokens_input)
            .sum::<u64>(),
        INPUT_USED
    );
    assert_eq!(
        lane.pending(),
        0,
        "journal retirement follows the failed budget task"
    );
    assert_eq!(
        read_chain(slots.calls().as_ref(), NODE + 1)
            .expect("journal reads")
            .len(),
        1
    );
}
