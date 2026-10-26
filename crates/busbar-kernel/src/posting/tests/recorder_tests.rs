// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The recorder against a ledger double and a store double that dedupes op ids (rule S3) and can
//! delay, commit-then-fail, refuse a bucket, or be down (MONEY-DESIGN §3c; PR-B tests).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize};

use super::*;
use crate::posting::TmpDir;

/// The ledger double: deltas emitted by "requests", taken by the writer.
#[derive(Default)]
struct Book {
    pending: Mutex<Vec<CellCount>>,
    landed: Mutex<Vec<CellCount>>,
    unposted: Mutex<Vec<CellCount>>,
}

impl Book {
    fn emit(&self, bucket: &str, window: u64, requests: i64) {
        let mut c = CellCount::new(bucket, window);
        c.requests = requests;
        c.add_billable("", requests);
        self.pending.lock().unwrap().push(c);
    }
}

impl Ledger for Book {
    fn take_pending(&self, mark: &dyn Fn(&str)) -> Vec<CellCount> {
        let taken = std::mem::take(&mut *self.pending.lock().unwrap());
        for c in &taken {
            mark(&c.bucket);
        }
        taken
    }
    fn take_metering(&self) -> Vec<MeteringDelta> {
        Vec::new()
    }
    fn landed(&self, cells: &[CellCount]) {
        self.landed.lock().unwrap().extend_from_slice(cells);
    }
    fn unposted(&self, cells: &[CellCount]) {
        self.unposted.lock().unwrap().extend_from_slice(cells);
    }
    fn reposted(&self, _cells: &[CellCount]) {}
}

/// How the store double answers.
#[derive(Default)]
struct Modes {
    /// Every batch call waits this long.
    delay: Mutex<Duration>,
    /// The store is down: nothing commits, the call faults.
    down: AtomicBool,
    /// Commit, then answer FAILED (a lost reply), this many more times.
    commit_then_fail: AtomicUsize,
    /// Refuse (before commit) any usage batch carrying this bucket.
    poison: Mutex<Option<String>>,
}

/// The store double: plain rows summed per (bucket, window); applied op ids deduped.
#[derive(Default)]
struct Store {
    modes: Modes,
    rows: Mutex<BTreeMap<(String, u64), (i64, i64)>>,
    ops: Mutex<HashMap<Op, String>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    calls: AtomicUsize,
}

impl Store {
    fn row(&self, bucket: &str, window: u64) -> (i64, i64) {
        self.rows
            .lock()
            .unwrap()
            .get(&(bucket.to_string(), window))
            .copied()
            .unwrap_or_default()
    }
}

impl PostStore for Store {
    fn add_usage_batch<'a>(
        &'a self,
        op: Op,
        cells: &'a [(String, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            let delay = *self.modes.delay.lock().unwrap();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if self.modes.down.load(Ordering::SeqCst) {
                return Err(StoreFailure::Fault("down".into()));
            }
            if let Some(p) = self.modes.poison.lock().unwrap().as_ref() {
                if cells.iter().any(|(b, _, _)| b == p) {
                    return Err(StoreFailure::Refused("unstorable cell".into()));
                }
            }
            let body = format!("{cells:?}");
            {
                let mut ops = self.ops.lock().unwrap();
                match ops.get(&op) {
                    Some(b) if *b == body => return Ok(()),
                    Some(_) => return Err(StoreFailure::Conflict),
                    None => {
                        ops.insert(op, body);
                    }
                }
            }
            let mut rows = self.rows.lock().unwrap();
            for (b, w, d) in cells {
                if b.starts_with("e:") {
                    continue;
                }
                let r = rows.entry((b.clone(), *w)).or_default();
                r.0 += d.requests;
                r.1 += d.billable_requests;
            }
            drop(rows);
            if self
                .modes
                .commit_then_fail
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(StoreFailure::Failed("the reply was lost".into()));
            }
            Ok(())
        })
    }
    fn add_metering_batch<'a>(&'a self, _op: Op, _rows: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn heartbeat(&self) -> StoreCall<'_, ()> {
        Box::pin(async move {
            if self.modes.down.load(Ordering::SeqCst) {
                Err(StoreFailure::Fault("down".into()))
            } else {
                Ok(())
            }
        })
    }
    fn get_usage<'a>(&'a self, _b: &'a str, _w: u64) -> StoreCall<'a, UsageLedger> {
        Box::pin(async { Ok(UsageLedger::default()) })
    }
}

const W: Duration = Duration::from_millis(20);

fn open(book: &Arc<Book>, store: &Arc<Store>, medium: &Medium) -> (Arc<Recorder>, Recovered) {
    Recorder::open(
        Arc::clone(book) as Arc<dyn Ledger>,
        Arc::clone(store) as Arc<dyn PostStore>,
        medium,
        false,
        W,
        Arc::new(spool::DataSync),
    )
    .expect("recorder opens")
}

async fn settle(rec: &Recorder, until: Duration) -> bool {
    rec.drain(true, until).await
}

/// T4: N concurrent settlements while the store delays every batch by D. No settlement waits on
/// the store (emitting is an in-memory push), and the writer carries them in ONE batch at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t4_concurrent_settlements_never_wait_on_the_store_and_go_one_batch_at_a_time() {
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    let d = Duration::from_millis(300);
    *store.modes.delay.lock().unwrap() = d;
    let (rec, _) = open(&book, &store, &Medium::Memory);
    rec.spawn();
    let started = std::time::Instant::now();
    let mut joins = Vec::new();
    for i in 0..16u64 {
        let book = Arc::clone(&book);
        joins.push(tokio::spawn(async move {
            let t = std::time::Instant::now();
            book.emit(&format!("k{i}"), 0, 1);
            t.elapsed()
        }));
    }
    for j in joins {
        let waited = j.await.unwrap();
        assert!(
            waited < d / 10,
            "a settlement waited on the store: {waited:?}"
        );
    }
    assert!(settle(&rec, Duration::from_secs(10)).await);
    assert!(
        started.elapsed() < d * 3,
        "16 settlements took {:?}",
        started.elapsed()
    );
    assert_eq!(
        store.max_in_flight.load(Ordering::SeqCst),
        1,
        "one batch in flight"
    );
    assert!(
        store.calls.load(Ordering::SeqCst) <= 2,
        "coalesced into at most 2 batches"
    );
    for i in 0..16u64 {
        assert_eq!(store.row(&format!("k{i}"), 0), (1, 1));
    }
    rec.stop().await;
}

/// T9: a store that commits and answers FAILED (a lost reply), twice: the batch is replayed under
/// the SAME op id and counted exactly once.
#[tokio::test]
async fn t9_commit_then_failed_is_replayed_under_the_same_op_and_counted_once() {
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    store.modes.commit_then_fail.store(2, Ordering::SeqCst);
    let (rec, _) = open(&book, &store, &Medium::Memory);
    book.emit("k", 0, 3);
    assert!(settle(&rec, Duration::from_secs(10)).await);
    assert_eq!(
        store.row("k", 0),
        (3, 3),
        "exactly once after two lost replies"
    );
    assert!(rec.dead_letters().is_empty());
    rec.stop().await;
}

/// T3 and T27: the store down in default mode: deltas accumulate, nothing is dead-lettered however
/// long the outage, and once it returns everything is recorded exactly once.
#[tokio::test]
async fn t3_t27_an_outage_accumulates_and_is_recorded_once_without_dead_letters() {
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    store.modes.down.store(true, Ordering::SeqCst);
    let (rec, _) = open(&book, &store, &Medium::Memory);
    book.emit("k", 0, 1);
    assert!(
        !settle(&rec, Duration::from_millis(300)).await,
        "nothing lands while down"
    );
    book.emit("k", 0, 2);
    // A first failure far in the past: while the heartbeat FAILS it never counts (T27).
    for op in rec.lock().failing.values_mut() {
        *op = 0;
    }
    rec.beat().await; // fails: the store is down
    assert!(!settle(&rec, Duration::from_millis(300)).await);
    assert!(
        rec.dead_letters().is_empty(),
        "an outage is never dead-lettered"
    );
    store.modes.down.store(false, Ordering::SeqCst);
    rec.beat().await; // fail→succeed: the first-failure clock restarts now
    assert!(settle(&rec, Duration::from_secs(10)).await);
    assert_eq!(store.row("k", 0), (3, 3));
    assert!(rec.dead_letters().is_empty());
    rec.stop().await;
}

/// T25 and T3b: a REFUSED cell is found by bisecting the refused op, dead-lettered ALONE, and every
/// other cell of the batch is recorded.
#[tokio::test]
async fn t25_t3b_a_refused_cell_is_bisected_out_and_dead_lettered_alone() {
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    *store.modes.poison.lock().unwrap() = Some("bad".into());
    let (rec, _) = open(&book, &store, &Medium::Memory);
    for b in ["a", "b", "bad", "c", "d"] {
        book.emit(b, 0, 1);
    }
    assert!(settle(&rec, Duration::from_secs(10)).await);
    for b in ["a", "b", "c", "d"] {
        assert_eq!(store.row(b, 0), (1, 1), "{b} recorded");
    }
    assert_eq!(store.row("bad", 0), (0, 0));
    let dead = rec.dead_letters();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].state, DeadState::Refused);
    assert_eq!(dead[0].cells.len(), 1);
    assert_eq!(dead[0].cells[0].bucket, "bad");
    // Its later deltas fold into the letter, never posted.
    book.emit("bad", 0, 1);
    assert!(settle(&rec, Duration::from_secs(5)).await);
    assert_eq!(store.row("bad", 0), (0, 0));
    assert_eq!(rec.dead_letters()[0].cells[0].requests, 2);
    rec.stop().await;
}

/// T10 and T7: a kill after the spool's fsync and before READY: the reopened recorder replays the
/// carve under its OWN op ids, so the counts are present exactly once, and nothing new reuses a
/// previous boot's op id.
#[tokio::test]
async fn t10_t7_a_kill_before_ready_replays_once_and_never_reuses_an_op_id() {
    let dir = TmpDir::new();
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    store.modes.commit_then_fail.store(1, Ordering::SeqCst);
    let medium = Medium::Dir(dir.path().to_path_buf());
    let (rec, _) = open(&book, &store, &medium);
    book.emit("k", 0, 5);
    // One send: the store commits and the reply is lost. Then the process dies.
    let (tx, rx) = tokio::sync::oneshot::channel();
    assert!(rec.post_msg(WriterMsg::Take(Ack::Async(tx))));
    rx.await.unwrap().unwrap();
    assert!(!rec.send_front().await, "unresolved");
    let first_ops: Vec<Op> = rec
        .lock()
        .entries
        .iter()
        .flat_map(|e| [e.batch.usage_op, e.batch.metering_op])
        .collect();
    rec.stop().await;
    drop(rec);

    let (rec, recovered) = open(&book, &store, &medium);
    assert_eq!(recovered.carves, 1, "the carve survived the kill");
    assert!(rec.drain(false, recovered.deadline()).await);
    assert_eq!(store.row("k", 0), (5, 5), "exactly once");
    book.emit("k", 0, 1);
    assert!(settle(&rec, Duration::from_secs(5)).await);
    let ops = store.ops.lock().unwrap();
    assert_eq!(store.row("k", 0), (6, 6));
    assert_eq!(
        ops.len(),
        2,
        "one op per carve, never two bodies under one id"
    );
    let fresh = ops.keys().filter(|o| !first_ops.contains(o)).count();
    assert_eq!(
        fresh, 1,
        "the new carve minted a new op id, never a previous boot's"
    );
    drop(ops);
    rec.stop().await;
}

/// T21: a carve whose `t_sent` is past the op-id retention at boot is dead-lettered
/// `landed-unknown`, never replayed.
#[tokio::test]
async fn t21_a_carve_past_retention_is_dead_lettered_not_replayed() {
    let dir = TmpDir::new();
    let spool_dir = dir.path().join("money-spool");
    {
        let (mut s, _) = Spool::open(&spool_dir, Arc::new(spool::DataSync)).unwrap();
        let mut c = CellCount::new("k", 0);
        c.requests = 1;
        s.append(&[Rec::Carve(Batch {
            seq: 0,
            usage_op: Op::mint(),
            metering_op: Op::mint(),
            cells: vec![c],
            metering: Vec::new(),
            t_sent: now_ms() - RETENTION_MS - 1,
        })])
        .unwrap();
    }
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    let (rec, recovered) = open(&book, &store, &Medium::Dir(dir.path().to_path_buf()));
    assert_eq!(recovered.carves, 1);
    assert!(rec.drain(false, recovered.deadline()).await);
    assert_eq!(store.calls.load(Ordering::SeqCst), 0, "never replayed");
    let dead = rec.dead_letters();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].state, DeadState::LandedUnknown);
    rec.stop().await;
}

/// T14: a dead letter survives a restart: its cells come back for RAM `cur` to count.
#[tokio::test]
async fn t14_a_dead_letter_survives_a_restart() {
    let dir = TmpDir::new();
    let medium = Medium::Dir(dir.path().to_path_buf());
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    *store.modes.poison.lock().unwrap() = Some("bad".into());
    let (rec, _) = open(&book, &store, &medium);
    book.emit("bad", 0, 4);
    assert!(settle(&rec, Duration::from_secs(5)).await);
    assert_eq!(rec.dead_letters().len(), 1);
    rec.stop().await;
    drop(rec);
    let (rec, recovered) = open(&book, &store, &medium);
    assert_eq!(recovered.refused_cells.len(), 1);
    assert_eq!(recovered.refused_cells[0].requests, 4);
    assert_eq!(rec.dead_letters().len(), 1);
    // The operator's clear re-posts it, once.
    *store.modes.poison.lock().unwrap() = None;
    let id = rec.dead_letters()[0].id;
    rec.clear(id, Verdict::NotLanded).await.expect("clears");
    assert_eq!(store.row("bad", 0), (4, 4));
    assert!(rec.dead_letters().is_empty());
    rec.stop().await;
}

/// The spool's `fsync` runs on the writer's own thread, never the caller's.
#[tokio::test]
async fn the_spool_fsync_never_runs_on_a_request_thread() {
    let dir = TmpDir::new();
    let (book, store) = (Arc::new(Book::default()), Arc::new(Store::default()));
    let (rec, _) = open(&book, &store, &Medium::Dir(dir.path().to_path_buf()));
    book.emit("k", 0, 1);
    assert!(settle(&rec, Duration::from_secs(5)).await);
    let thread = rec
        .stats
        .fsync_thread
        .lock()
        .unwrap()
        .expect("an fsync ran");
    assert_ne!(thread, std::thread::current().id());
    rec.stop().await;
}
