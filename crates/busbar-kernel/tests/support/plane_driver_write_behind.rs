// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INSTANCE'S RECORD WRITES BEHIND THE DRIVER (ruling H2 U10, `BUSBAR-1.6.0.md` Appendix B
//! 2026-09-30; THE DESIGN §11.11 H4/H5): write-behind is bounded (a flush cadence of at most 1 s,
//! at most N writes a batch), a piece's record write is durable before the unit that carried it
//! completes, and a store that hangs never holds a reload or the shutdown drain past its deadline.
//! Run against the contract-level double of `plane_driver.rs`.

use std::sync::atomic::AtomicUsize;
use std::sync::Condvar;

use busbar_kernel::host_records::{record_key, Acked, BATCH_CAP, FLUSH_INTERVAL};

use super::*;

const TASK: &str = "task";

fn task() -> RecordSchemaId {
    RecordSchemaId::new(TASK)
}

/// A store whose puts wait at the gate until the test opens it.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
    entered: AtomicUsize,
}

impl Gate {
    fn pass(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.cv.wait(open).unwrap();
        }
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }
}

/// The memory store's records, every put held at `gate`.
struct Gated {
    rows: Rows,
    gate: Arc<Gate>,
}

impl RecordRows for Gated {
    fn record_put(&self, s: RecordSchemaId, k: &[u8], v: &RecordBytes) -> Result<(), StoreError> {
        self.gate.pass();
        self.rows.record_put(s, k, v)
    }

    fn record_get(&self, s: RecordSchemaId, k: &[u8]) -> Result<Option<RecordBytes>, StoreError> {
        self.rows.record_get(s, k)
    }

    fn record_scan(
        &self,
        s: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        self.rows.record_scan(s, prefix, limit)
    }
}

/// Runs every job on its own thread, so a store that hangs holds no runtime thread.
struct Threads;

impl Offload for Threads {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        std::thread::spawn(job);
    }
}

/// Refuses (drops unrun) the first job, then runs every later one at once.
#[derive(Default)]
struct RefusesFirst(AtomicUsize);

impl Offload for RefusesFirst {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
            job();
        }
    }
}

/// Holds every job until the test runs them.
#[derive(Default)]
struct Held(Mutex<Vec<Box<dyn FnOnce() + Send>>>);

impl Held {
    fn run_all(&self) -> usize {
        let jobs = std::mem::take(&mut *self.0.lock().unwrap());
        let n = jobs.len();
        jobs.into_iter().for_each(|job| job());
        n
    }
}

impl Offload for Arc<Held> {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        self.0.lock().unwrap().push(job);
    }
}

/// The kernel's records services over a memory store read through `rows`, on `pool`, with "inst"
/// admitted keeping `task` records.
fn services_over(
    rows: impl FnOnce(Arc<MemoryStore>) -> Arc<dyn RecordRows>,
    pool: Arc<dyn Offload>,
) -> (Arc<KernelServices>, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let s = KernelServices::new(HashMap::new(), Arc::new(SystemResolver))
        .with_records(rows(Arc::clone(&store)), Arc::clone(&store))
        .with_pool(pool);
    let facts = InstanceFacts {
        record_kinds: vec![task()],
        ..InstanceFacts::default()
    };
    s.admit("inst", facts).unwrap();
    (Arc::new(s), store)
}

/// `inst`'s stored value of `key`, or `None` when the store has not taken it.
fn stored(store: &MemoryStore, key: &[u8]) -> Option<Vec<u8>> {
    store
        .record_get(task(), &record_key("inst", key))
        .unwrap()
        .map(|v| v.as_slice().to_vec())
}

fn completed(o: &busbar_contract::caps::Outcome) -> bool {
    matches!(o, busbar_contract::caps::Outcome::Completed)
}

/// The answers writes got, and the `Acked` that records each.
type Answers = Arc<Mutex<Vec<Result<(), &'static str>>>>;

fn answers() -> (Answers, impl Fn() -> Acked) {
    let got: Answers = Arc::default();
    let g = Arc::clone(&got);
    (got, move || {
        let g = Arc::clone(&g);
        Box::new(move |r| g.lock().unwrap().push(r)) as Acked
    })
}

// ── (a) bounded: the cadence and the batch ───────────────────────────────────────────────────────

/// RED (a), PAST THE TICK: a write whose flush the pool refused, with no later write and an
/// instance whose own tick schedule has ended, is flushed by the kernel's cadence within one
/// [`FLUSH_INTERVAL`]. Before: only a plane's `tick` restarted a flush, so the write waited forever
/// and the unit that carried it never completed.
#[tokio::test]
async fn a_write_left_queued_is_flushed_within_one_interval_whatever_the_planes_ticks() {
    let (s, store) = services_over(|m| Arc::new(Rows(m)), Arc::new(RefusesFirst::default()));
    let (_plane, _book, driver) = driven(0);
    tokio::time::timeout(Duration::from_secs(5), driver.ticks())
        .await
        .expect("the instance's schedule ends at once");
    let driver = driver.with_records(Arc::clone(&s), instance());
    let cadence = tokio::spawn({
        let s = Arc::clone(&s);
        async move { s.flushes().await }
    });
    let started = Instant::now();
    let unit = write(&driver, b"a=1");
    tokio::pin!(unit);
    // Queued: the overlay answers the instance at once; the store has not taken it.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut unit)
            .await
            .is_err(),
        "the unit waits on its write"
    );
    assert_eq!(get(&s, b"a").bytes, b"1", "read-your-writes while queued");
    assert_eq!(stored(&store, b"a"), None);
    let o = tokio::time::timeout(FLUSH_INTERVAL * 3, &mut unit)
        .await
        .expect("the cadence flushed the write");
    assert!(completed(&o), "{o:?}");
    assert!(
        started.elapsed() < FLUSH_INTERVAL + Duration::from_millis(500),
        "flushed within one interval: {:?}",
        started.elapsed()
    );
    assert_eq!(stored(&store, b"a"), Some(b"1".to_vec()));
    assert_eq!(s.pending().queued(), 0);
    cadence.abort();
}

/// RED (a), PAST N: a burst of more than [`BATCH_CAP`] writes queued behind one flush is carried by
/// that flush, batch after batch, every write answered only once the store took it.
#[test]
fn a_burst_past_one_batch_is_carried_by_the_one_flush() {
    let held = Arc::new(Held::default());
    let (s, store) = services_over(|m| Arc::new(Rows(m)), Arc::new(Arc::clone(&held)));
    let (got, acked) = answers();
    let n = 2 * BATCH_CAP + 1;
    for i in 0..n {
        let v = RecordBytes::new(format!("v{i}").into_bytes()).unwrap();
        s.record_write(&instance(), TASK, format!("k{i:04}").as_bytes(), v, acked())
            .unwrap();
    }
    assert!(
        got.lock().unwrap().is_empty(),
        "nothing answered before the store took it"
    );
    assert_eq!(s.pending().queued(), n);
    assert_eq!(held.run_all(), 1, "one flush for the whole burst");
    assert_eq!(got.lock().unwrap().len(), n);
    assert!(got.lock().unwrap().iter().all(Result::is_ok));
    assert_eq!(s.pending().queued(), 0);
    assert_eq!(
        stored(&store, format!("k{:04}", n - 1).as_bytes()),
        Some(format!("v{}", n - 1).into_bytes())
    );
}

// ── (b) durable before the answer ────────────────────────────────────────────────────────────────

/// RED (b): A PIECE'S RECORD WRITE IS DURABLE BEFORE ITS UNIT COMPLETES. While the store holds the
/// put, the instance already reads its write (the overlay) but the unit has not completed; it
/// completes only once the store took it.
#[tokio::test]
async fn a_pieces_record_write_is_in_the_store_before_its_unit_completes() {
    let gate = Arc::new(Gate::default());
    let g = Arc::clone(&gate);
    let (s, store) = services_over(
        move |m| {
            Arc::new(Gated {
                rows: Rows(m),
                gate: g,
            })
        },
        Arc::new(Threads),
    );
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.driver = r.driver.with_records(Arc::clone(&s), instance());
    let unit = write(&r.driver, b"a=1");
    tokio::pin!(unit);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut unit)
            .await
            .is_err(),
        "the unit completed before the store took its write"
    );
    assert_eq!(gate.entered(), 1, "the put reached the store");
    assert_eq!(stored(&store, b"a"), None);
    assert_eq!(
        get(&s, b"a").bytes,
        b"1",
        "read-your-writes while the store holds it"
    );
    gate.release();
    let o = tokio::time::timeout(Duration::from_secs(5), &mut unit)
        .await
        .expect("the unit completes once the store took the write");
    assert!(completed(&o), "{o:?}");
    assert_eq!(stored(&store, b"a"), Some(b"1".to_vec()));
}

/// RED (b): `records.claim` answers only after the store decided it: answered WON, the token is
/// already spent in the store, so a fresh host over the same store (a crash) answers TAKEN.
#[test]
fn a_claim_is_spent_in_the_store_before_it_answers() {
    let (s, store) = services_over(|m| Arc::new(Rows(m)), Arc::new(Threads));
    let (tx, rx) = std::sync::mpsc::channel();
    let ran = s.records_claim(
        &instance(),
        TASK,
        b"nonce",
        60_000,
        Box::new(move |a| tx.send(a.value).unwrap()),
    );
    assert!(matches!(ran, Ran::Later));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(svc::CLAIM_WON));
    let fresh = KernelServices::new(HashMap::new(), Arc::new(SystemResolver))
        .with_records(Arc::new(Rows(Arc::clone(&store))), store)
        .with_pool(Arc::new(Inline));
    fresh
        .admit(
            "inst",
            InstanceFacts {
                record_kinds: vec![task()],
                ..InstanceFacts::default()
            },
        )
        .unwrap();
    let again = answer(|l| fresh.records_claim(&instance(), TASK, b"nonce", 60_000, l));
    assert_eq!(again.value, svc::CLAIM_TAKEN);
}

// ── (c) a hung store holds neither a reload nor the shutdown drain ─────────────────────────────

/// RED (c), THE DESIGN §11.11 H5: with the store hung on a unit's record write, a reload ends the
/// unit at once (it never waits on the store), the shutdown drain gives up at its own deadline,
/// and the write itself runs on: once the store answers it is kept (write-behind is never
/// cancelled by a reload) and a later drain completes.
#[tokio::test]
async fn a_hung_store_holds_neither_the_reload_nor_the_drain() {
    let gate = Arc::new(Gate::default());
    let g = Arc::clone(&gate);
    let (s, store) = services_over(
        move |m| {
            Arc::new(Gated {
                rows: Rows(m),
                gate: g,
            })
        },
        Arc::new(Threads),
    );
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.driver = r.driver.with_records(Arc::clone(&s), instance());
    let unit = write(&r.driver, b"a=1");
    tokio::pin!(unit);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut unit)
            .await
            .is_err(),
        "the unit waits on the hung store"
    );
    assert_eq!(gate.entered(), 1);
    r.driver.reload();
    let o = tokio::time::timeout(Duration::from_secs(2), &mut unit)
        .await
        .expect("the reload ended the unit without waiting on the store");
    assert!(
        !completed(&o),
        "a unit whose write was never taken did not complete: {o:?}"
    );
    let t = Instant::now();
    assert!(
        !s.drain(Duration::from_millis(100)),
        "the hung write is not drained"
    );
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "the drain kept its deadline"
    );
    gate.release();
    assert!(
        s.drain(Duration::from_secs(5)),
        "the store answered: the drain completes"
    );
    assert_eq!(stored(&store, b"a"), Some(b"1".to_vec()));
}
