// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicUsize};

use busbar_contract::kinds::RecordBytes;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_kernel::host_records::{Acked, BATCH_CAP, FLUSH_INTERVAL};
use busbar_kernel::host_services::{AsyncJob, Offload};
use busbar_kernel::persistence::{facade::CoreStore, scoped::ScopedStore};

use super::*;

const TASK: &str = "task";

fn task() -> RecordSchemaId {
    RecordSchemaId::new(TASK)
}

/// Gate the actual primitive commit after Startup and instance admission complete.
#[derive(Default)]
struct Gate {
    armed: AtomicBool,
    open: AtomicBool,
    changed: tokio::sync::Notify,
    entered: AtomicUsize,
}
impl Gate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    async fn pass(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        self.entered.fetch_add(1, Ordering::SeqCst);
        loop {
            let changed = self.changed.notified();
            if self.open.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }
    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }
}
struct Gated {
    actual: Arc<dyn PersistenceBackend>,
    gate: Arc<Gate>,
}
impl PersistenceBackend for Gated {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.actual.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.actual.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            self.gate.pass().await;
            self.actual.commit(candidate).await
        })
    }
}
struct Threads;
impl Offload for Threads {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        std::thread::spawn(job);
    }
    fn run_async(&self, job: AsyncJob) {
        drop(tokio::spawn(job));
    }
}
/// Refuse the first actual asynchronous flush job, then let the cadence retry it.
#[derive(Default)]
struct RefusesFirst(AtomicUsize);
impl Offload for RefusesFirst {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
            job();
        }
    }
    fn run_async(&self, job: AsyncJob) {
        if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
            drop(tokio::spawn(job));
        }
    }
}
#[derive(Default, Clone)]
struct Held(Arc<Mutex<Vec<AsyncJob>>>);
impl Held {
    async fn run_all(&self) -> usize {
        let jobs = std::mem::take(&mut *self.0.lock().unwrap());
        let n = jobs.len();
        for job in jobs {
            job.await;
        }
        n
    }
}
impl Offload for Held {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        self.run_async(Box::pin(async move {
            job();
        }));
    }
    fn run_async(&self, job: AsyncJob) {
        self.0.lock().unwrap().push(job);
    }
}
async fn services_over(
    decorate: impl FnOnce(Arc<dyn PersistenceBackend>) -> Arc<dyn PersistenceBackend>,
    pool: Arc<dyn Offload>,
) -> (Arc<KernelServices>, Arc<CoreStore>) {
    let backend = super::real_store::native_backend().await;
    let store = super::real_store::core_over(decorate(backend)).await;
    let s = KernelServices::new().with_pool(pool);
    assert!(s.attach_persistence(store.clone()));
    s.admit(
        "inst",
        InstanceFacts {
            record_kinds: vec![task()],
            ..InstanceFacts::default()
        },
    )
    .await
    .unwrap();
    (Arc::new(s), store)
}
async fn stored(store: &Arc<CoreStore>, key: &[u8]) -> Option<Vec<u8>> {
    ScopedStore::authorized(store.clone(), "inst", [TASK.into()])
        .unwrap()
        .get(TASK, key)
        .await
        .unwrap()
        .map(|value| value.expose(&busbar_kernel::seal::lend()).clone())
}

fn completed(o: &busbar_contract::caps::Outcome) -> bool {
    matches!(o, busbar_contract::caps::Outcome::Completed)
}

type Answers = Arc<Mutex<Vec<Result<(), &'static str>>>>;

fn answers() -> (Answers, impl Fn() -> Acked) {
    let got: Answers = Arc::default();
    let g = Arc::clone(&got);
    (got, move || {
        let g = Arc::clone(&g);
        Box::new(move |r| g.lock().unwrap().push(r)) as Acked
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_left_queued_is_flushed_within_one_interval_whatever_the_planes_ticks() {
    let (s, store) = services_over(|backend| backend, Arc::new(RefusesFirst::default())).await;
    let (_plane, _book, driver) = driven(0).await;
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

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut unit)
            .await
            .is_err(),
        "the unit waits on its write"
    );
    assert_eq!(
        get(&s, b"a").await.bytes,
        b"1",
        "read-your-writes while queued"
    );
    assert_eq!(stored(&store, b"a").await, None);
    let o = tokio::time::timeout(FLUSH_INTERVAL * 3, &mut unit)
        .await
        .expect("the cadence flushed the write");
    assert!(completed(&o), "{o:?}");
    assert!(
        started.elapsed() < FLUSH_INTERVAL + Duration::from_millis(500),
        "flushed within one interval: {:?}",
        started.elapsed()
    );
    assert_eq!(stored(&store, b"a").await, Some(b"1".to_vec()));
    assert_eq!(s.pending().queued(), 0);
    cadence.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_past_one_batch_is_carried_by_the_one_flush() {
    let held = Held::default();
    let (s, store) = services_over(|backend| backend, Arc::new(held.clone())).await;
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
    assert_eq!(held.run_all().await, 1, "one flush for the whole burst");
    assert_eq!(got.lock().unwrap().len(), n);
    assert!(got.lock().unwrap().iter().all(Result::is_ok));
    assert_eq!(s.pending().queued(), 0);
    assert_eq!(
        stored(&store, format!("k{:04}", n - 1).as_bytes()).await,
        Some(format!("v{}", n - 1).into_bytes())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pieces_record_write_is_in_the_store_before_its_unit_completes() {
    let gate = Arc::new(Gate::default());
    let g = Arc::clone(&gate);
    let (s, store) = services_over(
        move |actual| Arc::new(Gated { actual, gate: g }),
        Arc::new(Threads),
    )
    .await;
    gate.arm();
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
    assert_eq!(stored(&store, b"a").await, None);
    assert_eq!(
        get(&s, b"a").await.bytes,
        b"1",
        "read-your-writes while the store holds it"
    );
    gate.release();
    let o = tokio::time::timeout(Duration::from_secs(5), &mut unit)
        .await
        .expect("the unit completes once the store took the write");
    assert!(completed(&o), "{o:?}");
    assert_eq!(stored(&store, b"a").await, Some(b"1".to_vec()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_is_spent_in_the_store_before_it_answers() {
    let (s, store) = services_over(|backend| backend, Arc::new(Threads)).await;
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
    let fresh = KernelServices::new().with_pool(Arc::new(Threads));
    assert!(fresh.attach_persistence(store.clone()));
    fresh
        .admit(
            "inst",
            InstanceFacts {
                record_kinds: vec![task()],
                ..InstanceFacts::default()
            },
        )
        .await
        .unwrap();
    let again = answer(|l| fresh.records_claim(&instance(), TASK, b"nonce", 60_000, l)).await;
    assert_eq!(again.value, svc::CLAIM_TAKEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_store_holds_neither_the_reload_nor_the_drain() {
    let gate = Arc::new(Gate::default());
    let g = Arc::clone(&gate);
    let (s, store) = services_over(
        move |actual| Arc::new(Gated { actual, gate: g }),
        Arc::new(Threads),
    )
    .await;
    gate.arm();
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
    assert_eq!(stored(&store, b"a").await, Some(b"1".to_vec()));
}
