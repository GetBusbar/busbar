// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The write-behind queue's money cases (PROOF-086 rows owed to P089): a write the pool refused
//! to flush is flushed by the kernel's own cadence within one `FLUSH_INTERVAL`; a burst past one
//! `BATCH_CAP` batch is carried and answered by the one flush; a write is answered only once the
//! store's commit took it; a hung store's commit holds neither the instance's reload nor the
//! drain's deadline.

use busbar_kernel::persistence;

#[path = "../src/tests/real_store.rs"]
mod real_store;

mod write_behind {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use busbar_contract::abi::mechanism::KindCode;
    use busbar_contract::ids::RecordSchemaId;
    use busbar_contract::kinds::RecordBytes;
    use busbar_contract::persistence::{
        BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision, Page,
        PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
    };
    use busbar_contract::services::Caller;
    use busbar_kernel::host_records::{Acked, BATCH_CAP, FLUSH_INTERVAL};
    use busbar_kernel::host_services::{AsyncJob, InstanceFacts, KernelServices, Offload};
    use busbar_kernel::persistence::{facade::CoreStore, scoped::ScopedStore};
    use tokio::sync::oneshot::{self, error::TryRecvError};

    use super::real_store;

    const INSTANCE: &str = "inst";
    const TASK: &str = "task";

    fn facts() -> InstanceFacts {
        InstanceFacts {
            record_kinds: vec![RecordSchemaId::new(TASK)],
            ..InstanceFacts::default()
        }
    }

    fn caller() -> Caller {
        Caller::for_test(Arc::from(INSTANCE), KindCode::Plane)
    }

    fn value(bytes: &[u8]) -> RecordBytes {
        RecordBytes::new(bytes.to_vec()).unwrap()
    }

    async fn services(store: Arc<CoreStore>, pool: Arc<dyn Offload>) -> KernelServices {
        let mut s = KernelServices::new().with_pool(pool);
        s = s.with_persistence(store);
        s.admit(&INSTANCE.into(), facts()).await.unwrap();
        s
    }

    async fn stored(store: &Arc<CoreStore>, key: &[u8]) -> Option<Vec<u8>> {
        ScopedStore::authorized(Arc::clone(store), INSTANCE, [TASK])
            .unwrap()
            .get(TASK, key)
            .await
            .unwrap()
            .map(|value| value.expose(&busbar_kernel::seal::lend()).clone())
    }

    /// The write's answer, as the unit waiting on it receives it.
    fn ack() -> (Acked, oneshot::Receiver<Result<(), &'static str>>) {
        let (tx, rx) = oneshot::channel();
        (
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
            rx,
        )
    }

    /// Runs every job on the runtime, except the first one after `arm`, which it refuses.
    #[derive(Default)]
    struct RefusesNext(AtomicBool);
    impl RefusesNext {
        fn arm(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl Offload for RefusesNext {
        fn run(&self, job: Box<dyn FnOnce() + Send>) {
            if !self.0.swap(false, Ordering::SeqCst) {
                job();
            }
        }
        fn run_async(&self, job: AsyncJob) {
            if !self.0.swap(false, Ordering::SeqCst) {
                drop(tokio::spawn(job));
            }
        }
    }

    /// Runs every job on the runtime.
    struct Spawns;
    impl Offload for Spawns {
        fn run(&self, job: Box<dyn FnOnce() + Send>) {
            job();
        }
        fn run_async(&self, job: AsyncJob) {
            drop(tokio::spawn(job));
        }
    }

    /// Holds every job until the test runs them.
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
            self.run_async(Box::pin(async move { job() }));
        }
        fn run_async(&self, job: AsyncJob) {
            self.0.lock().unwrap().push(job);
        }
    }

    /// Holds the store's commit once armed: a commit that arrives says so on `entered` and waits
    /// until `release` (closing `open` wakes every waiter).
    struct Gate {
        armed: AtomicBool,
        entered: tokio::sync::Notify,
        open: tokio::sync::Semaphore,
    }
    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                armed: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                open: tokio::sync::Semaphore::new(0),
            })
        }
        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
        }
        fn release(&self) {
            self.open.close();
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
        fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
            self.actual.read(request)
        }
        fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
            self.actual.scan(request)
        }
        fn commit(&self, candidate: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
            Box::pin(async move {
                if self.gate.armed.load(Ordering::SeqCst) {
                    self.gate.entered.notify_one();
                    // Closed by `release`: the wait ends and the commit goes on.
                    let _released = self.gate.open.acquire().await;
                }
                self.actual.commit(candidate, key).await
            })
        }
        fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
            self.actual.clock(dataset)
        }
    }

    async fn gated() -> (Arc<KernelServices>, Arc<CoreStore>, Arc<Gate>) {
        let gate = Gate::new();
        let store = real_store::core_over(Arc::new(Gated {
            actual: real_store::native_backend().await,
            gate: Arc::clone(&gate),
        }))
        .await;
        let s = services(Arc::clone(&store), Arc::new(Spawns)).await;
        gate.arm();
        (Arc::new(s), store, gate)
    }

    /// The pool refuses the write's own flush; nothing but the kernel's cadence restarts it. On
    /// the paused clock the waiting unit is answered, and the write is in the store, within one
    /// `FLUSH_INTERVAL` of the cadence starting.
    #[tokio::test(start_paused = true)]
    async fn a_write_left_queued_is_flushed_within_one_interval_whatever_the_planes_ticks() {
        let store = real_store::core().await;
        let pool = Arc::new(RefusesNext::default());
        let s = Arc::new(services(Arc::clone(&store), Arc::clone(&pool) as Arc<dyn Offload>).await);
        let (acked, mut answer) = ack();
        pool.arm();
        s.record_write(&caller(), TASK, b"a", value(b"1"), acked)
            .unwrap();
        assert_eq!(
            answer.try_recv(),
            Err(TryRecvError::Empty),
            "the refused flush answered nothing"
        );
        assert_eq!(s.pending().queued(), 1, "the write is left queued");
        assert_eq!(stored(&store, b"a").await, None);

        let started = tokio::time::Instant::now();
        let cadence = tokio::spawn({
            let s = Arc::clone(&s);
            async move { s.flushes().await }
        });
        let answered = tokio::time::timeout(FLUSH_INTERVAL * 2, &mut answer)
            .await
            .expect("the cadence flushed the queued write")
            .expect("the write was answered, not dropped");
        let took = started.elapsed();
        assert_eq!(answered, Ok(()));
        assert!(
            took <= FLUSH_INTERVAL,
            "flushed within one interval: {took:?}"
        );
        assert_eq!(stored(&store, b"a").await, Some(b"1".to_vec()));
        assert_eq!(s.pending().queued(), 0);
        cadence.abort();
    }

    /// `2 * BATCH_CAP + 1` writes cross two batch boundaries: the one flush job the burst
    /// started carries all of them, answers every one, and leaves nothing queued.
    #[tokio::test]
    async fn a_burst_past_one_batch_is_carried_by_the_one_flush() {
        let store = real_store::core().await;
        let held = Held::default();
        let s = services(Arc::clone(&store), Arc::new(held.clone())).await;
        let got: Arc<Mutex<Vec<Result<(), &'static str>>>> = Arc::default();
        let n = 2 * BATCH_CAP + 1;
        for i in 0..n {
            let g = Arc::clone(&got);
            s.record_write(
                &caller(),
                TASK,
                format!("k{i:04}").as_bytes(),
                value(format!("v{i}").as_bytes()),
                Box::new(move |r| g.lock().unwrap().push(r)),
            )
            .unwrap();
        }
        assert!(
            got.lock().unwrap().is_empty(),
            "nothing answered before the store took it"
        );
        assert_eq!(s.pending().queued(), n);

        assert_eq!(held.run_all().await, 1, "one flush for the whole burst");
        let got = std::mem::take(&mut *got.lock().unwrap());
        assert_eq!(got.len(), n, "every write answered");
        assert!(got.iter().all(Result::is_ok), "{got:?}");
        assert_eq!(s.pending().queued(), 0);
        for i in [
            0,
            BATCH_CAP - 1,
            BATCH_CAP,
            2 * BATCH_CAP - 1,
            2 * BATCH_CAP,
        ] {
            assert_eq!(
                stored(&store, format!("k{i:04}").as_bytes()).await,
                Some(format!("v{i}").into_bytes()),
                "write {i}"
            );
        }
    }

    /// The store's commit is held: the unit waiting on the write is not answered while the
    /// commit is held, and is answered only once the store took the write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pieces_record_write_is_in_the_store_before_its_unit_completes() {
        let (s, store, gate) = gated().await;
        let entered = gate.entered.notified();
        let (acked, mut answer) = ack();
        s.record_write(&caller(), TASK, b"a", value(b"1"), acked)
            .unwrap();
        entered.await;
        assert_eq!(
            answer.try_recv(),
            Err(TryRecvError::Empty),
            "the unit completed before the store took its write"
        );
        assert_eq!(stored(&store, b"a").await, None);

        gate.release();
        assert_eq!(
            (&mut answer).await,
            Ok(Ok(())),
            "the unit completes once the store took the write"
        );
        assert_eq!(stored(&store, b"a").await, Some(b"1".to_vec()));
    }

    /// The store's commit hangs under a queued write: the instance's reload (its re-admission)
    /// still completes and answers nothing false for the write, and `drain` gives up at its
    /// deadline rather than waiting on the store. Once the store answers, the drain completes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hung_store_holds_neither_the_reload_nor_the_drain() {
        let (s, store, gate) = gated().await;
        let entered = gate.entered.notified();
        let (acked, mut answer) = ack();
        s.record_write(&caller(), TASK, b"a", value(b"1"), acked)
            .unwrap();
        entered.await;

        tokio::time::timeout(FLUSH_INTERVAL, s.admit(&INSTANCE.into(), facts()))
            .await
            .expect("the reload is not held by the hung store")
            .expect("the reload readmits the instance");
        assert_eq!(
            answer.try_recv(),
            Err(TryRecvError::Empty),
            "a write the store never took is not answered as taken"
        );

        let (drained, took) = tokio::task::spawn_blocking({
            let s = Arc::clone(&s);
            move || {
                let started = std::time::Instant::now();
                let drained = s.drain(FLUSH_INTERVAL);
                (drained, started.elapsed())
            }
        })
        .await
        .unwrap();
        assert!(!drained, "the hung write is not drained");
        assert!(
            took < FLUSH_INTERVAL * 2,
            "the drain kept its deadline: {took:?}"
        );

        gate.release();
        let drained = tokio::task::spawn_blocking({
            let s = Arc::clone(&s);
            move || s.drain(FLUSH_INTERVAL)
        })
        .await
        .unwrap();
        assert!(drained, "the store answered: the drain completes");
        assert_eq!((&mut answer).await, Ok(Ok(())));
        assert_eq!(stored(&store, b"a").await, Some(b"1".to_vec()));
    }
}
