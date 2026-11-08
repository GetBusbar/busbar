// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::host_services::{AsyncJob, InstanceFacts, KernelServices, Offload};
use crate::persistence::{
    facade::{CoreStore, Limits, WriterAuthority},
    host_records::tests::Backend,
};
use crate::trust::{
    book::{Distrust, Ruling, RulingRow, TrustFacts},
    demotion::DemotionRecord,
    reverify::Policy,
    section::{DeclaredPin, TrustEntry},
};
use busbar_contract::services::HostServices;
use busbar_contract::{
    persistence::*,
    services::{Caller, Later, Ran, Stored},
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Notify;

pub(crate) const INSTANCE: &str = "inst";
pub(crate) const PEER: &str = "cp";
pub(crate) const KEY: &str = "inst/cp";
pub(crate) const ORIGINAL: &str = "original-digest";
pub(crate) const CHANGED: &str = "changed-digest";

#[derive(Default)]
pub(crate) struct NativeBackend {
    pub inner: Arc<Backend>,
    pub park_commit: AtomicBool,
    pub park_scan: AtomicBool,
    pub refuse_commit: AtomicBool,
    pub refuse_scan: AtomicBool,
    pub panic_commit: AtomicBool,
    pub panic_scan: AtomicBool,
    pub panic_after: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
    pub scans: AtomicUsize,
}
impl PersistenceBackend for NativeBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            self.scans.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_scan.swap(false, Ordering::SeqCst),
                "native scan panic"
            );
            if self.refuse_scan.load(Ordering::SeqCst) {
                return Err(Failure::Unavailable);
            }
            let page = self.inner.scan(request).await?;
            if self.park_scan.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(page)
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            assert!(
                !self.panic_commit.swap(false, Ordering::SeqCst),
                "native commit panic"
            );
            if self.refuse_commit.load(Ordering::SeqCst) {
                return Err(Failure::Refused);
            }
            let result = self.inner.commit(candidate).await;
            assert!(
                !self.panic_after.swap(false, Ordering::SeqCst),
                "native postcommit panic"
            );
            if self.park_commit.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            result
        })
    }
}

pub(crate) struct AsyncPool;
impl Offload for AsyncPool {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        drop(tokio::task::spawn_blocking(job));
    }
    fn run_async(&self, job: AsyncJob) {
        drop(tokio::spawn(job));
    }
}
#[derive(Default)]
pub(crate) struct Held(pub Mutex<Vec<AsyncJob>>);
impl Offload for Held {
    fn run(&self, _job: Box<dyn FnOnce() + Send>) {
        panic!("trust used blocking offload")
    }
    fn run_async(&self, job: AsyncJob) {
        self.0.lock().unwrap().push(job);
    }
}
impl Held {
    pub async fn drain(&self) -> usize {
        let jobs = std::mem::take(&mut *self.0.lock().unwrap());
        let count = jobs.len();
        for job in jobs {
            job.await;
        }
        count
    }
    pub fn discard(&self) -> usize {
        let jobs = std::mem::take(&mut *self.0.lock().unwrap());
        let n = jobs.len();
        drop(jobs);
        n
    }
}

pub(crate) fn facts() -> InstanceFacts {
    let mut approved = std::collections::BTreeMap::new();
    approved.insert("tool".into(), ORIGINAL.into());
    approved.insert("other-tool".into(), ORIGINAL.into());
    InstanceFacts {
        trust: vec![(
            PEER.into(),
            TrustEntry {
                pin: Some(DeclaredPin {
                    mechanism: "fingerprint".into(),
                    root: false,
                    peer_key: false,
                    key: None,
                    fingerprint: Some(ORIGINAL.into()),
                }),
                policy: Policy {
                    ttl_ms: 100,
                    recovery_backoff_ms: 0,
                },
                approved,
            },
        )],
        ..InstanceFacts::default()
    }
}
pub(crate) fn caller() -> Caller {
    Caller::for_test(
        INSTANCE.into(),
        busbar_contract::abi::mechanism::KindCode::Plane,
    )
}

pub(crate) struct Rig {
    pub backend: Arc<NativeBackend>,
    pub core: Arc<CoreStore>,
    pub node: Arc<KernelServices>,
    pub record: Arc<DemotionRecord>,
    pub clock: Arc<AtomicU64>,
}
impl Rig {
    pub async fn new() -> Self {
        let backend = Arc::new(NativeBackend::default());
        let core = Arc::new(
            CoreStore::attach(
                backend.clone(),
                WriterAuthority {
                    writer_epoch: 2,
                    writer: [4; 16],
                    execution_epoch: 3,
                },
                Limits {
                    pending_operations: 128,
                    conflict_retries: 16,
                    scan_items: 16,
                    scan_bytes: 1024 * 1024,
                },
            )
            .await
            .unwrap(),
        );
        let clock = Arc::new(AtomicU64::new(1_700_000_000_000));
        let (node, record) = Self::node_on(core.clone(), clock.clone(), Arc::new(AsyncPool)).await;
        Self {
            backend,
            core,
            node,
            record,
            clock,
        }
    }
    pub async fn node_on(
        core: Arc<CoreStore>,
        clock: Arc<AtomicU64>,
        pool: Arc<dyn Offload>,
    ) -> (Arc<KernelServices>, Arc<DemotionRecord>) {
        let record = Arc::new(DemotionRecord::default());
        record.set_store(core).unwrap();
        let node = Arc::new(
            KernelServices::new()
                .with_pool(pool)
                .with_demotions(record.clone(), INSTANCE)
                .with_wall_clock(Arc::new(move || clock.load(Ordering::SeqCst))),
        );
        node.admit(INSTANCE, facts()).await.unwrap();
        (node, record)
    }
    pub async fn follower(
        &self,
        pool: Arc<dyn Offload>,
    ) -> (Arc<KernelServices>, Arc<DemotionRecord>) {
        Self::node_on(self.core.clone(), self.clock.clone(), pool).await
    }
    pub async fn observe(&self, digest: &str) -> Stored {
        call(|later| self.node.trust_sight(&caller(), PEER, digest, later)).await
    }
    pub async fn approve(&self) {
        self.observe(ORIGINAL).await;
        self.node.trust_rule(KEY, Ruling::Approve).await.unwrap();
    }
    pub fn next_window(&self) {
        self.clock.fetch_add(
            crate::governance::REVOCATION_SYNC_TTL_SECS * 1000,
            Ordering::SeqCst,
        );
    }
    pub async fn kept(&self, item: Option<&str>) -> RulingRow {
        self.record
            .decisions()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.item.as_deref() == item)
            .unwrap()
    }
}
pub(crate) async fn call(operation: impl FnOnce(Later) -> Ran) -> Stored {
    let (tx, rx) = tokio::sync::oneshot::channel();
    match operation(Box::new(move |result| {
        let _ = tx.send(result);
    })) {
        Ran::Now(result) => result,
        Ran::Later => tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap(),
    }
}
pub(crate) async fn entered(backend: &NativeBackend) {
    tokio::time::timeout(Duration::from_secs(5), backend.entered.notified())
        .await
        .unwrap();
}
pub(crate) fn judged(node: &KernelServices, item: Option<&str>) -> Result<(), Distrust> {
    node.trust_judge(
        INSTANCE,
        &TrustFacts {
            counterparty: PEER,
            item,
            digest: item.map(|_| ORIGINAL),
        },
    )
}
pub(crate) async fn idle_resync(node: &KernelServices) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while node.trust_resync.1.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
