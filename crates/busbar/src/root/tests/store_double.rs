// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Faults at the actual product's primitive persistence boundary.
//! Semantic fixtures construct CoreStore over this backend and use their native owner APIs.
use busbar_contract::persistence::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

type Probe = Pin<Box<dyn Future<Output = Result<(), Failure>> + Send>>;
pub(crate) type CommitProbe = Arc<dyn Fn(PreparedCandidate) -> Probe + Send + Sync>;
pub(crate) type ReadProbe = Arc<dyn Fn(Arc<Read>) -> Probe + Send + Sync>;

pub(crate) struct NativeFaults {
    pub(crate) actual: Arc<dyn PersistenceBackend>,
    pub(crate) refusing: AtomicBool,
    pub(crate) unreadable: AtomicBool,
    pub(crate) lose_acks: AtomicBool,
    pub(crate) requests: Mutex<Vec<PreparedCandidate>>,
    pub(crate) on_commit: Mutex<Option<CommitProbe>>,
    pub(crate) on_read: Mutex<Option<ReadProbe>>,
    paused: AtomicBool,
    parked: Mutex<Vec<Waker>>,
    applied: AtomicUsize,
}
impl NativeFaults {
    pub(crate) async fn open() -> Arc<Self> {
        Self::over(crate::root::real_store::native_backend().await)
    }
    pub(crate) fn over(actual: Arc<dyn PersistenceBackend>) -> Arc<Self> {
        Arc::new(Self {
            actual,
            refusing: AtomicBool::new(false),
            unreadable: AtomicBool::new(false),
            lose_acks: AtomicBool::new(false),
            requests: Mutex::new(Vec::new()),
            on_commit: Mutex::new(None),
            on_read: Mutex::new(None),
            paused: AtomicBool::new(false),
            parked: Mutex::new(Vec::new()),
            applied: AtomicUsize::new(0),
        })
    }
    pub(crate) fn clear_observations(&self) {
        self.requests.lock().unwrap().clear();
        self.applied.store(0, Ordering::Release);
    }
    pub(crate) fn pause(&self, paused: bool) {
        self.paused.store(paused, Ordering::Release);
        if !paused {
            for waker in std::mem::take(&mut *self.parked.lock().unwrap()) {
                waker.wake();
            }
        }
    }
    pub(crate) fn waiting(&self) -> usize {
        self.parked.lock().unwrap().len()
    }
    pub(crate) fn applied(&self) -> usize {
        self.applied.load(Ordering::Acquire)
    }
    async fn ready(&self) {
        std::future::poll_fn(|context| {
            if !self.paused.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            self.parked.lock().unwrap().push(context.waker().clone());
            if self.paused.load(Ordering::Acquire) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
}
impl PersistenceBackend for NativeFaults {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if self.unreadable.load(Ordering::Acquire) {
                return Err(Failure::Unavailable);
            }
            let hook = self.on_read.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(request.clone()).await?;
            }
            self.actual.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            self.ready().await;
            if self.unreadable.load(Ordering::Acquire) {
                return Err(Failure::Unavailable);
            }
            self.actual.scan(request).await
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            self.ready().await;
            self.requests.lock().unwrap().push(candidate.clone());
            let hook = self.on_commit.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(candidate.clone()).await?;
            }
            if self.refusing.load(Ordering::Acquire) {
                return Err(Failure::Refused);
            }
            let answer = self.actual.commit(candidate).await?;
            if matches!(answer, Decision::Applied(_)) {
                self.applied.fetch_add(1, Ordering::AcqRel);
                if self.lose_acks.load(Ordering::Acquire) {
                    return Err(Failure::Unknown);
                }
            }
            Ok(answer)
        })
    }
}
