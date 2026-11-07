// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::persistence::{
    facade::{Limits, WriterAuthority},
    scoped::{Mutation as ScopedMutation, Request, ScopedStore},
};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Page, PersistenceBackend,
};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

pub(crate) struct Backend {
    inner: super::tests::Backend,
    pub(crate) lose_reply: AtomicBool,
    receipts: Mutex<BTreeSet<[u8; 16]>>,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            lose_reply: AtomicBool::new(false),
            receipts: Default::default(),
        }
    }
}
impl std::ops::Deref for Backend {
    type Target = super::tests::Backend;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let observed_at = ClockObservation {
                authority: self.info().clock_authority,
                unix_seconds: self.now.load(Ordering::SeqCst),
            };
            if request
                .time
                .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
            {
                return Ok(ReadResult::TimeGuardFailed { observed_at });
            }
            match self.inner.read(request).await? {
                ReadResult::Values { values, .. } => Ok(ReadResult::Values {
                    observed_at,
                    values,
                }),
                _ => Err(Failure::Corrupt),
            }
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async {
            Ok(ClockObservation {
                authority: self.info().clock_authority,
                unix_seconds: self.now.load(Ordering::SeqCst),
            })
        })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let operation = prepared.candidate().id.operation;
            let known = self.receipts.lock().unwrap().contains(&operation);
            let now = self.now.load(Ordering::SeqCst);
            if !known
                && prepared
                    .candidate()
                    .time
                    .is_some_and(|guard| !guard.permits(now))
            {
                return Ok(Decision::TimeGuardFailed {
                    observed_at: ClockObservation {
                        authority: self.info().clock_authority,
                        unix_seconds: now,
                    },
                });
            }
            let decision = self.inner.commit(prepared).await?;
            if matches!(decision, Decision::Applied(_)) {
                self.receipts.lock().unwrap().insert(operation);
                if self.lose_reply.swap(false, Ordering::SeqCst) {
                    return Err(Failure::Unknown);
                }
            }
            Ok(decision)
        })
    }
}
pub(crate) async fn attach(backend: Arc<Backend>, writer: u8) -> Arc<CoreStore> {
    Arc::new(
        CoreStore::attach(
            backend,
            WriterAuthority {
                writer_epoch: 2,
                writer: [writer; 16],
                execution_epoch: 3,
            },
            Limits {
                pending_operations: 64,
                conflict_retries: 2,
                scan_items: 16,
                scan_bytes: 1024 * 1024,
            },
        )
        .await
        .unwrap(),
    )
}
fn request() -> Request {
    Request {
        op_id: [9; 16],
        predicates: vec![],
        mutations: vec![ScopedMutation::Put {
            schema: "ticket".into(),
            key: b"one".to_vec(),
            value: Secret::new(b"opaque".to_vec()),
        }],
    }
}
#[tokio::test]
async fn timed_logical_receipt_replays_after_expiry_and_changed_interval_conflicts() {
    let backend = Arc::new(Backend::default());
    let store =
        ScopedStore::host_private(attach(backend.clone(), 4).await, "timed", ["ticket".into()])
            .unwrap();
    let request = request();
    let time = Some(TimeGuard {
        not_before: None,
        before: Some(11),
    });
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        store
            .conditional_native_timed(&request, time)
            .await
            .unwrap(),
        Outcome::Pending(_)
    ));
    backend.now.store(12, Ordering::SeqCst);
    assert_eq!(
        store
            .conditional_native_timed(&request, time)
            .await
            .unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        store
            .conditional_native_timed(
                &request,
                Some(TimeGuard {
                    not_before: None,
                    before: Some(20)
                })
            )
            .await
            .unwrap(),
        Outcome::OpIdConflict
    );
    assert_eq!(
        store
            .get("ticket", b"one")
            .await
            .unwrap()
            .unwrap()
            .expose(&crate::seal::lend()),
        b"opaque"
    );
}
#[tokio::test]
async fn expired_native_guard_applies_no_record_or_logical_receipt() {
    let backend = Arc::new(Backend::default());
    let store =
        ScopedStore::host_private(attach(backend.clone(), 4).await, "timed", ["ticket".into()])
            .unwrap();
    let request = request();
    assert_eq!(
        store
            .conditional_native_timed(
                &request,
                Some(TimeGuard {
                    not_before: None,
                    before: Some(10)
                })
            )
            .await
            .unwrap(),
        Outcome::NoEffect(Failure::Refused)
    );
    assert!(store.get("ticket", b"one").await.unwrap().is_none());
}
