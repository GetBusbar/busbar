// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::overlay::{persist_root_async, write_async, RootSettings};
use crate::persistence::scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore};
use busbar_contract::{persistence::*, Secret};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(in crate::config) const SCHEMA: &str = "busbar.config.overlay.v1";
pub(in crate::config) const HEAD: &[u8] = b"head";
const NORMAL: usize = 0;
pub(in crate::config) const REFUSE: usize = 1;
pub(in crate::config) const LOSE: usize = 2;
const PANIC: usize = 3;
const BLOCK: usize = 4;
const EXPIRED: usize = 5;

pub(in crate::config) struct FaultBackend {
    pub(in crate::config) inner: Arc<dyn PersistenceBackend>,
    pub(in crate::config) publication: AtomicUsize,
    pub(in crate::config) fail_reads: AtomicBool,
    fail_stage: AtomicUsize,
    stages: AtomicUsize,
    pub(in crate::config) sent: Mutex<Vec<([u8; 16], [u8; 32])>>,
    stage_sent: Mutex<Vec<([u8; 16], [u8; 32])>>,
    before_publish: Mutex<Option<Arc<OverlayStore>>>,
    after_read: Mutex<Option<Arc<OverlayStore>>>,
    reenter: Mutex<Option<Arc<OverlayStore>>>,
    entered: tokio::sync::Notify,
}

impl PersistenceBackend for FaultBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(Failure::Unavailable);
            }
            let head = request
                .addresses
                .iter()
                .any(|address| address.key.ends_with(HEAD));
            let result = self.inner.read(request).await?;
            let other = if head {
                self.after_read.lock().unwrap().take()
            } else {
                None
            };
            if let Some(other) = other {
                persist_root_async(Some(&other), &settings(2))
                    .await
                    .unwrap();
            }
            Ok(result)
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let publication = candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, busbar_contract::persistence::Mutation::Put { address, .. } if address.key.ends_with(HEAD)));
            let stage = candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, busbar_contract::persistence::Mutation::Put { address, .. } if address.key.windows(6).any(|bytes| bytes == b"chunk:")));
            if stage {
                self.stage_sent
                    .lock()
                    .unwrap()
                    .push((candidate.candidate().id.operation, candidate.fingerprint()));
                let index = self.stages.fetch_add(1, Ordering::SeqCst) + 1;
                if self
                    .fail_stage
                    .compare_exchange(index, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return Err(Failure::Unknown);
                }
            }
            let action = if publication {
                self.sent
                    .lock()
                    .unwrap()
                    .push((candidate.candidate().id.operation, candidate.fingerprint()));
                let other = self.before_publish.lock().unwrap().take();
                if let Some(other) = other {
                    persist_root_async(Some(&other), &settings(99))
                        .await
                        .unwrap();
                }
                let same = self.reenter.lock().unwrap().take();
                if let Some(same) = same {
                    let error = persist_root_async(Some(&same), &settings(123))
                        .await
                        .unwrap_err();
                    assert!(error.contains("in progress"));
                }
                self.publication.load(Ordering::SeqCst)
            } else {
                NORMAL
            };
            match action {
                REFUSE => return Err(Failure::Refused),
                EXPIRED => return Ok(Decision::ExpiredUnknown),
                BLOCK => {
                    self.publication.store(NORMAL, Ordering::SeqCst);
                    self.entered.notify_one();
                    std::future::pending::<()>().await;
                }
                _ => {}
            }
            let result = self.inner.commit(candidate).await?;
            if publication && (action == LOSE || action == PANIC) {
                self.publication.store(NORMAL, Ordering::SeqCst);
                if action == PANIC {
                    panic!("planted committed reply unwind");
                }
                return Err(Failure::Unknown);
            }
            Ok(result)
        })
    }
}

pub(in crate::config) fn settings(fee: i64) -> RootSettings {
    RootSettings {
        per_request_fee: Some(fee),
        ..Default::default()
    }
}

pub(in crate::config) async fn fixture() -> (
    Arc<FaultBackend>,
    Arc<crate::persistence::facade::CoreStore>,
    Arc<OverlayStore>,
) {
    let backend = Arc::new(FaultBackend {
        inner: crate::real_store::native_backend().await,
        publication: AtomicUsize::new(NORMAL),
        fail_reads: AtomicBool::new(false),
        fail_stage: AtomicUsize::new(0),
        stages: AtomicUsize::new(0),
        sent: Mutex::new(Vec::new()),
        stage_sent: Mutex::new(Vec::new()),
        before_publish: Mutex::new(None),
        after_read: Mutex::new(None),
        reenter: Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let core = crate::real_store::core_over(backend.clone()).await;
    let overlay = OverlayStore::from_core(core.clone()).unwrap();
    backend.sent.lock().unwrap().clear();
    backend.stage_sent.lock().unwrap().clear();
    backend.stages.store(0, Ordering::SeqCst);
    (backend, core, overlay)
}

pub(in crate::config) fn scope(core: Arc<crate::persistence::facade::CoreStore>) -> ScopedStore {
    ScopedStore::host_private(core, "busbar.config.overlay", [SCHEMA.to_string()]).unwrap()
}

pub(in crate::config) async fn seed_bytes(
    core: Arc<crate::persistence::facade::CoreStore>,
    bytes: &[u8],
) {
    let generation = crate::door::op_id().0;
    let head = serde_json::to_vec(&serde_json::json!({"version":1,"generation":generation,"length":bytes.len(),"digest":<[u8;32]>::from(Sha256::digest(bytes))})).unwrap();
    let mut mutations = Vec::new();
    for (index, bytes) in bytes.chunks(busbar_contract::MAX_RECORD_BYTES).enumerate() {
        let mut key = b"chunk:".to_vec();
        key.extend_from_slice(&generation);
        key.extend_from_slice(&(index as u64).to_be_bytes());
        mutations.push(Mutation::Put {
            schema: SCHEMA.into(),
            key,
            value: Secret::new(bytes.to_vec()),
        });
    }
    mutations.push(Mutation::Put {
        schema: SCHEMA.into(),
        key: HEAD.to_vec(),
        value: Secret::new(head),
    });
    assert!(matches!(
        scope(core)
            .conditional_native(&Request {
                op_id: crate::door::op_id().0,
                predicates: vec![Predicate {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    expected: Expected::Absent
                }],
                mutations
            })
            .await
            .unwrap(),
        Outcome::Applied
    ));
}

async fn fee(overlay: &OverlayStore) -> Option<i64> {
    overlay
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .root
        .and_then(|root| root.per_request_fee)
}

#[tokio::test]
async fn planning_unwind_restores_idle_and_committed_reply_unwind_restores_exact_candidate() {
    let (backend, _, overlay) = fixture().await;
    let task = overlay.clone();
    assert!(tokio::spawn(async move {
        task.update_async(|_| panic!("planted planning unwind"))
            .await
    })
    .await
    .unwrap_err()
    .is_panic());
    persist_root_async(Some(&overlay), &settings(1))
        .await
        .unwrap();
    backend.sent.lock().unwrap().clear();
    backend.publication.store(PANIC, Ordering::SeqCst);
    let task = overlay.clone();
    assert!(
        tokio::spawn(async move { persist_root_async(Some(&task), &settings(7)).await })
            .await
            .unwrap_err()
            .is_panic()
    );
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    {
        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent[0], sent[1]);
    }
    assert_eq!(fee(&overlay).await, Some(7));
}

#[tokio::test]
async fn callbacks_can_reenter_without_holding_the_backend_mutex() {
    let (backend, _, overlay) = fixture().await;
    *backend.reenter.lock().unwrap() = Some(overlay.clone());
    persist_root_async(Some(&overlay), &settings(7))
        .await
        .unwrap();
    assert_eq!(fee(&overlay).await, Some(7));
}

#[tokio::test]
async fn cancelled_publication_retains_exact_candidate_before_new_edit() {
    let (backend, _, overlay) = fixture().await;
    backend.publication.store(BLOCK, Ordering::SeqCst);
    let task = overlay.clone();
    let handle = tokio::spawn(async move { persist_root_async(Some(&task), &settings(7)).await });
    backend.entered.notified().await;
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    {
        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent[0], sent[1]);
    }
    assert_eq!(fee(&overlay).await, Some(7));
}

#[tokio::test]
async fn expired_unknown_retains_exact_custody_without_new_identity() {
    let (backend, _, overlay) = fixture().await;
    backend.publication.store(LOSE, Ordering::SeqCst);
    assert!(persist_root_async(Some(&overlay), &settings(7))
        .await
        .is_err());
    backend.publication.store(EXPIRED, Ordering::SeqCst);
    for _ in 0..2 {
        assert!(persist_root_async(Some(&overlay), &settings(99))
            .await
            .is_err());
    }
    {
        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|value| *value == sent[0]));
    }
    assert!(overlay.reopen_for_reload_async().await.is_err());
    assert_eq!(fee(&overlay).await, Some(7));
}

#[tokio::test]
async fn partial_staging_keeps_old_head_and_replays_the_same_generation() {
    let (backend, _, overlay) = fixture().await;
    persist_root_async(Some(&overlay), &settings(1))
        .await
        .unwrap();
    let before = overlay.read_bytes_async().await.unwrap();
    backend.stages.store(0, Ordering::SeqCst);
    backend.stage_sent.lock().unwrap().clear();
    backend.fail_stage.store(2, Ordering::SeqCst);
    let mut doc = OverlayDoc::default();
    doc.deleted
        .push("x".repeat(busbar_contract::MAX_RECORD_BYTES * 2));
    assert!(write_async(&overlay, &doc).await.is_err());
    assert_eq!(overlay.read_bytes_async().await.unwrap(), before);
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    {
        let sent = backend.stage_sent.lock().unwrap();
        assert_eq!(sent[1], sent[2]);
    }
    assert_eq!(
        overlay
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .deleted,
        doc.deleted
    );
}

#[tokio::test]
async fn head_cas_retires_superseded_and_conflicted_generations() {
    let (backend, core, overlay) = fixture().await;
    persist_root_async(Some(&overlay), &settings(1))
        .await
        .unwrap();
    let other = OverlayStore::from_core(core.clone()).unwrap();
    *backend.before_publish.lock().unwrap() = Some(other);
    assert!(persist_root_async(Some(&overlay), &settings(100))
        .await
        .is_err());
    assert_eq!(fee(&overlay).await, Some(99));
    // Exactly the winning head and its single immutable chunk survive both retirements.
    assert_eq!(
        scope(core)
            .page(SCHEMA, &[], None)
            .await
            .unwrap()
            .rows
            .len(),
        2
    );
}

#[tokio::test]
async fn reader_retries_only_when_its_immutable_snapshot_was_retired() {
    let (backend, core, overlay) = fixture().await;
    persist_root_async(Some(&overlay), &settings(1))
        .await
        .unwrap();
    *backend.after_read.lock().unwrap() = Some(OverlayStore::from_core(core.clone()).unwrap());
    assert_eq!(fee(&overlay).await, Some(2));
    let store = scope(core);
    let raw = store.get(SCHEMA, HEAD).await.unwrap().unwrap();
    let head: serde_json::Value = serde_json::from_slice(raw.expose(&crate::seal::lend())).unwrap();
    let generation: [u8; 16] = serde_json::from_value(head["generation"].clone()).unwrap();
    let mut chunk = b"chunk:".to_vec();
    chunk.extend_from_slice(&generation);
    chunk.extend_from_slice(&0u64.to_be_bytes());
    assert!(matches!(
        store.delete(SCHEMA, &chunk).await.unwrap(),
        Outcome::Applied
    ));
    assert!(overlay
        .read_required_async()
        .await
        .unwrap_err()
        .contains("incomplete"));
}

#[tokio::test]
async fn replay_of_superseded_unknown_commit_never_resurrects_retired_chunks() {
    let (backend, core, overlay) = fixture().await;
    backend.publication.store(LOSE, Ordering::SeqCst);
    assert!(persist_root_async(Some(&overlay), &settings(1))
        .await
        .is_err());
    let other = OverlayStore::from_core(core.clone()).unwrap();
    persist_root_async(Some(&other), &settings(2))
        .await
        .unwrap();
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    assert_eq!(fee(&overlay).await, Some(2));
    assert_eq!(
        scope(core)
            .page(SCHEMA, &[], None)
            .await
            .unwrap()
            .rows
            .len(),
        2
    );
    let (reloaded, _) = overlay.reopen_for_reload_async().await.unwrap();
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    persist_root_async(Some(&reloaded), &settings(3))
        .await
        .unwrap();
}

#[tokio::test]
async fn diagnostics_and_failed_rebuild_never_advance_old_app_baseline() {
    let (_, core, overlay) = fixture().await;
    persist_root_async(Some(&overlay), &settings(1))
        .await
        .unwrap();
    let observed = overlay.native.observed();
    let before = observed.lock().unwrap().clone();
    let other = OverlayStore::from_core(core).unwrap();
    persist_root_async(Some(&other), &settings(9))
        .await
        .unwrap();
    overlay.read_bytes_async().await.unwrap();
    overlay.read_required_async().await.unwrap();
    assert_eq!(*observed.lock().unwrap(), before);
    let (candidate, doc) = overlay.reopen_for_reload_async().await.unwrap();
    assert_eq!(doc.unwrap().root.unwrap().per_request_fee, Some(9));
    assert_eq!(*observed.lock().unwrap(), before);
    drop(candidate);
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    assert_eq!(*observed.lock().unwrap(), before);
}

#[tokio::test]
async fn normal_confirmed_commit_advances_its_reopened_candidate_carrier() {
    let (_, _, overlay) = fixture().await;
    persist_root_async(Some(&overlay), &settings(1))
        .await
        .unwrap();
    let (candidate, _) = overlay.reopen_for_reload_async().await.unwrap();
    persist_root_async(Some(&overlay), &settings(2))
        .await
        .unwrap();
    persist_root_async(Some(&candidate), &settings(3))
        .await
        .unwrap();
    assert_eq!(fee(&candidate).await, Some(3));
}

#[tokio::test]
async fn measurement_rates_survive_reopen_and_refused_publication_keeps_prior_card() {
    let (backend, core, overlay) = fixture().await;
    let settings = |rate| RootSettings {
        plugin_rate_cards: Some(std::collections::BTreeMap::from([(
            "hook".into(),
            std::collections::BTreeMap::from([(
                "gate".into(),
                std::collections::BTreeMap::from([(
                    "calls".into(),
                    busbar_kernel_ledger::cost::UnitRate::from_nanos(rate),
                )]),
            )]),
        )])),
        ..RootSettings::default()
    };
    persist_root_async(Some(&overlay), &settings(125))
        .await
        .unwrap();
    backend.publication.store(REFUSE, Ordering::SeqCst);
    assert!(persist_root_async(Some(&overlay), &settings(500))
        .await
        .is_err());
    let reopened = OverlayStore::from_core(core).unwrap();
    let stored = reopened
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .root
        .unwrap();
    assert_eq!(stored.plugin_rate_cards, settings(125).plugin_rate_cards);
    backend.publication.store(NORMAL, Ordering::SeqCst);
    persist_root_async(Some(&reopened), &settings(500))
        .await
        .unwrap();
    let stored = reopened
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .root
        .unwrap();
    assert_eq!(stored.plugin_rate_cards, settings(500).plugin_rate_cards);
}
