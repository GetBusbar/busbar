// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};
use std::sync::atomic::{AtomicU8, AtomicUsize};
use std::time::Duration;
use tokio::sync::Notify;

/// Inject faults at the actual native read boundary after Startup has admitted
/// the real plugin. A stalled native future never occupies a blocking thread.
struct ReadFault {
    inner: Arc<dyn PersistenceBackend>,
    mode: AtomicU8,
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}
impl PersistenceBackend for ReadFault {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let mode = self.mode.load(Ordering::SeqCst);
            if mode != 0 {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                if mode == 1 {
                    return Err(Failure::Unavailable);
                }
                self.release.notified().await;
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        self.inner.commit(candidate)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
}
async fn faulty_sync(now: u64) -> (Arc<ReadFault>, Arc<RevocationSync>) {
    let backend = Arc::new(ReadFault {
        inner: crate::real_store::native_backend().await,
        mode: AtomicU8::new(0),
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let core = crate::real_store::core_over(backend.clone()).await;
    let rev = RevocationSync::native(
        core,
        HashSet::new(),
        now,
        Arc::new(RwLock::new(crate::governance::GovCaches {
            by_id: Default::default(),
            by_credential: Default::default(),
            ..Default::default()
        })),
        Arc::new(crate::governance::CacheOrder::default()),
    );
    (backend, rev)
}
async fn finished(rev: &RevocationSync) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while rev.inflight.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("native refresh finishes");
}

#[tokio::test(flavor = "current_thread")]
async fn a_hung_store_does_not_park_the_reactor() {
    let (backend, rev) = faulty_sync(0).await;
    backend.mode.store(2, Ordering::SeqCst);
    rev.refresh_if_stale(REVOCATION_SYNC_TTL_SECS * 100);
    tokio::time::timeout(Duration::from_secs(5), backend.entered.notified())
        .await
        .unwrap();
    // This runs on the only reactor thread while the backend read is suspended.
    tokio::time::timeout(Duration::from_secs(1), tokio::task::yield_now())
        .await
        .unwrap();
    assert!(!rev.contains("vk_whoever"));
    for window in 200..210 {
        rev.refresh_if_stale_at(0, REVOCATION_SYNC_TTL_SECS * 1_000 * window);
    }
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "only one native refresh is in flight"
    );
    backend.mode.store(0, Ordering::SeqCst);
    backend.release.notify_one();
    finished(&rev).await;
}

#[tokio::test]
async fn a_failed_read_does_not_close_the_staleness_window() {
    let (backend, rev) = faulty_sync(0).await;
    backend.mode.store(1, Ordering::SeqCst);
    let t = REVOCATION_SYNC_TTL_SECS * 10;
    rev.refresh_if_stale(t);
    finished(&rev).await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(rev.synced_at(), 0, "failure preserves last success");
    for _ in 0..50 {
        rev.refresh_if_stale(t + 1);
    }
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    rev.refresh_if_stale(t + REVOCATION_SYNC_TTL_SECS + 1);
    finished(&rev).await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_successful_read_unions_and_closes_the_window() {
    let core = crate::real_store::core().await;
    core.identity()
        .add_denylist("vk_peer", "peer revoke")
        .await
        .unwrap();
    let rev = RevocationSync::native(
        core,
        HashSet::from(["vk_local".into()]),
        0,
        Arc::new(RwLock::new(crate::governance::GovCaches {
            by_id: Default::default(),
            by_credential: Default::default(),
            ..Default::default()
        })),
        Arc::new(crate::governance::CacheOrder::default()),
    );
    let t = REVOCATION_SYNC_TTL_SECS * 10;
    rev.refresh_if_stale(t);
    finished(&rev).await;
    assert!(rev.contains("vk_peer"));
    assert!(
        rev.contains("vk_local"),
        "refresh unions local confirmed revocations"
    );
    assert_eq!(rev.synced_at(), t);
}

async fn node(core: Arc<crate::persistence::facade::CoreStore>) -> crate::governance::GovState {
    crate::governance::GovState::new_with_core(
        core,
        None,
        Some(crate::governance::signing::TokenSigner::from_secret_bytes(
            &[9; 32], "test",
        )),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_key_another_node_minted_rotated_or_deleted_is_seen_within_one_window() {
    let core = crate::real_store::core().await;
    let (a, b) = (node(core.clone()).await, node(core).await);
    let t0 = crate::store::now();
    let exp = t0 + REVOCATION_SYNC_TTL_SECS * 1_000;
    let window = |n| t0 + REVOCATION_SYNC_TTL_SECS * 2 * n;
    let (key, first) = a
        .mint_signed_async(crate::governance::NewKeySpec::default(), exp, t0)
        .await
        .unwrap();
    let first = first.expose(&crate::seal::lend());
    b.denylist.refresh_if_stale(window(1));
    finished(&b.denylist).await;
    assert!(b.verify_token(first, window(1), None).is_some());
    let rotated = a
        .rotate_key_outcome_async(&key.id, exp)
        .await
        .unwrap()
        .unwrap();
    let second = rotated.token.expose(&crate::seal::lend());
    b.denylist.refresh_if_stale(window(2));
    finished(&b.denylist).await;
    assert!(b.verify_token(first, window(2), None).is_none());
    assert!(b.verify_token(second, window(2), None).is_some());
    a.delete_key_outcome_async(&key.id).await.unwrap();
    b.denylist.refresh_if_stale(window(3));
    finished(&b.denylist).await;
    assert!(b.verify_token(second, window(3), None).is_none());
}

#[tokio::test]
async fn a_backwards_wall_clock_still_observes_shared_store_rotation_and_revocation() {
    let core = crate::real_store::core().await;
    let (a, b) = (node(core.clone()).await, node(core).await);
    let t0 = crate::store::now();
    let exp = t0 + 7_200;
    let rolled_back = t0 - 3_600;
    let (key, first) = a
        .mint_signed_async(crate::governance::NewKeySpec::default(), exp, t0)
        .await
        .unwrap();
    b.refresh_async().await.unwrap();
    let second = a
        .rotate_key_outcome_async(&key.id, exp)
        .await
        .unwrap()
        .unwrap()
        .token;
    assert!(
        b.verify_token(first.expose(&crate::seal::lend()), rolled_back, None)
            .is_some()
    );
    let window_ms = REVOCATION_SYNC_TTL_SECS * 1_000;
    b.denylist.refresh_if_stale_at(rolled_back, window_ms);
    finished(&b.denylist).await;
    assert!(
        b.verify_token(first.expose(&crate::seal::lend()), rolled_back, None)
            .is_none()
    );
    assert!(
        b.verify_token(second.expose(&crate::seal::lend()), rolled_back, None)
            .is_some()
    );
    assert_eq!(b.denylist.synced_at(), rolled_back);
    a.revoke_async(&key.id, "peer revoke after clock correction")
        .await
        .unwrap();
    b.denylist.refresh_if_stale_at(rolled_back, window_ms * 2);
    finished(&b.denylist).await;
    assert!(
        b.verify_token(second.expose(&crate::seal::lend()), rolled_back, None)
            .is_none()
    );
    assert!(b.denylist.contains(&key.id));
}

#[tokio::test]
async fn failed_refreshes_under_a_regressing_clock_are_rate_limited_by_monotonic_age() {
    let (backend, rev) = faulty_sync(10_000).await;
    backend.mode.store(1, Ordering::SeqCst);
    let window_ms = REVOCATION_SYNC_TTL_SECS * 1_000;
    rev.refresh_if_stale_at(6_400, window_ms);
    finished(&rev).await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    for n in 1..100 {
        rev.refresh_if_stale_at(6_400 - n, window_ms + n);
    }
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    rev.refresh_if_stale_at(6_000, window_ms * 2);
    finished(&rev).await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    assert_eq!(rev.synced_at(), 10_000);
}
