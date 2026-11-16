// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::overlay::{persist_root_async, OverlayStore, RootSettings};
use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn migration_rows_stream_bounded_current_chunks_before_manifest() {
    let doc = OverlayDoc {
        deleted: vec!["x".repeat(busbar_contract::MAX_RECORD_BYTES + 17)],
        ..Default::default()
    };
    let bytes = Secret::new(serde_json::to_vec(&doc.authoring(&crate::seal::acquire())).unwrap());
    let seal = crate::seal::lend();
    let mut rows = migration_rows(&bytes, [9; 16]).unwrap();
    let mut assembled = Vec::new();
    let chunks = bytes
        .expose(&seal)
        .len()
        .div_ceil(busbar_contract::MAX_RECORD_BYTES);
    for index in 0..chunks {
        let (address, chunk) = rows.next().unwrap().unwrap();
        assert_eq!(
            address,
            crate::persistence::scoped::migration_address(
                true,
                "busbar.config.overlay",
                SCHEMA,
                &chunk_key(&[9; 16], index as u64)
            )
            .unwrap()
        );
        assert!(chunk.expose(&seal).len() <= busbar_contract::MAX_RECORD_BYTES);
        assembled.extend_from_slice(chunk.expose(&seal));
    }
    assert_eq!(&assembled, bytes.expose(&seal));
    let (address, manifest) = rows.next().unwrap().unwrap();
    assert_eq!(
        address,
        crate::persistence::scoped::migration_address(true, "busbar.config.overlay", SCHEMA, HEAD)
            .unwrap()
    );
    let manifest: Head = serde_json::from_slice(manifest.expose(&seal)).unwrap();
    assert_eq!(manifest.length as usize, assembled.len());
    assert_eq!(manifest.digest, Sha256::digest(&assembled));
    assert!(rows.next().is_none());
    assert!(migration_rows(&Secret::new(br#"{"version":999}"#.to_vec()), [9; 16]).is_err());
}

fn settings(fee: i64) -> RootSettings {
    RootSettings {
        per_request_fee: Some(fee),
        ..Default::default()
    }
}

#[tokio::test]
async fn native_overlay_rejects_a_stale_carrier_until_explicit_reload() {
    let core = crate::real_store::core().await;
    let first = OverlayStore::from_core(core.clone()).unwrap();
    assert!(first.read_required_async().await.unwrap().is_none());
    let other = OverlayStore::from_core(core).unwrap();
    persist_root_async(Some(&other), &settings(2))
        .await
        .unwrap();
    assert!(persist_root_async(Some(&first), &settings(3))
        .await
        .is_err());
    let (reloaded, doc) = first.reopen_for_reload_async().await.unwrap();
    assert_eq!(doc.unwrap().root.unwrap().per_request_fee, Some(2));
    persist_root_async(Some(&reloaded), &settings(3))
        .await
        .unwrap();
    assert!(persist_root_async(Some(&first), &settings(4))
        .await
        .is_err());
}

struct LostPublication {
    inner: Arc<dyn PersistenceBackend>,
    lose: AtomicBool,
    sent: Mutex<Vec<([u8; 16], [u8; 32])>>,
}
impl PersistenceBackend for LostPublication {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        candidate: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            let publication = candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, busbar_contract::persistence::Mutation::Put { address, .. } if address.key.ends_with(HEAD)));
            if publication {
                self.sent
                    .lock()
                    .unwrap()
                    .push((candidate.candidate().id.operation, candidate.fingerprint()));
            }
            let answer = self.inner.commit(candidate, key).await?;
            if publication && self.lose.swap(false, Ordering::SeqCst) {
                Err(Failure::Unknown)
            } else {
                Ok(answer)
            }
        })
    }
}

#[tokio::test]
async fn lost_native_publication_replays_its_exact_candidate_before_new_edits() {
    let backend = Arc::new(LostPublication {
        inner: crate::real_store::native_backend().await,
        lose: AtomicBool::new(false),
        sent: Mutex::new(Vec::new()),
    });
    let core = crate::real_store::core_over(backend.clone()).await;
    let overlay = OverlayStore::from_core(core).unwrap();
    backend.sent.lock().unwrap().clear();
    backend.lose.store(true, Ordering::SeqCst);
    assert!(persist_root_async(Some(&overlay), &settings(7))
        .await
        .is_err());
    assert!(persist_root_async(Some(&overlay), &settings(99))
        .await
        .is_err());
    let sent = backend.sent.lock().unwrap().clone();
    assert!(sent.len() >= 2);
    assert_eq!(sent[0], sent[1]);
    let (reloaded, doc) = overlay.reopen_for_reload_async().await.unwrap();
    assert_eq!(doc.unwrap().root.unwrap().per_request_fee, Some(7));
    persist_root_async(Some(&reloaded), &settings(8))
        .await
        .unwrap();
}
