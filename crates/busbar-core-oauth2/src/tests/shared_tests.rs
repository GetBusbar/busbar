// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn shared(store: Arc<busbar_kernel::persistence::facade::CoreStore>) -> Arc<Shared> {
    Arc::new(Shared::new(Arc::new(
        ScopedStore::host_private(store, "oauth-as", Shared::schemas()).unwrap(),
    )))
}

fn client(id: &str) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth: oauth_as::client::ClientAuth::Public,
        grant_types: vec![oauth_as::grant::GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".into()],
        allowed_scopes: oauth_as::scope::ScopeSet::default(),
        default_scopes: oauth_as::scope::ScopeSet::default(),
        name: Some(id.into()),
        registration: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_backed_server_holds_the_storage_contract() {
    let violations = oauth_as::storage_conformance::StorageConformance::new(|| async {
        SharedStorage::new(shared(crate::testkit::memory_store().await))
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .run()
    .await;
    assert!(violations.is_empty(), "{violations:#?}");
}

#[tokio::test]
async fn native_records_exceed_the_plane_bound_and_survive_reopen() {
    let store = crate::testkit::memory_store().await;
    let a = SharedStorage::new(shared(store.clone()));
    let mut value = client("large");
    value.name = Some("x".repeat(8192));
    a.put_client(value.clone()).await.unwrap();
    let b = SharedStorage::new(shared(store));
    assert_eq!(
        *b.get_client(&value.client_id).await.unwrap().unwrap(),
        value
    );
}

#[tokio::test]
async fn signing_key_is_shared_between_fresh_owners() {
    let store = crate::testkit::memory_store().await;
    assert_eq!(
        shared(store.clone())
            .signing_key(|| Ok(vec![1, 2, 3]))
            .await
            .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        shared(store)
            .signing_key(|| panic!("existing key must be read"))
            .await
            .unwrap(),
        vec![1, 2, 3]
    );
}

#[tokio::test]
async fn ambiguous_record_commit_settles_the_original_candidate() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let store = crate::testkit::memory_store_on(backend.clone()).await;
    let s = shared(store.clone());
    crate::testkit::lose_next_reply(&backend);
    let a = SharedStorage::new(s.clone());
    let value = client("unknown");
    assert!(a.put_client(value.clone()).await.is_err());
    assert!(!s.pending.lock().unwrap().is_empty());
    assert_eq!(
        *a.get_client(&value.client_id).await.unwrap().unwrap(),
        value
    );
    assert!(s.pending.lock().unwrap().is_empty());
    let b = SharedStorage::new(shared(store));
    assert!(b.get_client(&value.client_id).await.unwrap().is_some());
}

#[tokio::test]
async fn native_claim_expiry_and_single_use_apply_across_fresh_owners() {
    let store = crate::testkit::memory_store().await;
    let a = shared(store.clone());
    let b = shared(store);
    assert!(!a
        .claim("replay", "expired", now_secs().saturating_sub(1))
        .await
        .unwrap());
    let until = now_secs() + 60;
    let (first, second) = tokio::join!(
        a.claim("replay", "once", until),
        b.claim("replay", "once", until)
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(|won| *won)
            .count(),
        1
    );
}

#[tokio::test]
async fn ambiguous_claim_is_retried_with_its_original_expiry() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let s = shared(crate::testkit::memory_store_on(backend.clone()).await);
    let expiry = now_secs() + 60;
    crate::testkit::lose_next_reply(&backend);
    assert!(s.claim("spent", "single", expiry).await.is_err());
    assert!(s.claim("spent", "single", expiry + 1).await.is_err());
    assert!(s.claim("spent", "single", expiry).await.unwrap());
    assert!(!s.claim("spent", "single", expiry).await.unwrap());
}

#[tokio::test]
async fn cancelled_record_submission_retains_original_request() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let s = shared(crate::testkit::memory_store_on(backend.clone()).await);
    let value = client("cancelled");
    backend
        .hang
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let storage = SharedStorage::new(s.clone());
    {
        let mut write = Box::pin(storage.put_client(value.clone()));
        assert!(futures::poll!(&mut write).is_pending());
    }
    assert!(!s.pending.lock().unwrap().is_empty());
    backend
        .hang
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        *storage.get_client(&value.client_id).await.unwrap().unwrap(),
        value
    );
    assert!(s.pending.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancelled_claim_retains_original_expiry_and_native_candidate() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let s = shared(crate::testkit::memory_store_on(backend.clone()).await);
    let expiry = now_secs() + 60;
    backend
        .hang
        .store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let mut claim = Box::pin(s.claim("spent", "cancelled", expiry));
        assert!(futures::poll!(&mut claim).is_pending());
    }
    backend
        .hang
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(s.claim("spent", "cancelled", expiry + 1).await.is_err());
    assert!(s.claim("spent", "cancelled", expiry).await.unwrap());
    assert!(!s.claim("spent", "cancelled", expiry).await.unwrap());
}

#[tokio::test]
async fn prior_logical_cell_boundary_remains_writable_and_scannable() {
    let shared = shared(crate::testkit::memory_store().await);
    let schema = atomic_schema("key");
    assert_eq!(
        shared
            .submit(Shared::candidate(
                &schema,
                "boundary",
                None,
                vec![b'x'; MAX_LOGICAL_CELL_BYTES]
            ))
            .await
            .unwrap(),
        Decision::Applied
    );
    let page = shared.store.page(&schema, b"", None).await.unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        page.rows[0].1.expose(&busbar_kernel::seal::lend()).len(),
        MAX_LOGICAL_CELL_BYTES
    );
    assert!(shared
        .submit(Shared::candidate(
            &schema,
            "oversize",
            None,
            vec![b'x'; MAX_LOGICAL_CELL_BYTES + 1]
        ))
        .await
        .is_err());
    assert!(shared
        .store
        .get(&schema, b"oversize")
        .await
        .unwrap()
        .is_none());
}
