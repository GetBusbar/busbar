// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::AsyncClaimSet;
use std::sync::Arc;

#[tokio::test]
async fn same_key_waits_while_other_keys_progress() {
    let claims = AsyncClaimSet::new();
    let first = claims.claim_async("key").await;
    assert!(claims.try_claim("key").is_none());
    assert!(claims.try_claim("key").is_none());
    let next = claims.claim_async("key");
    tokio::pin!(next);
    assert!(futures::poll!(&mut next).is_pending());
    let independent = claims.claim_async("other").await;
    drop(independent);
    drop(first);
    let _next = next.await;
}

#[tokio::test]
async fn cancellation_releases_owned_key_without_retaining_waiter_keys() {
    let claims = Arc::new(AsyncClaimSet::new());
    let owned = claims.clone();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(async move {
        let _claim = owned.claim_async("key").await;
        entered.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    ready.await.unwrap();
    let waiter = claims.claim_async("key");
    tokio::pin!(waiter);
    assert!(futures::poll!(&mut waiter).is_pending());
    assert_eq!(claims.held.lock().unwrap().len(), 1);
    driver.abort();
    assert!(driver.await.unwrap_err().is_cancelled());
    let next = waiter.await;
    drop(next);
    assert!(claims.held.lock().unwrap().is_empty());
}
