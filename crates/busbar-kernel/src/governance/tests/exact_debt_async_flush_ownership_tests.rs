// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::BudgetFlushRunner;
use std::sync::Arc;

#[tokio::test]
async fn final_flush_yields_until_the_active_future_releases_custody() {
    let runner = BudgetFlushRunner::default();
    let active = runner.try_enter().unwrap();
    let final_flush = runner.enter(true);
    tokio::pin!(final_flush);
    assert!(futures::poll!(&mut final_flush).is_pending());
    assert!(runner.try_enter().is_err());
    drop(active);
    let _joined = final_flush.await.unwrap();
}

#[tokio::test]
async fn cancelled_driver_releases_ownership_for_exact_retained_retry() {
    let runner = Arc::new(BudgetFlushRunner::default());
    let retained = runner.clone();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(async move {
        let _owner = retained.enter(true).await.unwrap();
        entered.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    ready.await.unwrap();
    assert!(runner.try_enter().is_err());
    driver.abort();
    assert!(driver.await.unwrap_err().is_cancelled());
    assert!(runner.try_enter().is_ok());
}
