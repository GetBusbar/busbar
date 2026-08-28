// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The detached-work drain seam: a tracked spawn holds `drained()` open until it finishes; an
//! ABORT settles the count exactly like completion (the guard lives inside the future); an
//! untracked thread's spawn behaves like plain `tokio::spawn` and never blocks anyone's drain.

use crate::detached::{set_worker_detached, spawn_detached, DetachedTasks};
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn drained_waits_for_completion_and_settles_on_abort() {
    let t = DetachedTasks::new();
    set_worker_detached(t.clone());

    // A tracked task holds the drain open until it completes.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let h = spawn_detached(async move {
        let _ = rx.await;
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), t.drained())
            .await
            .is_err(),
        "drained() must wait while a tracked task is live"
    );
    let _ = tx.send(());
    let _ = h.await;
    tokio::time::timeout(Duration::from_secs(1), t.drained())
        .await
        .expect("drained() must resolve once the tracked task completes");

    // An ABORTED task settles the count too — the guard drops with the future.
    let h = spawn_detached(async {
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    h.abort();
    tokio::time::timeout(Duration::from_secs(1), t.drained())
        .await
        .expect("an aborted tracked task must settle the drain");
}

#[tokio::test(flavor = "current_thread")]
async fn untracked_thread_spawns_plainly() {
    // No tracker registered on this thread: spawn works, and a fresh tracker drains immediately.
    let h = spawn_detached(async { 7 });
    assert_eq!(h.await.unwrap(), 7);
    let t = DetachedTasks::new();
    tokio::time::timeout(Duration::from_millis(100), t.drained())
        .await
        .expect("an empty tracker drains immediately");
}
