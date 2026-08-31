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

/// The worker-shutdown seam beside the tracker: registered per worker thread, captured by clone at
/// spawn, and `shutdown_fired` resolves on the level flipping true — with a CLOSED channel counting
/// as fired (the composition root owns the sender for the process lifetime, so losing it means
/// teardown) and `None` NEVER resolving (a non-worker thread's spawn keeps its pre-seam behaviour).
#[tokio::test(flavor = "current_thread")]
async fn worker_shutdown_registers_and_fires_and_none_never_does() {
    use crate::detached::{set_worker_shutdown, shutdown_fired, worker_shutdown};

    // Unregistered thread: no watch, and the `None` arm never resolves.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), shutdown_fired(None))
            .await
            .is_err(),
        "with no watch registered the shutdown arm must be inert, never instantly fired"
    );

    let (tx, rx) = tokio::sync::watch::channel(false);
    set_worker_shutdown(rx);
    let captured = worker_shutdown().expect("the registered watch is readable on this thread");

    // Not yet fired: the arm waits.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            shutdown_fired(Some(captured.clone()))
        )
        .await
        .is_err(),
        "shutdown_fired must wait while the level is false"
    );

    // Fired: the arm resolves — including for a receiver captured BEFORE the flip.
    let _ = tx.send(true);
    tokio::time::timeout(Duration::from_secs(1), shutdown_fired(Some(captured)))
        .await
        .expect("shutdown_fired must resolve once the level flips true");
    tokio::time::timeout(Duration::from_secs(1), shutdown_fired(worker_shutdown()))
        .await
        .expect("a receiver captured after the flip observes the level, not just the edge");

    // A dropped sender counts as fired — teardown must not strand a waiter.
    let (tx2, rx2) = tokio::sync::watch::channel(false);
    drop(tx2);
    tokio::time::timeout(Duration::from_secs(1), shutdown_fired(Some(rx2)))
        .await
        .expect("a closed watch counts as fired");
}
