// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// ── DETACHED-WORK DRAIN (thread-per-core shutdown) ──────────────────────────────────────────────
//
// Work spawned FROM a request that must outlive its connection (an MCP task runner, a webhook
// delivery, a tap notification, an A2A outcome watcher) lives on the worker runtime that spawned
// it. When that runtime drops at graceful drain, every such task aborts — under the old topology
// they died at process teardown instead, an ACCIDENTAL later abort, not a designed one. This
// tracker makes the window designed: each worker counts its live detached tasks, and after its
// listener drains it waits ONE bounded grace for them to finish before the runtime drops. No
// knob — the grace is a documented constant; N = 1 runs the identical code.

pub const DETACHED_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// The worker's live detached tasks, counted by a `tokio_util` `TaskTracker`. A task's count is
/// released only after its future (and so any custody it holds) has dropped, so `drained` cannot
/// return while accepted work is still cleaning up.
pub struct DetachedTasks {
    tracker: tokio_util::task::TaskTracker,
}

impl DetachedTasks {
    pub fn new() -> std::sync::Arc<DetachedTasks> {
        std::sync::Arc::new(DetachedTasks {
            tracker: tokio_util::task::TaskTracker::new(),
        })
    }

    /// Finishes once no detached task is live. Closing the tracker only lets `wait` finish when it
    /// is empty; later spawns are still counted.
    pub async fn drained(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }

    pub fn spawn_on<F>(
        self: &std::sync::Arc<Self>,
        runtime: &tokio::runtime::Handle,
        fut: F,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tracker.spawn_on(fut, runtime)
    }
}

thread_local! {
    /// This worker thread's tracker, set once at spawn (like `WORKER_ID`); `None` on non-worker
    /// threads, where detached spawns behave exactly as before.
    static DETACHED: std::cell::RefCell<Option<std::sync::Arc<DetachedTasks>>> =
        const { std::cell::RefCell::new(None) };
}

pub fn set_worker_detached(t: std::sync::Arc<DetachedTasks>) {
    DETACHED.with(|d| *d.borrow_mut() = Some(t));
}

pub fn worker_detached() -> Option<std::sync::Arc<DetachedTasks>> {
    DETACHED.with(|d| d.borrow().clone())
}

thread_local! {
    /// This worker thread's view of the process shutdown broadcast, set once at spawn exactly like
    /// the detached tracker above; `None` on non-worker threads, where detached work keeps its
    /// pre-seam behaviour (no early shutdown arm — it is aborted when its runtime drops).
    static SHUTDOWN: std::cell::RefCell<Option<tokio::sync::watch::Receiver<bool>>> =
        const { std::cell::RefCell::new(None) };
}

pub fn set_worker_shutdown(rx: tokio::sync::watch::Receiver<bool>) {
    SHUTDOWN.with(|s| *s.borrow_mut() = Some(rx));
}

pub fn worker_shutdown() -> Option<tokio::sync::watch::Receiver<bool>> {
    SHUTDOWN.with(|s| s.borrow().clone())
}

pub async fn shutdown_fired(rx: Option<tokio::sync::watch::Receiver<bool>>) {
    let Some(mut rx) = rx else {
        return std::future::pending().await;
    };
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

pub fn spawn_detached<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let tracker = worker_detached();
    match tracker {
        Some(t) => t.spawn_on(&tokio::runtime::Handle::current(), fut),
        None => tokio::spawn(fut),
    }
}

#[cfg(test)]
#[path = "tests/detached_tests.rs"]
mod detached_tests;
