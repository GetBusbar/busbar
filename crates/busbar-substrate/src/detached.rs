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

/// The bounded post-drain grace for detached work. Long enough for an in-flight webhook/tap
/// delivery or a journal write; short enough that a stuck task cannot hold shutdown hostage.
pub const DETACHED_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Per-worker live-detached-task count with a completion signal. Registered per worker thread by
/// the composition root exactly like the worker id.
pub struct DetachedTasks {
    count: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

impl DetachedTasks {
    pub fn new() -> std::sync::Arc<DetachedTasks> {
        std::sync::Arc::new(DetachedTasks {
            count: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Wait until every tracked task has finished (returns immediately when none are live).
    /// Caller bounds it with [`DETACHED_DRAIN_GRACE`].
    pub async fn drained(&self) {
        loop {
            // Arm the waiter BEFORE the count check (the reverse order loses a wakeup racing the
            // last decrement).
            let notified = self.notify.notified();
            if self.count.load(std::sync::atomic::Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// Count guard living INSIDE the spawned future, so an abort (future dropped) decrements exactly
/// like completion does.
struct DetachedGuard(std::sync::Arc<DetachedTasks>);
impl Drop for DetachedGuard {
    fn drop(&mut self) {
        if self
            .0
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.0.notify.notify_waiters();
        }
    }
}

thread_local! {
    /// This worker thread's tracker, set once at spawn (like `WORKER_ID`); `None` on non-worker
    /// threads, where detached spawns behave exactly as before.
    static DETACHED: std::cell::RefCell<Option<std::sync::Arc<DetachedTasks>>> =
        const { std::cell::RefCell::new(None) };
}

/// Register the current worker thread's tracker (composition root, once per worker, at spawn).
pub fn set_worker_detached(t: std::sync::Arc<DetachedTasks>) {
    DETACHED.with(|d| *d.borrow_mut() = Some(t));
}

/// Spawn request-outliving work: tracked on a data worker (so shutdown grants it the bounded
/// drain grace), a plain `tokio::spawn` anywhere else. The wrapper is a `Drop` guard inside the
/// future, so completion AND abort both settle the count.
pub fn spawn_detached<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let tracker = DETACHED.with(|d| d.borrow().clone());
    match tracker {
        Some(t) => {
            t.count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let guard = DetachedGuard(t);
            tokio::spawn(async move {
                let _guard = guard;
                fut.await
            })
        }
        None => tokio::spawn(fut),
    }
}

#[cfg(test)]
#[path = "tests/detached_tests.rs"]
mod detached_tests;
