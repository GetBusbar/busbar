// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use tokio::sync::broadcast;

static SHUTDOWN: OnceLock<broadcast::Sender<()>> = OnceLock::new();

static DRAIN_AT_EXIT: AtomicBool = AtomicBool::new(false);

static DRAIN_ASKED: AtomicU64 = AtomicU64::new(NO_UNIT);

const NO_UNIT: u64 = 0;

pub const UNKEYED_UNIT: u64 = u64::MAX;

tokio::task_local! {
    /// The unit whose work is executing on this task.
    ///
    /// A task-local rather than a thread-local because the operation's body runs on a task the seam
    /// spawned, not on the blocking worker the loop walks on: a thread-local set by the walker would
    /// be invisible exactly where the handler that asks for the drain runs.
    static ASKING_UNIT: u64;
}

async fn as_unit<F>(unit: u64, f: F) -> F::Output
where
    F: std::future::Future,
{
    ASKING_UNIT.scope(unit, f).await
}

pub struct UnitDrain {
    unit: u64,
}

impl UnitDrain {
    #[must_use]
    pub fn of_unit(unit: u64) -> Self {
        UnitDrain { unit }
    }

    pub async fn scoping<F>(&self, f: F) -> F::Output
    where
        F: std::future::Future,
    {
        as_unit(self.unit, f).await
    }

    pub fn release(&self) -> bool {
        release_asked_drain(self.unit)
    }
}

fn asking_unit() -> u64 {
    ASKING_UNIT.try_with(|unit| *unit).unwrap_or(UNKEYED_UNIT)
}

pub fn publish_shutdown(tx: broadcast::Sender<()>) {
    let _ = SHUTDOWN.set(tx);
}

pub fn drain_released_at_exit() {
    DRAIN_AT_EXIT.store(true, Ordering::Release);
}

fn release_asked_drain(unit: u64) -> bool {
    if DRAIN_ASKED
        .compare_exchange(unit, NO_UNIT, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    send_shutdown();
    true
}

fn send_shutdown() {
    if let Some(tx) = SHUTDOWN.get() {
        let _ = tx.send(());
    }
}

pub(crate) fn can_restart() -> bool {
    SHUTDOWN.get().is_some()
}

pub fn begin_drain() {
    if DRAIN_AT_EXIT.load(Ordering::Acquire) {
        DRAIN_ASKED.store(asking_unit(), Ordering::Release);
        return;
    }
    send_shutdown();
}

const SUPERVISOR_MARKERS: [&str; 2] = ["INVOCATION_ID", "KUBERNETES_SERVICE_HOST"];

pub(crate) fn supervisor_detected() -> bool {
    supervisor_detected_in(|k| std::env::var_os(k).is_some())
}

fn supervisor_detected_in(present: impl Fn(&str) -> bool) -> bool {
    SUPERVISOR_MARKERS.iter().any(|k| present(k))
}

#[cfg(test)]
#[path = "tests/restart.rs"]
mod tests;
