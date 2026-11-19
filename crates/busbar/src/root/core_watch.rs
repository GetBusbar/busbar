// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The core watch: a data core held by a hung plugin entry stops taking new connections, and rejoins when the
//! entry returns.
//!
//! A plane crossing is a direct call on the request's core, so a plugin entry that never returns holds that core's
//! thread. The plugin watchdog finds the entry past its ceiling and quarantines the instance, but it cannot free
//! the thread. The watch rides the engine's housekeeping tick (`advanced.usage_flush_interval_ms`, the budget
//! flusher's loop); when the watchdog has reported a hung entry it nudges each data core (one beat task on the
//! core's own runtime) and, at the next tick, a core that has not run its nudge is the one holding the entry
//! ([`Verdicts`]): its `SO_REUSEPORT` listener is stopped, so the kernel sends new connections to the other cores.
//! Connections already queued on it are reset unless `net.ipv4.tcp_migrate_req` is 1 (docs/operations.md). When
//! the stopped core runs its nudge, its entry has returned: a new listener joins the group for it. With no hung
//! entry the tick costs one atomic load and nothing more.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_core_connector::listen::ListenStop;
use busbar_kernel::core_watch::{Tick, Verdicts};

/// One data core: its beat (advanced only by a nudge), its listener's stop, and its runtime.
struct Core {
    beat: Arc<AtomicU64>,
    stop: ListenStop,
    runtime: tokio::runtime::Handle,
}

/// The data cores and the watch's reading of them.
pub(crate) struct CoreWatch {
    cores: Mutex<Vec<Core>>,
    verdicts: Mutex<Verdicts>,
    hung_total: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl CoreWatch {
    /// `hung_total` is the plugin watchdog's count of hung entries.
    pub(crate) fn new(hung_total: impl Fn() -> u64 + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            cores: Mutex::new(Vec::new()),
            verdicts: Mutex::new(Verdicts::default()),
            hung_total: Box::new(hung_total),
        })
    }

    /// Enrol the calling data core: its listener's stop, on its own runtime.
    pub(crate) fn enrol(&self, stop: ListenStop) {
        self.cores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Core {
                beat: Arc::new(AtomicU64::new(0)),
                stop,
                runtime: tokio::runtime::Handle::current(),
            });
    }

    /// The housekeeping tick's hook.
    pub(crate) fn tick(self: &Arc<Self>) -> Tick {
        let watch = Arc::clone(self);
        Box::new(move || watch.check())
    }

    /// The watch's own wake, for an engine with no housekeeping tick (no governance: the budget flusher does not
    /// run): the same configured interval, so the watch reads the cores at the cadence it would have.
    pub(crate) async fn run_alone(self: Arc<Self>) {
        busbar_kernel::core_watch::tick_alone(self.tick()).await;
    }

    fn check(&self) {
        let beats: Vec<u64> = self
            .cores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|core| core.beat.load(Ordering::Relaxed))
            .collect();
        let step = self
            .verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check(&beats, (self.hung_total)());
        if step == busbar_kernel::core_watch::Step::default() {
            return;
        }
        let cores = self.cores.lock().unwrap_or_else(PoisonError::into_inner);
        for &i in &step.stop {
            tracing::error!(
                core = i,
                "core_stopped: a plugin entry hung on this data core; its listener is closed and new \
                 connections go to the other cores until the entry returns"
            );
            if let Some(core) = cores.get(i) {
                core.stop.stop();
            }
        }
        for &i in &step.resume {
            tracing::warn!(
                core = i,
                "core_resumed: the hung plugin entry on this data core returned; a new listener joins the data port"
            );
            if let Some(core) = cores.get(i) {
                core.stop.resume();
            }
        }
        for &i in &step.nudge {
            if let Some(core) = cores.get(i) {
                let beat = Arc::clone(&core.beat);
                drop(core.runtime.spawn(async move {
                    beat.fetch_add(1, Ordering::Relaxed);
                }));
            }
        }
    }
}
