// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The core watch: a data core whose plugin entry hung stops taking new connections.
//!
//! A plane crossing is a direct call on the request's core, so a plugin entry that never returns holds that core's
//! thread. The plugin watchdog finds the entry past its ceiling and quarantines the instance, but it cannot free
//! the thread. Each data core beats a counter from a task of its own runtime; the watch, on the control runtime,
//! reads the beats and the watchdog's count of hung entries every [`CHECK`]. A core whose beat stood still while
//! an entry was reported hung is the one holding it ([`Verdicts`]): its `SO_REUSEPORT` listener is stopped from
//! here, so the kernel sends new connections to the other cores. Connections already queued on it are reset unless
//! `net.ipv4.tcp_migrate_req` is 1 (docs/operations.md). The stop is final for the process's life.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_core_connector::listen::ListenStop;
use busbar_kernel::core_watch::Verdicts;

/// How often the cores beat and the watch reads them.
const CHECK: Duration = Duration::from_millis(100);

/// The data cores of one data bind and their listeners' stops.
pub(crate) struct CoreWatch {
    cores: Mutex<Vec<(Arc<AtomicU64>, ListenStop)>>,
}

impl CoreWatch {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            cores: Mutex::new(Vec::new()),
        })
    }

    /// Enrol one core: its listener's stop. The core runs [`beat`] over the returned counter.
    pub(crate) fn enrol(&self, stop: ListenStop) -> Arc<AtomicU64> {
        let beat = Arc::new(AtomicU64::new(0));
        self.cores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((Arc::clone(&beat), stop));
        beat
    }

    /// The watch, on the control runtime, for the process's life: `hung_total` is the watchdog's count of hung
    /// entries.
    pub(crate) async fn run(self: Arc<Self>, hung_total: impl Fn() -> u64) {
        let mut verdicts = Verdicts::default();
        let mut tick = tokio::time::interval(CHECK);
        let mut beats = Vec::new();
        loop {
            tick.tick().await;
            beats.clear();
            beats.extend(
                self.cores
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .map(|(beat, _)| beat.load(Ordering::Relaxed)),
            );
            for core in verdicts.check(&beats, hung_total()) {
                tracing::error!(
                    core,
                    "core_stopped: a plugin entry hung on this data core; its listener is closed and new \
                     connections go to the other cores"
                );
                if let Some((_, stop)) = self
                    .cores
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(core)
                {
                    stop.stop();
                }
            }
        }
    }
}

/// One core's beat, on that core's own runtime: a hung core stops beating.
pub(crate) async fn beat(beat: Arc<AtomicU64>) {
    let mut tick = tokio::time::interval(CHECK);
    loop {
        tick.tick().await;
        beat.fetch_add(1, Ordering::Relaxed);
    }
}
