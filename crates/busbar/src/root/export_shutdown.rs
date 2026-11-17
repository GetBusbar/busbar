// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Export observation settlement inside the existing shutdown authority. Pump and capture
//! quiescence precede intake closure; native audit alone confirms the retained first loss.

use std::sync::Arc;

use crate::root::export_observer::ExportObservers;

/// The real retry worker's lifetime, owned by the published serving generation's root.
pub(crate) struct ExportRetry {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl ExportRetry {
    pub(crate) fn start(observers: Arc<ExportObservers>) -> Self {
        let (stop, receiver) = tokio::sync::watch::channel(false);
        Self {
            stop,
            task: tokio::spawn(observers.run(receiver)),
        }
    }

    /// Only after the final receipt pass. The caller joins under the same shutdown cut.
    pub(super) fn stop(self) -> tokio::task::JoinHandle<()> {
        self.stop.send_replace(true);
        self.task
    }
}

/// Immutable, bounded evidence for the ordinary incomplete-shutdown diagnostic.
pub(super) fn failures(observers: &ExportObservers) -> Vec<String> {
    let mut failures: Vec<_> = observers
        .unresolved()
        .into_iter()
        .map(|facts| {
            format!(
                "export.{} loss receipt unconfirmed: kind={:?} observed_at={} count={}",
                facts.instance, facts.kind, facts.observed_at, facts.count
            )
        })
        .collect();
    let late = observers.late_callbacks();
    if late != 0 {
        failures.push(format!("export observer received {late} late callbacks"));
    }
    failures
}
