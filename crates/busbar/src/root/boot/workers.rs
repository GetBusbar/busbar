// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Candidate-owned maintenance work. Construction never polls or starts a worker.

use std::{future::Future, pin::Pin};

pub(crate) struct PreparedWorkers {
    work: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl PreparedWorkers {
    pub(crate) fn new() -> Self {
        Self { work: Vec::new() }
    }

    pub(crate) fn push(&mut self, work: impl Future<Output = ()> + Send + 'static) {
        self.work.push(Box::pin(work));
    }

    /// Consumed by root only after the generation's serving routes are published.
    pub(crate) fn start(self) -> RunningWorkers {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let handles = self
            .work
            .into_iter()
            .map(|work| {
                let mut stopped = stopped.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        biased;
                        _ = stopped.changed() => {}
                        () = work => {}
                    }
                })
            })
            .collect();
        RunningWorkers { stop, handles }
    }
}

/// Retains all joins. Dropping the owner also closes the stop channel; shutdown normally
/// consumes `stop` under its existing deadline and refuses Store retirement on failure.
pub(crate) struct RunningWorkers {
    stop: tokio::sync::watch::Sender<bool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningWorkers {
    pub(crate) async fn stop(self) -> Result<(), String> {
        let Self { stop, handles } = self;
        stop.send_replace(true);
        let mut errors = Vec::new();
        for handle in handles {
            if let Err(error) = handle.await {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
