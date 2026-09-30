// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE DISPATCHER (BUSBAR-1.6.0.md THE DESIGN, §11.2: one entry point per plugin,
//! one loading path, one dispatcher). The composition root builds it at boot, one plugin worker per
//! data worker, and every kind's wiring reaches its plugins through it: the root opens each kind's
//! instances on it and hands the kernel contract-level per-kind handles (`busbar_contract::*_calls`),
//! so the kernel never names the loader or this dispatcher.
//!
//! Built once; the first build stands. A build that never booted (a test binary) gets the default
//! shape on first use.

use std::sync::{Arc, OnceLock};

use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};

static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();

/// The dispatcher's shape for `workers` data workers: one plugin worker each, the default watchdog
/// budgets. Host services are bound when the kernel serves them (BUSBAR-1.6.0.md THE DESIGN, §11.5,
/// `abi/host/`).
#[must_use]
pub fn config(workers: usize) -> DispatchConfig {
    DispatchConfig {
        workers: u32::try_from(workers).unwrap_or(u32::MAX).max(1),
        ..DispatchConfig::default()
    }
}

/// Build the process's dispatcher for `workers` data workers, at boot, before any plugin loads.
/// The first build stands; a later call answers it.
pub fn boot(workers: usize) -> Arc<Dispatcher> {
    Arc::clone(DISPATCHER.get_or_init(|| Arc::new(Dispatcher::new(config(workers)))))
}

/// The process's dispatcher (built at boot; built with one worker on first use where no boot ran).
#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    boot(1)
}

#[cfg(test)]
#[path = "tests/dispatch.rs"]
mod tests;
