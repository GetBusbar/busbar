// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

static DATA_WORKERS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

pub fn set_data_workers(n: usize) {
    let _ = DATA_WORKERS.set(n.max(1));
}

thread_local! {
    /// This thread's data-plane worker id (0..N), or `usize::MAX` on every non-worker thread
    /// (the control runtime, the blocking pool). A plain `Cell` read — no atomic — because the id
    /// is a per-thread constant after spawn.
    static WORKER_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

pub fn set_worker_id(id: usize) {
    WORKER_ID.with(|w| w.set(id));
}

pub fn worker_id() -> usize {
    WORKER_ID.with(|w| w.get())
}

pub fn worker_stripes() -> usize {
    DATA_WORKERS.get().copied().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(16)
    }) + 1
}

pub fn worker_stripe(stripes: usize) -> usize {
    let id = worker_id();
    if id == usize::MAX {
        stripes - 1
    } else {
        id.min(stripes - 1)
    }
}

#[cfg(test)]
#[path = "worker_shard_tests.rs"]
mod worker_shard_tests;
