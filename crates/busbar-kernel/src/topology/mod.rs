// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL DATA-PLANE TOPOLOGY (1.6.0 App-retype WEDGE 3-PREP).
//!
//! Neutral PROCESS facts — how many data workers exist and which worker each thread is — published
//! by the composition root and read by the per-worker state stripes. No `App`, no config, no plane
//! vocabulary, and no client: every outbound connection, and its per-worker pool, is the
//! connector's (BUSBAR-1.6.0.md THE DESIGN §8).

// ── DATA-PLANE TOPOLOGY, published once by the composition root ─────────────────────────────────
// The `busbar` binary spawns N per-worker data runtimes (thread-per-core; see main.rs) and tells
// core two things before any request is served: HOW MANY workers exist (sizes the per-worker state
// stripes) and, on each worker thread, WHICH worker this thread is. Both are process-topology facts
// — set at boot, immutable, no config.

/// Total data-plane workers, set once by the composition root before serving. Unset (tests,
/// embedded uses) falls back to the machine-derived default at each consumer.
static DATA_WORKERS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Publish the data-plane worker count. First call wins; later calls are ignored (boot runs once).
pub fn set_data_workers(n: usize) {
    let _ = DATA_WORKERS.set(n.max(1));
}

thread_local! {
    /// This thread's data-plane worker id (0..N), or `usize::MAX` on every non-worker thread
    /// (the control runtime, the blocking pool). A plain `Cell` read — no atomic — because the id
    /// is a per-thread constant after spawn.
    static WORKER_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Mark the current thread as data-plane worker `id`. Called exactly once per worker thread by the
/// composition root, after pinning and before the worker's runtime starts serving.
pub fn set_worker_id(id: usize) {
    WORKER_ID.with(|w| w.set(id));
}

/// The current thread's worker id, or `usize::MAX` for a non-worker thread.
pub fn worker_id() -> usize {
    WORKER_ID.with(|w| w.get())
}

/// Stripe count for per-worker striped store state: one stripe per data worker PLUS one shared
/// FALLBACK stripe (the last) for every non-worker thread. Constant for the process lifetime
/// (`set_data_workers` runs before anything builds; the machine-derived fallback is stable).
pub fn worker_stripes() -> usize {
    DATA_WORKERS.get().copied().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(16)
    }) + 1
}

/// The current thread's stripe index in a `stripes`-slot stripe array: its worker id, or the
/// last (fallback) slot for a non-worker thread. `min`: defensive clamp only.
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
