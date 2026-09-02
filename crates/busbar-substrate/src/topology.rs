// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL DATA-PLANE TOPOLOGY + the sharded upstream client (1.6.0 App-retype WEDGE 3-PREP).
//!
//! Relocated DOWN from `busbar_core::state` so a plane crate names the sharded egress client and the
//! worker-topology facts without reaching into `busbar-core`. These are neutral PROCESS facts — how
//! many data workers exist and which worker each thread is — plus the per-worker-sharded upstream
//! HTTP client those facts size. No `App`, no config, no plane vocabulary; the sole value type
//! ([`UpstreamClients`]) holds a set of the substrate egress engine's own [`EngineClient`] shards.
//! Core re-exports each item at its historical `busbar_core::state::…` path (the `pub(crate)` worker
//! accessors kept `pub(crate)` on the re-export) so every in-core call site — the composition root's
//! boot publish, the store-striping readers, `appbuild`'s client build — is unchanged.

use std::sync::Arc;

use crate::egress::engine::EngineClient as Client;

// ── DATA-PLANE TOPOLOGY, published once by the composition root ─────────────────────────────────
// The `busbar` binary spawns N per-worker data runtimes (thread-per-core; see main.rs) and tells
// core two things before any request is served: HOW MANY workers exist (sizes the client shards
// below, and the per-worker state stripes later stages add) and, on each worker thread, WHICH
// worker this thread is. Both are process-topology facts — set at boot, immutable, no config.

/// Total data-plane workers, set once by the composition root before serving. Unset (tests,
/// embedded uses) falls back to the machine-derived default at each consumer.
static DATA_WORKERS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Publish the data-plane worker count. First call wins; later calls are ignored (boot runs once).
pub fn set_data_workers(n: usize) {
    let _ = DATA_WORKERS.set(n.max(1));
    // The egress engine's connect gate sizes its per-shard establishment share from this same
    // topology fact — the engine lives in this crate, so the publish FORWARDS in the same boot act:
    // one composition-root call, two subscribers, no second source of the number.
    crate::egress::engine::set_establishment_shards(n);
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

/// The upstream HTTP client, SHARDED: N identical `reqwest::Client`s, each owning its own
/// connection pool, one selected per thread. ONE shared client meant one pool mutex that every
/// request crossed twice (connection checkout + checkin) across every worker — a lock convoy
/// that grows with core count (measured: throughput fell ~36% from concurrency 64 → 1024 on a
/// 4-core pin, and inverted busbar's standing against per-worker-sharded gateways on 32-thread
/// x86). Each worker thread is assigned one shard on first use and keeps it: warm connections
/// and TLS sessions stay worker-local, and each shard's pool lock is contended by ~1/Nth of the
/// threads. NOT configurable — the shard count is one per data-plane worker (published by the
/// composition root; machine-derived fallback for embedded/test uses) and the per-host idle
/// budget is divided across shards so the TOTAL kept-alive sockets toward any upstream are
/// unchanged.
#[derive(Clone)]
pub struct UpstreamClients {
    shards: Arc<[Client]>,
}

impl UpstreamClients {
    /// The shard count: ONE SHARD PER DATA-PLANE WORKER when the composition root published the
    /// count (`set_data_workers` — the thread-per-core binary always does), so every worker gets a
    /// pool of its own and shard selection is a direct index by worker id. Unset (tests, embedded
    /// uses that never call `set_data_workers`) falls back to the machine-derived
    /// `min(cores, 16).next_power_of_two()` the pre-topology sharding used.
    pub fn shard_count() -> usize {
        match DATA_WORKERS.get() {
            Some(&n) => n,
            None => {
                let n = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .next_power_of_two()
                    .min(16);
                // UNPUBLISHED-TOPOLOGY UNIFICATION: the engine's
                // establishment machinery (connect gate permits + the pool's dial bound) divides
                // one GLOBAL per-authority budget by the shard count. When the composition root
                // never published a worker count (tests, embedded uses), this fallback is the
                // shard count — so it must ALSO be the establishment divisor, or an unpublished
                // build runs up to 16 pools × an undivided per-shard budget (16× the invariant).
                // Publishing the value HERE — from the one function that derives it — keeps a
                // single source instead of the engine re-deriving the formula (the exact drift
                // shape the single-source rule forbids). First call wins on both sides; the
                // thread-per-core binary always publishes at boot and never gets here.
                crate::egress::engine::set_establishment_shards(n);
                n
            }
        }
    }

    /// Build N shards from a builder factory (each shard is an IDENTICAL client; reqwest clients
    /// cannot be cloned into independent pools, so the builder runs once per shard).
    pub fn build(count: usize, mut make: impl FnMut() -> Client) -> Self {
        let shards: Arc<[Client]> = (0..count.max(1)).map(|_| make()).collect();
        UpstreamClients { shards }
    }

    /// This thread's client. A DATA-PLANE WORKER (id set at spawn) indexes its own shard directly —
    /// one thread-local `Cell` read, no shared write ever, and its warm connections/TLS sessions
    /// never cross another worker's pool lock. Any OTHER thread (the control runtime's prober,
    /// blocking-pool threads, non-unix workers without ids) keeps the prior behavior: assigned a
    /// shard round-robin on FIRST use for its lifetime — a once-per-thread counter bump, never a
    /// per-request write.
    pub fn get(&self) -> &Client {
        let id = worker_id();
        if id != usize::MAX {
            // min: defensive only — the composition root sizes shards to the worker count, so a
            // worker id is always in range.
            return &self.shards[id.min(self.shards.len() - 1)];
        }
        static NEXT_THREAD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        thread_local! {
            static SHARD: std::cell::OnceCell<usize> = const { std::cell::OnceCell::new() };
        }
        let idx = SHARD.with(|s| {
            *s.get_or_init(|| NEXT_THREAD.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        });
        // Modulo, not mask: with worker-published counts the shard count is exact (= N workers),
        // not a power of two. Cold path — the result is cached per thread above.
        &self.shards[idx % self.shards.len()]
    }

    /// Do two `UpstreamClients` share the SAME underlying shard set (`Arc::ptr_eq`)? True exactly
    /// when one was cloned from the other (a config apply that REUSED the prior client for pool
    /// warmth); false when the shards were freshly built. Lets the apply path — and its tests —
    /// distinguish "carried the warm pool forward" from "rebuilt with new client settings".
    #[cfg(any(test, feature = "test-support"))]
    pub fn shares_pool_with(&self, other: &UpstreamClients) -> bool {
        Arc::ptr_eq(&self.shards, &other.shards)
    }
}

#[cfg(test)]
#[path = "topology/worker_shard_tests.rs"]
mod worker_shard_tests;
