// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel test binary's allocator: jemalloc, counted process-wide by `stats_alloc`
//! (UNSAFE-MIN §4.4). The allocation gates read the count through [`CountingJemalloc`], which keeps
//! the API they always had. The telemetry tests read jemalloc's own per-thread counters.

use stats_alloc::StatsAlloc;
use std::sync::atomic::{AtomicU64, Ordering};
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: StatsAlloc<Jemalloc> = StatsAlloc::new(Jemalloc);

/// The count `reset` last took, subtracted from every reading.
static BASE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct CountingJemalloc;

impl CountingJemalloc {
    /// Allocations and reallocations since the last [`reset`](Self::reset). Deallocations are not
    /// counted: the gates measure allocation COUNT.
    pub(crate) fn count() -> u64 {
        Self::total().saturating_sub(BASE.load(Ordering::Relaxed))
    }

    /// Start counting again from zero, returning what the count was.
    pub(crate) fn reset() -> u64 {
        let total = Self::total();
        total.saturating_sub(BASE.swap(total, Ordering::Relaxed))
    }

    fn total() -> u64 {
        let stats = ALLOCATOR.stats();
        stats.allocations as u64 + stats.reallocations as u64
    }
}
