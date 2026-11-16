// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-request work counters for the CI work-budget gate (`perf/work-budget.toml`).
//!
//! A deterministic count of work, not a timing. The host bumps one counter at each boundary it
//! owns: [`Work::Crossing`] where the loader calls into a plugin, [`Work::StoreRoundTrip`] where
//! the loader submits one request to the store plugin. The heap allocations are read from the test binary's own
//! `#[global_allocator]` (a `stats_alloc::StatsAlloc` over jemalloc), which it names through
//! [`count_allocations_through`].
//!
//! Test support only: the counters and `Tally` exist only when this crate is built
//! with `test-support`, which only `[dev-dependencies]` enable and no shipping build does. [`Work`]
//! and [`tally`] stay in every build so the host's boundaries can name the work they do; without
//! the feature [`tally`] is an empty inline function.

#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicU64, Ordering};

/// One kind of counted work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// One call from the loader into a plugin (the loader boundary).
    Crossing,
    /// One request submitted to the store plugin and answered.
    StoreRoundTrip,
    /// One clock read by a connector drive (its lazy `now`: at most one per drive).
    ClockRead,
}

#[cfg(feature = "test-support")]
static CROSSINGS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "test-support")]
static STORE_ROUND_TRIPS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "test-support")]
static CLOCK_READS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "test-support")]
static ALLOCATION_SOURCE: std::sync::OnceLock<fn() -> u64> = std::sync::OnceLock::new();

/// Name how to read the heap-allocation count of this test binary's global allocator (allocations plus
/// reallocations, process-wide). The first call wins; until one is made `Tally::allocations` reads 0.
#[cfg(feature = "test-support")]
pub fn count_allocations_through(read: fn() -> u64) {
    let _ = ALLOCATION_SOURCE.set(read);
}

/// Count one unit of `work`. A no-op unless built with `test-support`.
#[inline]
pub fn tally(work: Work) {
    #[cfg(feature = "test-support")]
    {
        let counter = match work {
            Work::Crossing => &CROSSINGS,
            Work::StoreRoundTrip => &STORE_ROUND_TRIPS,
            Work::ClockRead => &CLOCK_READS,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(not(feature = "test-support"))]
    let _ = work;
}

/// Every counter's value at one moment, process-wide.
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Heap allocations (`alloc`, `alloc_zeroed`, `realloc`) by the reader [`count_allocations_through`] names.
    pub allocations: u64,
    /// Calls from the loader into a plugin.
    pub crossings: u64,
    /// Store requests submitted and answered.
    pub store_round_trips: u64,
    /// Clock reads by connector drives.
    pub clock_reads: u64,
}

#[cfg(feature = "test-support")]
impl Tally {
    /// The counters now.
    pub fn now() -> Self {
        Self {
            allocations: ALLOCATION_SOURCE.get().map_or(0, |read| read()),
            crossings: CROSSINGS.load(Ordering::Relaxed),
            store_round_trips: STORE_ROUND_TRIPS.load(Ordering::Relaxed),
            clock_reads: CLOCK_READS.load(Ordering::Relaxed),
        }
    }

    /// The work done between `earlier` and `self`.
    pub fn since(self, earlier: Self) -> Self {
        Self {
            allocations: self.allocations.wrapping_sub(earlier.allocations),
            crossings: self.crossings.wrapping_sub(earlier.crossings),
            store_round_trips: self
                .store_round_trips
                .wrapping_sub(earlier.store_round_trips),
            clock_reads: self.clock_reads.wrapping_sub(earlier.clock_reads),
        }
    }
}
