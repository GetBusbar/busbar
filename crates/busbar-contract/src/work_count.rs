// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-request work counters for the CI work-budget gate (`perf/work-budget.toml`).
//!
//! A deterministic count of work, not a timing. The host bumps one counter at each boundary it
//! owns: [`Work::Crossing`] where the loader calls into a plugin, [`Work::StoreRoundTrip`] where
//! the loader submits one request to the store plugin. [`Counting`] wraps the global allocator so
//! the gate can count heap allocations too.
//!
//! The counters only move when this crate is built with `test-support`, which no shipping build
//! enables; in every other build [`tally`] is an empty inline function.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering};

/// One kind of counted work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// One call from the loader into a plugin (the loader boundary).
    Crossing,
    /// One request submitted to the store plugin and answered.
    StoreRoundTrip,
}

static CROSSINGS: AtomicU64 = AtomicU64::new(0);
static STORE_ROUND_TRIPS: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Count one unit of `work`. A no-op unless built with `test-support`.
#[inline]
pub fn tally(work: Work) {
    #[cfg(feature = "test-support")]
    {
        let counter = match work {
            Work::Crossing => &CROSSINGS,
            Work::StoreRoundTrip => &STORE_ROUND_TRIPS,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(not(feature = "test-support"))]
    let _ = work;
}

/// Every counter's value at one moment, process-wide.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Heap allocations (`alloc`, `alloc_zeroed`, `realloc`) through [`Counting`].
    pub allocations: u64,
    /// Calls from the loader into a plugin.
    pub crossings: u64,
    /// Store requests submitted and answered.
    pub store_round_trips: u64,
}

impl Tally {
    /// The counters now.
    pub fn now() -> Self {
        Self {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            crossings: CROSSINGS.load(Ordering::Relaxed),
            store_round_trips: STORE_ROUND_TRIPS.load(Ordering::Relaxed),
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
        }
    }
}

/// A global allocator that counts every allocation, then forwards to `A`.
#[derive(Debug)]
pub struct Counting<A>(pub A);

// SAFETY: every method forwards verbatim to `A`, a sound `GlobalAlloc`. The only added work is a
// relaxed increment of a static atomic, which neither allocates nor touches the memory handed out.
#[allow(unsafe_code)]
unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded as given.
        unsafe { self.0.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded as given.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded as given.
        unsafe { self.0.dealloc(ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded as given.
        unsafe { self.0.realloc(ptr, layout, new_size) }
    }
}
