// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel test binary's allocation gate (UNSAFE-MIN §4.4): what THIS thread allocated, read from
//! jemalloc's own per-thread counter (`thread.allocatedp`, through upstream `tikv-jemalloc-ctl`).
//! The binary runs on plain jemalloc, so no allocator of busbar's own (and no `unsafe`) is needed.
//!
//! The counter is the bytes this thread has been handed, at jemalloc's usable (size-class) size, by
//! every allocation and every reallocation. Every allocation request adds at least one size class
//! (8 bytes), so a reading of zero means no allocation was made on this thread, and a planted
//! 32-byte allocation (a size class of its own) reads exactly 32. Another thread's allocations never
//! move this thread's counter.

use std::cell::Cell;

thread_local! {
    /// The counter's value when this thread last called [`ThreadAllocated::reset`].
    static BASE: Cell<u64> = const { Cell::new(0) };
}

pub(crate) struct ThreadAllocated;

impl ThreadAllocated {
    /// Bytes this thread allocated (and reallocated into) since its last [`Self::reset`].
    pub(crate) fn bytes() -> u64 {
        Self::total().saturating_sub(BASE.with(Cell::get))
    }

    /// Start counting this thread again from zero, returning what the reading was.
    pub(crate) fn reset() -> u64 {
        let total = Self::total();
        total.saturating_sub(BASE.with(|base| base.replace(total)))
    }

    /// jemalloc's running total for this thread. Reading it allocates nothing: the ctl name is a
    /// static string, and the first read (which sets up jemalloc's ctl state) happens in `reset`,
    /// before any measured window opens.
    fn total() -> u64 {
        tikv_jemalloc_ctl::thread::allocatedp::read()
            .expect("jemalloc's thread.allocatedp is readable (the stats feature is on)")
            .get()
    }
}
