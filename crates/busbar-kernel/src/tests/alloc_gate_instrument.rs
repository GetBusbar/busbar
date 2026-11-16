// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout};
use tikv_jemallocator::Jemalloc;

thread_local! {
    static ALLOC_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub(crate) struct CountingJemalloc;

impl CountingJemalloc {
    pub(crate) fn count() -> u64 {
        ALLOC_COUNT.with(|c| c.get())
    }

    pub(crate) fn reset() -> u64 {
        ALLOC_COUNT.with(|c| c.replace(0))
    }
    #[inline]
    fn bump() {
        ALLOC_COUNT.with(|c| c.set(c.get() + 1));
    }
}

// SAFETY: every method delegates verbatim to `Jemalloc` (a sound `GlobalAlloc`); the only added
// work is a per-thread `Cell` increment, which allocates nothing and cannot re-enter the
// allocator. `dealloc` is NOT counted — the gate measures allocation COUNT, and jemalloc's own
// deallocation accounting (which the telemetry tests read) is untouched. `alloc_zeroed` is left to
// the trait default, which calls the counted `alloc` once (this keeps the file at its 5-token row).
unsafe impl GlobalAlloc for CountingJemalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::bump();
        Jemalloc.alloc(layout)
    }
    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Jemalloc.dealloc(ptr, layout)
    }
    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::bump();
        Jemalloc.realloc(ptr, layout, new_size)
    }
}
