// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ALLOCATION COUNTER for a dependent crate's test binary: [`Counting`] wraps the allocator the
//! binary already runs on and counts every allocation, per thread, so concurrent tests in the same
//! binary never inflate the measured thread's count. The binary installs it as its
//! `#[global_allocator]` under `cfg(test)` only; its shipped build keeps the bare allocator. A
//! crate root that forbids `unsafe` names this type and writes no `unsafe` of its own.
//!
//! The same instrument this crate's own test binary carries (`lib.rs`, `CountingJemalloc`), made
//! generic over the inner allocator so the wrapping crate's allocator choice stays its own.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;

thread_local! {
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
}

/// `A`, counting each allocation (`alloc`, `alloc_zeroed`, `realloc`) on the calling thread.
pub struct Counting<A>(pub A);

/// Allocations a [`Counting`] allocator observed on THIS thread since it started (or since the last
/// [`reset`]).
#[must_use]
pub fn count() -> u64 {
    ALLOC_COUNT.with(Cell::get)
}

/// Reset this thread's count to zero, answering the count it held.
pub fn reset() -> u64 {
    ALLOC_COUNT.with(|c| c.replace(0))
}

#[inline]
fn bump() {
    ALLOC_COUNT.with(|c| c.set(c.get() + 1));
}

// SAFETY: every method delegates verbatim to `A` (a sound `GlobalAlloc`); the only added work is a
// per-thread `Cell` increment (const-initialised, no destructor), which allocates nothing and cannot
// re-enter the allocator. `dealloc` is not counted: the count is of allocations.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: the caller's contract for `alloc`, passed through unchanged.
        unsafe { self.0.alloc(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract for `dealloc`, passed through unchanged.
        unsafe { self.0.dealloc(ptr, layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: the caller's contract for `alloc_zeroed`, passed through unchanged.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        // SAFETY: the caller's contract for `realloc`, passed through unchanged.
        unsafe { self.0.realloc(ptr, layout, new_size) }
    }
}
