// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The counting allocator: per-thread allocation and byte counters over the system allocator.
//!
//! The counters are `const`-initialised thread locals with no destructor, so counting costs two
//! TLS increments per allocation and never contends between bench threads. A binary installs it
//! with [`crate::bench_main!`] (or `#[global_allocator]` by hand). A dropped-in cdylib carries its
//! own allocator, so its allocations are not seen here: only the host side of the crossing is
//! (see the README).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting every allocation (and every growing `realloc`) per thread.
#[derive(Debug, Default, Clone, Copy)]
pub struct CountingAlloc;

#[inline]
fn note(size: usize) {
    // `try_with`: an allocation during thread teardown must never panic inside the allocator.
    let _ = ALLOCS.try_with(|a| a.set(a.get() + 1));
    let _ = BYTES.try_with(|b| b.set(b.get() + size as u64));
}

// SAFETY: every method forwards to `System` unchanged; the counters never allocate.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// This thread's `(allocations, bytes)` so far.
#[inline]
#[must_use]
pub fn thread_counts() -> (u64, u64) {
    (
        ALLOCS.try_with(Cell::get).unwrap_or(0),
        BYTES.try_with(Cell::get).unwrap_or(0),
    )
}

/// Whether the binary's global allocator is [`CountingAlloc`]: one probe allocation moves the
/// counters only if it is.
#[must_use]
pub fn installed() -> bool {
    let before = thread_counts().0;
    let probe = std::hint::black_box(Box::new(0u64));
    drop(probe);
    thread_counts().0 != before
}
