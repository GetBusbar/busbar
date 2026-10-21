//! THE ONE COUNTING ALLOCATOR a plugin's allocation gates read (ARCHITECT ruling 2026-10-21,
//! superseding the `cfg_attr(not(test), forbid)` pair: plugin crate roots keep the literal
//! `#![forbid(unsafe_code)]`, BUSBAR-1.6.0.md l.273, so the `GlobalAlloc` impl a gate needs lives
//! here instead of in the plugin).
//!
//! TEST ONLY. Compiled for this crate's own tests and, through the dev-only, EMPTY `alloc-counter`
//! feature, for a plugin's `[dev-dependencies]` edge. `tests/test_seal_is_dev_only.rs` refuses any
//! `[dependencies]`, `[build-dependencies]`, `[target.*]` or `default` that turns the feature on,
//! so no shipped artifact carries it. Even when compiled, nothing here is installed: the allocator
//! only counts where a test binary declares it its own `#[global_allocator]`:
//!
//! ```ignore
//! #[global_allocator]
//! static A: busbar_contract::alloc_counter::Counting = busbar_contract::alloc_counter::Counting::new();
//! ```
//!
//! PER-THREAD, not process-global: `cargo test` runs tests concurrently, so a shared atomic would let
//! another test thread's allocations inflate the measured count and flap an exact-equality gate. A
//! `const`-initialized thread-local has no lazy init, no destructor and no heap, so touching it from
//! inside the allocator never re-enters it.
//!
//! The crate's `#![deny(unsafe_code)]` holds over this whole module except the one
//! `unsafe impl GlobalAlloc` block, which carries the module's only `#[allow(unsafe_code)]`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations (and reallocations) made by THIS thread since it started or last [`reset`].
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting every allocation and reallocation on the calling thread.
#[derive(Debug)]
pub struct Counting {
    _private: (),
}

impl Counting {
    /// The counter, for a `#[global_allocator]` static.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for Counting {
    fn default() -> Self {
        Self::new()
    }
}

/// One more allocation on this thread. `try_with`: a thread tearing down its locals may still
/// allocate, and that allocation is simply not counted.
fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

// SAFETY: every method forwards verbatim to `System`, adding only a thread-local integer increment
// before the call; it never reads or writes the memory handed out and changes no allocation
// behaviour.
#[allow(unsafe_code)] // REVIEWED, TEST ONLY: counting GlobalAlloc for plugin allocation gates
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: forwarded verbatim; the caller's obligations on `layout` are unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        // SAFETY: forwarded verbatim; the caller's obligations on `layout` are unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim; the caller's obligations on `ptr`/`layout` are unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        // SAFETY: forwarded verbatim; the caller's obligations on `ptr`/`layout`/`new_size` are
        // unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Allocations counted on THIS thread since it started or last [`reset`].
#[must_use]
pub fn allocations() -> u64 {
    ALLOCS.with(Cell::get)
}

/// Zero this thread's counter, returning what it held.
pub fn reset() -> u64 {
    ALLOCS.with(|c| c.replace(0))
}

/// How many allocations `f` made on this thread.
pub fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = allocations();
    f();
    allocations() - before
}

#[cfg(test)]
mod tests {
    use super::{allocations, allocations_of, reset};

    /// The counter counts: this crate's own test binary installs [`super::Counting`] as its
    /// `#[global_allocator]` (`lib.rs`), so a heap allocation moves this thread's count and a call
    /// that allocates nothing does not.
    #[test]
    fn the_counter_counts_this_threads_allocations() {
        let one = allocations_of(|| {
            let v: Vec<u8> = Vec::with_capacity(64);
            std::hint::black_box(v);
        });
        assert_eq!(one, 1, "one Vec::with_capacity is one allocation");

        let grown = allocations_of(|| {
            let mut v: Vec<u8> = Vec::with_capacity(1);
            v.extend_from_slice(&[0; 256]);
            std::hint::black_box(v);
        });
        assert_eq!(grown, 2, "an allocation and one realloc");

        let zeroed = allocations_of(|| {
            std::hint::black_box(vec![0u8; 128]);
        });
        assert_eq!(zeroed, 1, "vec![0; n] is one alloc_zeroed");

        let none = allocations_of(|| {
            std::hint::black_box(1 + 1);
        });
        assert_eq!(none, 0, "a call that allocates nothing counts nothing");

        reset();
        assert_eq!(allocations(), 0);
        std::hint::black_box(Box::new(7u64));
        assert_eq!(reset(), 1, "reset returns the count it cleared");
        assert_eq!(allocations(), 0);
    }

    /// Per thread: another thread's allocations do not reach this thread's count.
    #[test]
    fn another_threads_allocations_are_not_counted_here() {
        let here = allocations_of(|| {
            std::thread::scope(|s| {
                s.spawn(|| {
                    for _ in 0..32 {
                        std::hint::black_box(Box::new([0u8; 64]));
                    }
                });
            });
        });
        // Spawning the scoped thread allocates on THIS thread (its handle and packet), but none of
        // the spawned thread's 32 boxes is counted here.
        assert!(
            here < 32,
            "{here} allocations counted on the spawning thread"
        );
    }
}
