// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WATCH ROW (SDK-SAFE-TEST-HOST §3.4): the one `GlobalAlloc` in test code. While a test holds
//! it armed, every allocation is counted, and every block freed is counted and scanned, inside
//! `dealloc`, for a canary and for non-zero bytes. One block the test names ([`Watch::block`]) is
//! read as it is freed, on any thread. The scan writes only atomics: it never allocates, never
//! panics and calls no user code, and a thread-local guard keeps it from re-entering itself.
//!
//! ```ignore
//! #[global_allocator]
//! static A: Watch = Watch::new();
//! let freed = A.armed(b"canary-0123456789", || drop(secret));
//! assert_eq!(freed.blocks_containing_canary, 0);
//! let here = A.armed_here(b"", || parse(input));          // this thread's allocations only
//! assert_eq!(here.allocs, 0);
//! let wiped = A.armed(b"", || { A.block(key.as_ptr(), key.len()); drop(key) });
//! assert_eq!(wiped.block, Some(Block { nonzero: false, canary: false }));
//! ```
//!
//! Test code only (feature `test-support`, which no release build enables). Moved here unchanged from
//! busbar-contract's old SDK test support (`abi/sdk/test_support/watch.rs`, which stays until the old
//! interface is cut), except that `realloc`'s copy and free are two blocks, as this crate's lints require.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// What one armed scope allocated and freed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Freed {
    /// Blocks freed.
    pub count: usize,
    /// Their bytes.
    pub bytes: usize,
    /// Blocks that still held the canary when freed.
    pub blocks_containing_canary: usize,
    /// Blocks that held any non-zero byte when freed.
    pub nonzero_blocks: usize,
    /// Blocks allocated (`alloc`, `alloc_zeroed`, and the new block of each `realloc`, whose old
    /// block is counted freed).
    pub allocs: usize,
    /// Their bytes (live bytes at the end = `alloc_bytes - bytes`, for blocks of this scope).
    pub alloc_bytes: usize,
    /// The largest one asked for.
    pub largest_alloc: usize,
    /// What the block named by [`Watch::block`] held when it was freed; `None` if it was not
    /// freed in the scope (or none was named).
    pub block: Option<Block>,
}

/// What a watched block held as it was freed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Block {
    /// A byte of its watched prefix was non-zero.
    pub nonzero: bool,
    /// Its watched prefix held the canary.
    pub canary: bool,
}

/// The system allocator, watched while armed.
#[derive(Debug)]
pub struct Watch {
    armed: AtomicBool,
    here_only: AtomicBool,
    canary: AtomicPtr<u8>,
    canary_len: AtomicUsize,
    count: AtomicUsize,
    bytes: AtomicUsize,
    canary_blocks: AtomicUsize,
    nonzero_blocks: AtomicUsize,
    allocs: AtomicUsize,
    alloc_bytes: AtomicUsize,
    largest: AtomicUsize,
    block_at: AtomicPtr<u8>,
    block_len: AtomicUsize,
    /// 0 = not freed; else 1 | 2 (non-zero) | 4 (canary).
    block_seen: AtomicUsize,
}

/// One armed scope at a time per process (scopes on two threads would share the counters).
static SCOPE: Mutex<()> = Mutex::new(());

std::thread_local! {
    static SCANNING: Cell<bool> = const { Cell::new(false) };
    /// This thread runs an `armed_here` scope.
    static HERE: Cell<bool> = const { Cell::new(false) };
}

impl Default for Watch {
    fn default() -> Self {
        Self::new()
    }
}

impl Watch {
    /// Unarmed: a plain system allocator until [`Watch::armed`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            here_only: AtomicBool::new(false),
            canary: AtomicPtr::new(std::ptr::null_mut()),
            canary_len: AtomicUsize::new(0),
            count: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            canary_blocks: AtomicUsize::new(0),
            nonzero_blocks: AtomicUsize::new(0),
            allocs: AtomicUsize::new(0),
            alloc_bytes: AtomicUsize::new(0),
            largest: AtomicUsize::new(0),
            block_at: AtomicPtr::new(std::ptr::null_mut()),
            block_len: AtomicUsize::new(0),
            block_seen: AtomicUsize::new(0),
        }
    }

    /// Runs `f` armed with `canary` (empty: counts and non-zero only), counting every thread,
    /// and answers what was allocated and freed meanwhile. A panic in `f` disarms and propagates;
    /// it never aborts.
    pub fn armed(&self, canary: &'static [u8], f: impl FnOnce()) -> Freed {
        self.scope(canary, false, f)
    }

    /// [`Watch::armed`], counting only what the calling thread allocates and frees (a watched
    /// [`Watch::block`] is still read on any thread).
    pub fn armed_here(&self, canary: &'static [u8], f: impl FnOnce()) -> Freed {
        self.scope(canary, true, f)
    }

    /// Inside an armed scope: read the first `len` bytes of the block at `at` when it is freed,
    /// on whichever thread frees it. Nothing is read unless a block at exactly `at` is freed.
    pub fn block(&self, at: *const u8, len: usize) {
        self.block_seen.store(0, Ordering::SeqCst);
        self.block_len.store(len, Ordering::SeqCst);
        self.block_at.store(at.cast_mut(), Ordering::SeqCst);
    }

    fn scope(&self, canary: &'static [u8], here: bool, f: impl FnOnce()) -> Freed {
        let _scope = SCOPE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for c in [
            &self.count,
            &self.bytes,
            &self.canary_blocks,
            &self.nonzero_blocks,
            &self.allocs,
            &self.alloc_bytes,
            &self.largest,
            &self.block_seen,
        ] {
            c.store(0, Ordering::SeqCst);
        }
        self.block_at.store(std::ptr::null_mut(), Ordering::SeqCst);
        self.canary
            .store(canary.as_ptr().cast_mut(), Ordering::SeqCst);
        self.canary_len.store(canary.len(), Ordering::SeqCst);
        self.here_only.store(here, Ordering::SeqCst);
        struct Disarm<'a>(&'a Watch);
        impl Drop for Disarm<'_> {
            fn drop(&mut self) {
                self.0.armed.store(false, Ordering::SeqCst);
                self.0
                    .block_at
                    .store(std::ptr::null_mut(), Ordering::SeqCst);
                let _ = HERE.try_with(|h| h.set(false));
            }
        }
        let disarm = Disarm(self);
        let _ = HERE.try_with(|h| h.set(here));
        self.armed.store(true, Ordering::SeqCst);
        f();
        drop(disarm);
        let seen = self.block_seen.load(Ordering::SeqCst);
        Freed {
            count: self.count.load(Ordering::SeqCst),
            bytes: self.bytes.load(Ordering::SeqCst),
            blocks_containing_canary: self.canary_blocks.load(Ordering::SeqCst),
            nonzero_blocks: self.nonzero_blocks.load(Ordering::SeqCst),
            allocs: self.allocs.load(Ordering::SeqCst),
            alloc_bytes: self.alloc_bytes.load(Ordering::SeqCst),
            largest_alloc: self.largest.load(Ordering::SeqCst),
            block: (seen != 0).then_some(Block {
                nonzero: seen & 2 != 0,
                canary: seen & 4 != 0,
            }),
        }
    }

    /// Whether this thread's allocations and frees count now.
    fn counting(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
            && (!self.here_only.load(Ordering::SeqCst) || HERE.try_with(Cell::get).unwrap_or(false))
    }

    fn allocated(&self, size: usize) {
        if self.counting() {
            self.allocs.fetch_add(1, Ordering::SeqCst);
            self.alloc_bytes.fetch_add(size, Ordering::SeqCst);
            self.largest.fetch_max(size, Ordering::SeqCst);
        }
    }

    /// The canary of the armed scope; empty for none.
    fn canary(&self) -> &'static [u8] {
        let len = self.canary_len.load(Ordering::SeqCst);
        let at = self.canary.load(Ordering::SeqCst);
        if len == 0 || at.is_null() {
            return &[];
        }
        // SAFETY: `canary`/`canary_len` were stored together from a `&'static [u8]` before the
        // scope armed, and are only replaced by the next scope, which `SCOPE` serializes.
        unsafe { std::slice::from_raw_parts(at.cast_const(), len) }
    }

    /// Counts and scans one block about to be freed. Atomics only; never panics or allocates.
    fn scan(&self, block: &[u8]) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.bytes.fetch_add(block.len(), Ordering::SeqCst);
        if block.iter().any(|b| *b != 0) {
            self.nonzero_blocks.fetch_add(1, Ordering::SeqCst);
        }
        if holds(block, self.canary()) {
            self.canary_blocks.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Reads the watched block's prefix as it is freed, once.
    fn read_block(&self, prefix: &[u8]) {
        let mut seen = 1;
        if prefix.iter().any(|b| *b != 0) {
            seen |= 2;
        }
        if holds(prefix, self.canary()) {
            seen |= 4;
        }
        self.block_seen.store(seen, Ordering::SeqCst);
    }
}

fn holds(block: &[u8], canary: &[u8]) -> bool {
    !canary.is_empty()
        && canary.len() <= block.len()
        && block.windows(canary.len()).any(|w| w == canary)
}

// SAFETY: every call forwards to `System` with the caller's own arguments (a watched `realloc`
// as the documented default: a new block, the old one copied and then freed through `dealloc`);
// `dealloc` only reads the block before forwarding it.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocated(layout.size());
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.allocated(layout.size());
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !self.armed.load(Ordering::SeqCst) {
            // SAFETY: the caller's contract, forwarded.
            return unsafe { System.realloc(ptr, layout, new_size) };
        }
        // SAFETY: the caller's contract: `new_size` is non-zero and, rounded up to `layout`'s
        // alignment, does not overflow `isize`, so this layout is valid.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: a non-zero-sized layout, as above.
        let new = unsafe { self.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: `ptr` is live for `layout.size()` bytes and `new` for `new_size`; they are
            // distinct blocks.
            unsafe { std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size)) };
            // SAFETY: the old block is freed once, with the layout it was allocated with.
            unsafe { self.dealloc(ptr, layout) };
        }
        new
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.armed.load(Ordering::SeqCst) {
            let entered = SCANNING.try_with(|s| !s.replace(true)).unwrap_or(false);
            if entered {
                // SAFETY: the caller's contract: `ptr` is a live block of `layout.size()` bytes
                // this allocator handed out, not yet freed. Bytes the program never wrote are
                // read as whatever the allocator left there, as every allocator probe does.
                let whole = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                if self.counting() {
                    self.scan(whole);
                }
                if !ptr.is_null()
                    && self
                        .block_at
                        .compare_exchange(
                            ptr,
                            std::ptr::null_mut(),
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                {
                    let len = self.block_len.load(Ordering::SeqCst).min(whole.len());
                    self.read_block(&whole[..len]);
                }
                let _ = SCANNING.try_with(|s| s.set(false));
            }
        }
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}
