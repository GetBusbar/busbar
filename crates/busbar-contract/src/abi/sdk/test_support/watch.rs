// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WATCH ROW (SDK-SAFE-TEST-HOST §3.4): the one `GlobalAlloc` in test code. While a test holds
//! it armed, every block freed (on any thread) is counted and scanned, inside `dealloc`, for a
//! canary and for non-zero bytes. The scan writes only atomics: it never allocates, never panics
//! and calls no user code, and a thread-local guard keeps it from re-entering itself.
//!
//! ```ignore
//! #[global_allocator]
//! static A: Watch = Watch::new();
//! let freed = A.armed(b"canary-0123456789", || drop(secret));
//! assert_eq!(freed.blocks_containing_canary, 0);
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::Mutex;

/// What the blocks freed during one armed scope held.
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
}

/// The system allocator, watched while armed.
#[derive(Debug)]
pub struct Watch {
    armed: AtomicBool,
    canary: AtomicPtr<u8>,
    canary_len: AtomicUsize,
    count: AtomicUsize,
    bytes: AtomicUsize,
    canary_blocks: AtomicUsize,
    nonzero_blocks: AtomicUsize,
}

/// One armed scope at a time per process (scopes on two threads would share the counters).
static SCOPE: Mutex<()> = Mutex::new(());

std::thread_local! {
    static SCANNING: Cell<bool> = const { Cell::new(false) };
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
            canary: AtomicPtr::new(std::ptr::null_mut()),
            canary_len: AtomicUsize::new(0),
            count: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            canary_blocks: AtomicUsize::new(0),
            nonzero_blocks: AtomicUsize::new(0),
        }
    }

    /// Runs `f` armed with `canary` (empty: count and non-zero only) and answers what was freed
    /// meanwhile. A panic in `f` disarms and propagates; it never aborts.
    pub fn armed(&self, canary: &'static [u8], f: impl FnOnce()) -> Freed {
        let _scope = SCOPE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for c in [
            &self.count,
            &self.bytes,
            &self.canary_blocks,
            &self.nonzero_blocks,
        ] {
            c.store(0, Ordering::SeqCst);
        }
        self.canary
            .store(canary.as_ptr().cast_mut(), Ordering::SeqCst);
        self.canary_len.store(canary.len(), Ordering::SeqCst);
        struct Disarm<'a>(&'a AtomicBool);
        impl Drop for Disarm<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let disarm = Disarm(&self.armed);
        self.armed.store(true, Ordering::SeqCst);
        f();
        drop(disarm);
        Freed {
            count: self.count.load(Ordering::SeqCst),
            bytes: self.bytes.load(Ordering::SeqCst),
            blocks_containing_canary: self.canary_blocks.load(Ordering::SeqCst),
            nonzero_blocks: self.nonzero_blocks.load(Ordering::SeqCst),
        }
    }

    /// Counts and scans one block about to be freed. Atomics only; never panics or allocates.
    fn scan(&self, block: &[u8]) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.bytes.fetch_add(block.len(), Ordering::SeqCst);
        if block.iter().any(|b| *b != 0) {
            self.nonzero_blocks.fetch_add(1, Ordering::SeqCst);
        }
        let len = self.canary_len.load(Ordering::SeqCst);
        let at = self.canary.load(Ordering::SeqCst);
        if len == 0 || at.is_null() || len > block.len() {
            return;
        }
        // SAFETY: `canary`/`canary_len` were stored together from a `&'static [u8]` before the
        // scope armed, and are only replaced by the next scope, which `SCOPE` serializes.
        let canary = unsafe { std::slice::from_raw_parts(at.cast_const(), len) };
        if block.windows(len).any(|w| w == canary) {
            self.canary_blocks.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// SAFETY: every call forwards to `System` with the caller's own arguments; `dealloc` only reads
// the block before forwarding it.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.armed.load(Ordering::SeqCst) {
            let entered = SCANNING.try_with(|s| !s.replace(true)).unwrap_or(false);
            if entered {
                // SAFETY: the caller's contract: `ptr` is a live block of `layout.size()` bytes
                // this allocator handed out, not yet freed. Bytes the program never wrote are
                // read as whatever the allocator left there, as every allocator probe does.
                self.scan(unsafe { std::slice::from_raw_parts(ptr, layout.size()) });
                let _ = SCANNING.try_with(|s| s.set(false));
            }
        }
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}
