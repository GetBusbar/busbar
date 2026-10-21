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
//! THE FREED-KEY WITNESS rides the same allocator (a zeroise gate, e.g. transport-webrtc's "keys
//! are zeroised", BUSBAR-1.6.0.md l.753): a test builds a marked key with [`marked_key`], which
//! arms the witness, and [`freed_unzeroed`] reports how many freed blocks still held that key.
//! Unarmed (every binary that never calls [`marked_key`]) it costs one atomic load per free.
//!
//! The crate's `#![deny(unsafe_code)]` holds over this whole module except the one
//! `unsafe impl GlobalAlloc` block, which carries the module's only `#[allow(unsafe_code)]`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// The eight bytes that open a marked key; the key's id fills the rest of it.
pub const MARK: [u8; 8] = *b"ZEROISE!";

/// How many key ids the freed-key witness tells apart: `0..MARKED_IDS`.
pub const MARKED_IDS: usize = 8;

/// The armed key length: `0` until [`marked_key`] arms the witness. One length per test binary.
static KEY_LEN: AtomicUsize = AtomicUsize::new(0);

/// Freed blocks seen still holding marked key `id`, per id.
static FREED_UNZEROED: [AtomicUsize; MARKED_IDS] = [const { AtomicUsize::new(0) }; MARKED_IDS];

/// The marked key `id` of `N` bytes ([`MARK`], then `id` repeated), on the caller's stack (the
/// stack is not the allocator's to watch). Arms the freed-key witness for `N`-byte keys.
///
/// # Panics
///
/// When `id` is not below [`MARKED_IDS`] or `N` leaves no room for the id after [`MARK`].
#[must_use]
pub fn marked_key<const N: usize>(id: u8) -> [u8; N] {
    assert!(usize::from(id) < MARKED_IDS, "key id {id} >= {MARKED_IDS}");
    assert!(N > MARK.len(), "a {N}-byte key has no room after the mark");
    KEY_LEN.store(N, Ordering::SeqCst);
    let mut k = [id; N];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

/// How many freed blocks were seen still holding marked key `id`.
#[must_use]
pub fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

/// The id of the marked key at the start of `w`, if one is there whole.
fn marked(w: &[u8], key_len: usize) -> Option<usize> {
    let (mark, rest) = w.split_at_checked(MARK.len())?;
    let id = *rest.first()?;
    (mark == MARK
        && rest.len() >= key_len - MARK.len()
        && rest[..key_len - MARK.len()].iter().all(|b| *b == id))
    .then_some(usize::from(id))
    .filter(|id| *id < MARKED_IDS)
}

/// Count every marked key a block being freed still holds.
fn witness_freed(block: &[u8], key_len: usize) {
    for at in 0..=block.len() - key_len {
        if block[at] == MARK[0] {
            if let Some(id) = marked(&block[at..], key_len) {
                FREED_UNZEROED[id].fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// One more allocation on this thread. `try_with`: a thread tearing down its locals may still
/// allocate, and that allocation is simply not counted.
fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

// SAFETY: every method forwards to `System` with its own arguments, adding only a thread-local
// integer increment; nothing writes the memory handed out. Armed, `dealloc` READS the block it is
// handed (live until `System` frees it below, and given up by its owner) before forwarding, and
// `realloc` is the trait's own default (allocate, copy, free) so a moved block passes that read.
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
        let key_len = KEY_LEN.load(Ordering::SeqCst);
        if key_len != 0 && layout.size() >= key_len {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until `System` frees it below,
            // and its owner has given it up: nothing else reads or writes it during `dealloc`. It
            // is read as plain bytes and nothing read is kept.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            witness_freed(block, key_len);
        }
        // SAFETY: forwarded verbatim; the caller's obligations on `ptr`/`layout` are unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if KEY_LEN.load(Ordering::SeqCst) != 0 {
            // Armed: the trait's default body, so the old block is freed through `dealloc` and
            // read. One allocation, counted by `alloc`.
            // SAFETY: the caller guarantees `new_size`, rounded up to `layout.align()`, does not
            // overflow `isize` (the `realloc` contract), so the layout is valid.
            let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
            // SAFETY: `new_layout` has a non-zero size (the `realloc` contract).
            let new = unsafe { self.alloc(new_layout) };
            if !new.is_null() {
                // SAFETY: both blocks are live, distinct, and at least the copied length long;
                // `ptr`/`layout` are the caller's live block, freed once.
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                    self.dealloc(ptr, layout);
                }
            }
            return new;
        }
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
    allocations_with(f).0
}

/// How many allocations `f` made on this thread, and what it returned.
pub fn allocations_with<R>(f: impl FnOnce() -> R) -> (u64, R) {
    let before = allocations();
    let r = f();
    (allocations() - before, r)
}

#[cfg(test)]
mod tests {
    use super::{allocations, allocations_of, allocations_with, freed_unzeroed, marked_key, reset};

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

    /// `allocations_with` hands back the closure's value beside its count.
    #[test]
    fn allocations_with_returns_the_value_and_the_count() {
        let (n, v) = allocations_with(|| std::hint::black_box(vec![1_u8; 64]));
        assert_eq!(v.len(), 64);
        assert_eq!(n, 1);
    }

    /// THE FREED-KEY WITNESS SEES: a marked key freed in a plain `Vec` is counted against its id,
    /// and so is the block a growing `Vec` moved away from; a zeroising holder of the same bytes is
    /// not counted.
    #[test]
    fn the_freed_key_witness_sees_an_unzeroed_key_and_not_a_zeroised_one() {
        let plain: Vec<u8> = marked_key::<56>(7).to_vec();
        drop(std::hint::black_box(plain));
        assert!(freed_unzeroed(7) >= 1, "a key freed unzeroed was not seen");

        let mut grown: Vec<u8> = marked_key::<56>(5).to_vec();
        grown.extend_from_slice(&[0; 512]);
        grown.fill(0);
        drop(std::hint::black_box(grown));
        assert!(
            freed_unzeroed(5) >= 1,
            "the block a growing Vec moved away from still held the key and was not seen"
        );

        let held = zeroize::Zeroizing::new(marked_key::<56>(6).to_vec());
        drop(std::hint::black_box(held));
        assert_eq!(freed_unzeroed(6), 0, "a zeroised key was counted");
    }
}
