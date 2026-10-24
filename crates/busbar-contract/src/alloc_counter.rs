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
//! THE FREED-KEY WITNESS rides the same allocator (a zeroise gate, "keys are zeroised",
//! BUSBAR-1.6.0.md l.753): a test builds a marked key with [`marked_key`] and names every secret
//! derived from it with [`watch`] (a split-out master key or salt, a derived session key, a key
//! schedule's round keys), each against the test's own id; [`freed_unzeroed`] reports how many
//! freed blocks still held ANY [`WINDOW`] consecutive bytes of one of that id's secrets (all of a
//! shorter one). A whole copy, a split copy and a derived copy are all seen, wherever in the block
//! they sit. Unarmed (every binary that never calls [`marked_key`] or [`watch`]) it costs one
//! atomic load per free.
//!
//! The crate's `#![deny(unsafe_code)]` holds over this whole module except the one
//! `unsafe impl GlobalAlloc` block, which carries the module's only `#[allow(unsafe_code)]`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

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

/// The eight bytes that open a marked key; a byte stream drawn from the key's id fills the rest,
/// so every window of it is distinct from every other id's and from ordinary heap contents.
pub const MARK: [u8; 8] = *b"ZEROISE!";

/// How many key ids the freed-key witness tells apart: `0..MARKED_IDS`.
pub const MARKED_IDS: usize = 8;

/// The window the witness matches: a freed block holding ANY `WINDOW` consecutive bytes of a
/// watched secret (all of a secret shorter than that, such as a 12-byte salt) is counted.
pub const WINDOW: usize = 16;

/// The most secrets one test binary watches.
pub const MAX_WATCHED: usize = 256;

/// The longest secret the witness watches.
pub const MAX_WATCHED_LEN: usize = 64;

/// One watched secret: its id, its length (`0` until it is published) and its bytes.
struct Watched {
    id: AtomicUsize,
    len: AtomicUsize,
    bytes: [AtomicU8; MAX_WATCHED_LEN],
}

impl Watched {
    const fn new() -> Self {
        Self {
            id: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
            bytes: [const { AtomicU8::new(0) }; MAX_WATCHED_LEN],
        }
    }
}

/// The watched secrets, `0..WATCHING` claimed. Fixed storage: the allocator reads it on every free
/// and must never allocate, lock or re-enter itself to do so.
static WATCHED: [Watched; MAX_WATCHED] = [const { Watched::new() }; MAX_WATCHED];

/// How many slots of [`WATCHED`] were claimed: `0` is unarmed.
static WATCHING: AtomicUsize = AtomicUsize::new(0);

/// One bit per two-byte prefix of every window of every watched secret: a block position whose
/// two bytes are no window's first two is skipped with one load.
static PREFIXES: [AtomicU64; 1024] = [const { AtomicU64::new(0) }; 1024];

/// Freed blocks seen still holding a secret watched under `id`, per id.
static FREED_UNZEROED: [AtomicUsize; MARKED_IDS] = [const { AtomicUsize::new(0) }; MARKED_IDS];

/// The marked key `id` of `N` bytes ([`MARK`], then a byte stream drawn from `id`), on the
/// caller's stack (the stack is not the allocator's to watch). The whole key is watched under
/// `id`, so any [`WINDOW`] of it in a freed block is counted.
///
/// # Panics
///
/// When `id` is not below [`MARKED_IDS`], `N` leaves no room after the mark or exceeds
/// [`MAX_WATCHED_LEN`], or [`MAX_WATCHED`] secrets are already watched.
#[must_use]
pub fn marked_key<const N: usize>(id: u8) -> [u8; N] {
    assert!(N > MARK.len(), "a {N}-byte key has no room after the mark");
    let mut k = [0_u8; N];
    k[..MARK.len()].copy_from_slice(&MARK);
    // xorshift64*, seeded from the id: deterministic per id, distinct between ids.
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ (u64::from(id) + 1).wrapping_mul(0xD1B5_4A32_D192_ED03);
    for b in &mut k[MARK.len()..] {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes()[0];
    }
    watch(id, &k);
    k
}

/// Watch `watched` under `id`: from now on a freed block holding any [`WINDOW`] consecutive bytes
/// of it (all of it when it is shorter) counts against `id`. A test names here every secret it
/// derives from its marked key (a split-out part, a derived session key, a round key), copied
/// from the stack: a heap copy the test frees would be counted itself.
///
/// # Panics
///
/// When `id` is not below [`MARKED_IDS`], `watched` is shorter than 2 or longer than
/// [`MAX_WATCHED_LEN`] bytes, or [`MAX_WATCHED`] secrets are already watched.
pub fn watch(id: u8, watched: &[u8]) {
    assert!(usize::from(id) < MARKED_IDS, "key id {id} >= {MARKED_IDS}");
    assert!(
        (2..=MAX_WATCHED_LEN).contains(&watched.len()),
        "a watched secret is 2..={MAX_WATCHED_LEN} bytes"
    );
    let slot = WATCHING.fetch_add(1, Ordering::SeqCst);
    assert!(
        slot < MAX_WATCHED,
        "more than {MAX_WATCHED} watched secrets"
    );
    let w = &WATCHED[slot];
    for (to, b) in w.bytes.iter().zip(watched) {
        to.store(*b, Ordering::Relaxed);
    }
    w.id.store(usize::from(id), Ordering::Relaxed);
    let win = watched.len().min(WINDOW);
    for pair in watched.windows(2).take(watched.len() - win + 1) {
        let bit = prefix(pair[0], pair[1]);
        PREFIXES[bit / 64].fetch_or(1_u64 << (bit % 64), Ordering::SeqCst);
    }
    // Published last: a reader that sees the length sees the bytes and the id.
    w.len.store(watched.len(), Ordering::Release);
}

/// Where the witness last saw a secret watched under one id: what a failing zeroise gate names,
/// so the copy it found can be traced to its holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// The freed block's size.
    pub block: usize,
    /// The offset in the block the secret's window starts at.
    pub at: usize,
    /// Which of the id's watched secrets it was: `0` is the first watched (a marked key itself),
    /// in the order [`marked_key`] and [`watch`] were called for the id.
    pub nth: usize,
    /// That secret's length.
    pub len: usize,
}

/// The last sighting per id: block size, offset, nth secret, its length (`0` block: none yet).
static LAST_SEEN: [[AtomicUsize; 4]; MARKED_IDS] =
    [const { [const { AtomicUsize::new(0) }; 4] }; MARKED_IDS];

/// Where a secret watched under `id` was last seen in a freed block, if one was.
#[must_use]
pub fn last_seen(id: u8) -> Option<Seen> {
    let s = &LAST_SEEN[usize::from(id)];
    let block = s[0].load(Ordering::SeqCst);
    (block != 0).then(|| Seen {
        block,
        at: s[1].load(Ordering::SeqCst),
        nth: s[2].load(Ordering::SeqCst),
        len: s[3].load(Ordering::SeqCst),
    })
}

/// How many freed blocks were seen still holding a secret watched under `id`.
#[must_use]
pub fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

/// The prefix bit of two bytes.
fn prefix(a: u8, b: u8) -> usize {
    (usize::from(a) << 8) | usize::from(b)
}

/// Whether the claimed slot `w` holds a secret one of whose windows starts at `block[at..]`, and
/// under which id.
fn window_at(w: &Watched, block: &[u8], at: usize) -> Option<usize> {
    let len = w.len.load(Ordering::Acquire);
    if len == 0 {
        return None;
    }
    let win = len.min(WINDOW);
    let rest = block.get(at..at + win)?;
    (0..=len - win)
        .any(|start| {
            rest.iter()
                .enumerate()
                .all(|(i, b)| w.bytes[start + i].load(Ordering::Relaxed) == *b)
        })
        .then(|| w.id.load(Ordering::Relaxed))
        .filter(|id| *id < MARKED_IDS)
}

/// Count, once per id, every watched secret a block being freed still holds a window of.
fn witness_freed(block: &[u8]) {
    let claimed = WATCHING.load(Ordering::SeqCst).min(MAX_WATCHED);
    let mut seen = [false; MARKED_IDS];
    for (at, pair) in block.windows(2).enumerate() {
        let bit = prefix(pair[0], pair[1]);
        if PREFIXES[bit / 64].load(Ordering::Relaxed) & (1_u64 << (bit % 64)) == 0 {
            continue;
        }
        for (slot, w) in WATCHED[..claimed].iter().enumerate() {
            if let Some(id) = window_at(w, block, at) {
                seen[id] = true;
                let nth = WATCHED[..slot]
                    .iter()
                    .filter(|o| {
                        o.len.load(Ordering::Acquire) != 0 && o.id.load(Ordering::Relaxed) == id
                    })
                    .count();
                let last = &LAST_SEEN[id];
                last[1].store(at, Ordering::SeqCst);
                last[2].store(nth, Ordering::SeqCst);
                last[3].store(w.len.load(Ordering::Acquire), Ordering::SeqCst);
                last[0].store(block.len(), Ordering::SeqCst);
            }
        }
    }
    for (id, hit) in seen.iter().enumerate() {
        if *hit {
            FREED_UNZEROED[id].fetch_add(1, Ordering::SeqCst);
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
        if WATCHING.load(Ordering::SeqCst) != 0 && layout.size() >= 2 {
            // SAFETY (TEST ONLY, and NOT fully sound): `ptr` is a live block of `layout.size()`
            // bytes until `System` frees it below, and its owner has given it up, so nothing else
            // reads or writes it during `dealloc`. But the slice spans the WHOLE block, including
            // bytes the owner never wrote: reading uninitialised memory through a `&[u8]` is
            // undefined behaviour, and Miri would flag it. It is accepted here because this
            // allocator is compiled only into test binaries (the dev-only `alloc-counter`
            // feature), reads the bytes only to compare them, and keeps nothing it read.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            witness_freed(block);
        }
        // SAFETY: forwarded verbatim; the caller's obligations on `ptr`/`layout` are unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if WATCHING.load(Ordering::SeqCst) != 0 {
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
#[path = "tests/alloc_counter_tests.rs"]
mod tests;
