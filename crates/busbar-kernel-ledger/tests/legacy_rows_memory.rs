// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the production dual write keeps in memory, measured.
//!
//! Out here rather than beside the other dual-write cases for the reason `hot_path_allocation.rs`
//! gives: measuring live bytes means installing an allocator, which is an unsafe trait
//! implementation the library forbids. An integration test is its own crate with its own lints.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use busbar_kernel_ledger::legacy::{LegacyPosting, LegacyRows, RecordingRows, SummedRows};

thread_local! {
    /// Bytes allocated and not yet freed on THIS thread. Thread-local so cases running in parallel
    /// cannot perturb one another; const-initialised with no destructor, so reading it from inside
    /// the allocator cannot allocate or recurse.
    static LIVE: Cell<i64> = const { Cell::new(0) };
}

fn live() -> i64 {
    LIVE.with(Cell::get)
}

fn add(bytes: usize, sign: i64) {
    let _ = LIVE.try_with(|c| c.set(c.get() + sign * bytes as i64));
}

struct Counting;

// SAFETY: every method forwards to the system allocator unchanged and hands back exactly the
// pointer `System` returned. The only addition is a thread-local integer update, which allocates
// nothing; `try_with` skips the count on a thread whose local has already been destroyed.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        add(layout.size(), 1);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        add(layout.size(), -1);
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        add(layout.size(), 1);
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        add(layout.size(), -1);
        add(new_size, 1);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The cells a busy node settles into: a few principals, a couple of buckets, one window.
const CELLS: [(&str, &str); 4] = [("p1", "b1"), ("p1", "b2"), ("p2", "b1"), ("p3", "b3")];

fn posting(n: u64) -> LegacyPosting {
    let (principal, bucket) = CELLS[(n % CELLS.len() as u64) as usize];
    LegacyPosting {
        principal: principal.into(),
        bucket: bucket.into(),
        window_start: 1_767_225_600,
        reserved: 100,
        settled: 90 + n % 7,
        overdraft: 0,
        fee_count: 1,
    }
}

/// Live bytes the binding holds after `n` postings, every transient the write made already freed.
fn held_after(binding: &mut dyn LegacyRows, n: u64) -> i64 {
    let before = live();
    for i in 0..n {
        let p = posting(i);
        binding
            .write(&p)
            .expect("an in-memory binding always writes");
        drop(p);
    }
    live() - before
}

/// **THE PRODUCTION BINDING'S MEMORY DOES NOT GROW WITH THE POSTINGS.**
///
/// The same four cells, settled into a thousand times and then a hundred thousand times: the
/// summing binding holds the same number of live bytes after both, because it holds a row per cell
/// and nothing per posting.
#[test]
fn the_summed_rows_hold_the_same_bytes_after_a_thousand_postings_and_a_hundred_thousand() {
    let mut small = SummedRows::new();
    let held_small = held_after(&mut small, 1_000);
    let mut large = SummedRows::new();
    let held_large = held_after(&mut large, 100_000);

    assert_eq!(small.len(), CELLS.len());
    assert_eq!(large.len(), CELLS.len());
    assert!(
        held_small > 0,
        "the rows are real allocations: {held_small}"
    );
    assert_eq!(
        held_large, held_small,
        "a hundred times the postings, the same memory: bounded by cells, not by postings"
    );
}

/// RED ARM: the recorder the node used to bind grows with every posting — the leak this replaces.
#[test]
fn the_recorder_grows_with_every_posting() {
    let mut small = RecordingRows::new();
    let held_small = held_after(&mut small, 1_000);
    let mut large = RecordingRows::new();
    let held_large = held_after(&mut large, 100_000);

    assert!(
        held_large > held_small * 50,
        "the recorder keeps every posting: {held_small} bytes for 1k, {held_large} for 100k"
    );
}
