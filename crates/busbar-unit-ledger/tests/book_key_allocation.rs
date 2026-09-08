// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What moving a balance costs, measured.
//!
//! This case lives out here rather than beside the other book cases for one reason: measuring
//! allocations means installing an allocator, and installing one is an unsafe trait implementation,
//! which the library forbids outright. An integration test is its own crate and carries its own
//! lints, so the measurement can exist without the library relaxing anything. The library's own
//! lints stand exactly as they were. The shape is `busbar-unit-cost`'s `hot_path_allocation.rs`,
//! deliberately: one counting allocator, thread-local, forwarding everything to the system one.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use busbar_unit_ledger::totals::{Book, BucketId, BucketScope, CapDimension, TotalsKey};

thread_local! {
    /// Allocations made on THIS thread. Thread-local on purpose: the harness runs cases in
    /// parallel, and a process-wide counter would be perturbed by whatever else happens to be
    /// allocating at the same moment. The cell is const-initialised and has no destructor, so
    /// reading it from inside the allocator cannot itself allocate and cannot recurse.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

struct Counting;

// SAFETY: every method forwards to the system allocator unchanged and hands back exactly the
// pointer `System` returned. The only addition is a thread-local integer increment, which allocates
// nothing; `try_with` is used so that a thread whose local has already been destroyed skips the
// count rather than panicking inside the allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The widest key there is: all three of its parts are names rather than fixed shapes, so this is
/// the key that costs the most to reach a row with.
fn widest_key() -> TotalsKey {
    TotalsKey::new(
        BucketId::new("user:a-fairly-long-principal-identifier"),
        CapDimension::Class("a-declared-meter-class-name".into()),
        BucketScope::Pool("a-named-pool-inside-the-bucket".into()),
    )
}

/// **MOVING A BALANCE THAT ALREADY EXISTS ALLOCATES NOTHING.**
///
/// The book is keyed by a bucket, a dimension, a scope and a window, and three of those four are
/// names. `BTreeMap` takes its key by value, so reaching an existing row used to mint a fresh copy
/// of every one of those names and throw it away again — on `post`, on every `record_*`, on both
/// arms of a cross-window transfer, and on a pure read through `Book::get`. In the overwhelmingly
/// common case the row is already there and nothing is inserted, so the copy bought nothing at all.
///
/// `Ledger::post` is on the production settle path, so that is a heap allocation per settled unit
/// against ARCHITECTURE.md §10's target of zero outside the arena. The names are interned now, so
/// cloning a key is a refcount bump and the count below is the whole of what a repeat mutation
/// costs: nothing.
#[test]
fn reaching_a_row_that_is_already_there_allocates_nothing() {
    let key = widest_key();
    let mut book = Book::new();
    // The first touch inserts, and an insert is allowed to allocate — it is buying a row that did
    // not exist. Everything after it is the case under measurement.
    book.entry(key.clone(), 86_400).settled += 1;

    let before = allocations();
    for _ in 0..1_000 {
        book.entry(key.clone(), 86_400).settled += 1;
    }
    let after = allocations();

    assert_eq!(
        after - before,
        0,
        "a thousand mutations of one existing balance allocated {} times",
        after - before
    );
    assert_eq!(book.get(&key, 86_400).settled, 1_001);
}

/// The same, for the pure READ. A read that allocates is worse than a write that does: it moves
/// nothing, so the allocation is the entire cost of it.
#[test]
fn reading_a_balance_allocates_nothing() {
    let key = widest_key();
    let mut book = Book::new();
    book.entry(key.clone(), 86_400).settled += 7;

    let before = allocations();
    let mut total = 0i128;
    for _ in 0..1_000 {
        total += book.get(&key, 86_400).settled;
    }
    let after = allocations();

    assert_eq!(
        after - before,
        0,
        "a thousand reads of one balance allocated {} times",
        after - before
    );
    assert_eq!(total, 7_000);
}

/// A key the book has NOT seen is a row that has to be created, and creating one is allowed to
/// allocate. Asserted rather than left implicit, so the case above cannot be read as "the book
/// never allocates" — it says something narrower and more useful, and this is the other half of it.
#[test]
fn a_row_that_does_not_exist_yet_still_costs_an_insert() {
    let mut book = Book::new();
    let key = widest_key();
    let before = allocations();
    book.entry(key, 86_400).settled += 1;
    assert!(
        allocations() > before,
        "inserting a row the book did not hold is what the allocation is FOR"
    );
}
