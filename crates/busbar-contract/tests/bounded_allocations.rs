// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What filling a bounded list costs.
//!
//! Its own test binary, because proving this needs a counting global allocator and a global
//! allocator belongs to the whole binary it is installed in. And ONE test, because the counter is
//! global too: a second test running on another thread allocates into the same count, and a
//! measurement taken while it does reads that thread's work as this one's.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::{BoundedVec, MAX_LEGS};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting the allocations that go through it.
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// An empty list is free.
///
/// The overwhelmingly common case on this ABI: a default-constructed facts or patch value whose
/// bounded field the plugin never touches.
fn an_untouched_bounded_list_allocates_nothing() {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let list: BoundedVec<u8, MAX_LEGS> = BoundedVec::new();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    assert!(list.is_empty());
    assert_eq!(after - before, 0, "an empty bounded list allocated");
}

/// Filling one to its declared capacity is one allocation, not a doubling sequence.
///
/// The capacity is part of the type and the list refuses past it, so every reallocation on the way
/// to a size that was known at compile time is waste: this was four allocations and three copies
/// for eight bytes.
fn filling_a_bounded_list_to_capacity_takes_one_allocation() {
    let mut list: BoundedVec<u8, MAX_LEGS> = BoundedVec::new();

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for i in 0..MAX_LEGS {
        list.push(u8::try_from(i).expect("the ceiling fits in a byte"))
            .expect("every push is under the ceiling");
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(list.len(), MAX_LEGS);
    assert!(
        after - before <= 1,
        "filling a bounded list to its declared capacity took {} allocations",
        after - before
    );
}

/// Asking for the capacity up front is the same one allocation, taken earlier.
fn a_list_built_with_its_declared_capacity_never_reallocates() {
    let mut list: BoundedVec<u8, MAX_LEGS> = BoundedVec::with_declared_capacity();

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for i in 0..MAX_LEGS {
        list.push(u8::try_from(i).expect("the ceiling fits in a byte"))
            .expect("every push is under the ceiling");
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(after - before, 0, "a pre-sized bounded list reallocated");
    assert!(list.push(0).is_err(), "the ceiling still refuses");
}

/// The three measurements, one after another on one thread: no other test's allocations can
/// land in a window this binary is counting.
#[test]
fn bounded_lists_allocate_exactly_what_their_capacity_says() {
    an_untouched_bounded_list_allocates_nothing();
    filling_a_bounded_list_to_capacity_takes_one_allocation();
    a_list_built_with_its_declared_capacity_never_reallocates();
}
