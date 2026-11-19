// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the rate lookup costs, measured.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;

#[cfg(target_env = "msvc")]
use std::alloc::System as Base;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc as Base;

use busbar_kernel_ledger::cost::{LaneClass, RateCard};

thread_local! {
    /// Allocations and reallocations made by this thread.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// The shipped allocator (jemalloc), counted PER THREAD: the harness's own threads allocate while a
/// test runs, and a process-wide count would charge their allocations to the lookups under test.
struct Counting;

#[global_allocator]
static COUNTING: Counting = Counting;

fn count() {
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get().wrapping_add(1)));
}

// SAFETY: every call is delegated unchanged to the base allocator; the count is a thread-local
// integer that never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller upholds GlobalAlloc's contract for `layout`.
        unsafe { Base.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: as in `alloc`.
        unsafe { Base.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: `ptr` and `layout` came from this allocator, which forwards to `Base`.
        unsafe { Base.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` came from this allocator, which forwards to `Base`.
        unsafe { Base.dealloc(ptr, layout) }
    }
}

/// Allocations and reallocations this thread has made so far.
fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

/// A card over one lane pricing four classes.
fn four_class_card() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new("lane", "input"), 1.0),
            (LaneClass::new("lane", "output"), 2.0),
            (LaneClass::new("lane", "cache_read"), 3.0),
            (LaneClass::new("lane", "cache_write"), 4.0),
        ],
        0,
    )
}

/// A RATE LOOKUP ALLOCATES NOTHING.
#[test]
fn a_rate_lookup_allocates_nothing() {
    let card = four_class_card();
    let view = card.lane_rates("lane").expect("the lane is priced");

    assert_eq!(view.nanos_per_unit("input"), 1_000);
    assert!(view.class_priced("output"));
    assert!(!card.lane_unpriced("lane"));

    let before = allocations();
    let mut total = 0u64;
    for _ in 0..1_000 {
        total += view.nanos_per_unit("input");

        total += view.nanos_per_unit("a-class-this-lane-does-not-name");
        assert!(!view.class_priced("a-class-this-lane-does-not-name"));
        assert!(view.class_priced("output"));
        assert!(!card.lane_unpriced("lane"));
    }
    let spent = allocations() - before;
    assert_eq!(total, 1_000_000, "the loop really did read the rates");
    assert_eq!(
        spent, 0,
        "a thousand lookups on borrowed text must allocate nothing"
    );
}

/// Resolving the lane itself allocates nothing either, so a whole priced line — lane, then class —
#[test]
fn resolving_a_lane_allocates_nothing() {
    let card = four_class_card();
    assert!(card.lane_rates("lane").is_some());
    assert!(card.lane_rates("mystery").is_none());

    let before = allocations();
    let mut hits = 0u32;
    for _ in 0..1_000 {
        if card.lane_rates("lane").is_some() {
            hits += 1;
        }
        assert!(card.lane_rates("mystery").is_none());
    }
    assert_eq!(hits, 1_000);
    assert_eq!(allocations() - before, 0, "the lane step allocates nothing");
}
