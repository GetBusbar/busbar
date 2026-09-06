// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the rate lookup costs, measured.
//!
//! This case lives out here rather than beside the other rate cases for one reason: measuring
//! allocations means installing an allocator, and installing one is an unsafe trait implementation,
//! which the library forbids outright. An integration test is its own crate and carries its own
//! lints, so the measurement can exist without the library relaxing anything. The library's
//! `forbid(unsafe_code)` stands exactly as it was.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use busbar_unit_cost::{LaneClass, RateCard, RateCardVersion};

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

/// A card over one lane pricing four classes.
fn four_class_card() -> RateCard {
    RateCard::from_micro_rates(
        RateCardVersion::new("v1"),
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
///
/// The lookup is on the hot path twice over: every priced line of every posting asks for one, and
/// the read-time derivation asks again for every line it reprices. A card keyed by a composite of
/// two OWNED strings has to build that composite before it can look anything up, which is two heap
/// allocations per lookup, thrown away immediately — paid for nothing, because both strings are
/// already in hand as borrowed text. Keyed lane-first and then class, both steps are asked with the
/// borrowed text directly.
///
/// The claim is measured rather than read off the source, because "no allocation" is exactly the
/// kind of property a later refactor undoes without anyone noticing.
#[test]
fn a_rate_lookup_allocates_nothing() {
    let card = four_class_card();
    let view = card.lane_rates("lane").expect("the lane is priced");
    // A warm-up pass, so nothing lazy is counted against the loop.
    assert_eq!(view.nanos_per_unit("input"), 1_000);
    assert!(view.class_priced("output"));
    assert!(!card.lane_unpriced("lane"));

    let before = allocations();
    let mut total = 0u64;
    for _ in 0..1_000 {
        total += view.nanos_per_unit("input");
        // A class the lane does not name: the miss must not allocate either.
        total += view.nanos_per_unit("a-class-this-lane-does-not-name");
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
/// is allocation-free end to end. A lane the card does not name is the same: the miss is a lookup,
/// not a construction.
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
