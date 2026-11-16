// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What filling a bounded list costs.

use stats_alloc::StatsAlloc;
#[cfg(target_env = "msvc")]
use std::alloc::System as Base;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc as Base;

use busbar_contract::{BoundedVec, MAX_LEGS};

/// The shipped allocator (jemalloc), counted process-wide by `stats_alloc`.
#[global_allocator]
static ALLOCATOR: StatsAlloc<Base> = StatsAlloc::new(Base);

/// Allocations and reallocations so far, the two the old counter summed.
fn allocations() -> usize {
    let stats = ALLOCATOR.stats();
    stats.allocations + stats.reallocations
}

/// An empty list is free.
fn an_untouched_bounded_list_allocates_nothing() {
    let before = allocations();
    let list: BoundedVec<u8, MAX_LEGS> = BoundedVec::new();
    let after = allocations();
    assert!(list.is_empty());
    assert_eq!(after - before, 0, "an empty bounded list allocated");
}

/// Filling one to its declared capacity is one allocation, not a doubling sequence.
fn filling_a_bounded_list_to_capacity_takes_one_allocation() {
    let mut list: BoundedVec<u8, MAX_LEGS> = BoundedVec::new();

    let before = allocations();
    for i in 0..MAX_LEGS {
        list.push(u8::try_from(i).expect("the ceiling fits in a byte"))
            .expect("every push is under the ceiling");
    }
    let after = allocations();

    assert_eq!(list.len(), MAX_LEGS);
    assert!(
        after - before <= 1,
        "filling a bounded list to its declared capacity took {} allocations",
        after - before
    );
}

/// The two measurements, one after another on one thread: no other test's allocations can
#[test]
fn bounded_lists_allocate_exactly_what_their_capacity_says() {
    an_untouched_bounded_list_allocates_nothing();
    filling_a_bounded_list_to_capacity_takes_one_allocation();
}
