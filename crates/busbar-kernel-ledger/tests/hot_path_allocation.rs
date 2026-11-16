// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the rate lookup costs, measured.

use stats_alloc::StatsAlloc;
#[cfg(target_env = "msvc")]
use std::alloc::System as Base;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc as Base;

use busbar_kernel_ledger::cost::{LaneClass, RateCard};

/// The shipped allocator (jemalloc), counted process-wide by `stats_alloc`. The counts are
/// process-wide, so the measuring tests run one at a time (nextest runs each in its own process).
#[global_allocator]
static COUNTING: StatsAlloc<Base> = StatsAlloc::new(Base);

/// Allocations and reallocations made so far.
fn allocations() -> u64 {
    let stats = COUNTING.stats();
    stats.allocations as u64 + stats.reallocations as u64
}

/// One measuring test at a time: a second test building its card must not land inside a window.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
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
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
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
