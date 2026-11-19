// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the rate lookup costs, measured.

use busbar_kernel_ledger::cost::{LaneClass, RateCard};
use busbar_plugin_test::Watch;

/// The one audited test allocator (busbar-ffi `test_watch::Watch`, through busbar-plugin-test),
/// counted PER THREAD (`armed_here`): the harness's own threads allocate while a test runs, and a
/// process-wide count would charge their allocations to the lookups under test. While armed it
/// counts every allocation and every reallocation the measuring thread makes.
#[global_allocator]
static WATCH: Watch = Watch::new();

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

    let mut total = 0u64;
    let spent = WATCH
        .armed_here(b"", || {
            for _ in 0..1_000 {
                total += view.nanos_per_unit("input");

                total += view.nanos_per_unit("a-class-this-lane-does-not-name");
                assert!(!view.class_priced("a-class-this-lane-does-not-name"));
                assert!(view.class_priced("output"));
                assert!(!card.lane_unpriced("lane"));
            }
        })
        .allocs;
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

    let mut hits = 0u32;
    let spent = WATCH
        .armed_here(b"", || {
            for _ in 0..1_000 {
                if card.lane_rates("lane").is_some() {
                    hits += 1;
                }
                assert!(card.lane_rates("mystery").is_none());
            }
        })
        .allocs;
    assert_eq!(hits, 1_000);
    assert_eq!(spent, 0, "the lane step allocates nothing");
}
