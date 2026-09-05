// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pick costs per member.
//!
//! The weighted floor runs once per hop of every route walk, so anything it does per OFFERED MEMBER
//! is paid on the request path times pool membership. The pool name is a borrowed `&str` for the
//! whole walk, and there is no reason for a turn of the rotation to own a copy of it once per
//! member. This crate forbids unsafe, so the count cannot be taken with a counting allocator; what
//! is measured instead is the shape that decides it — how many keys carry a pool name at all.

use crate::ports::DestinationId;
use crate::select::WeightedFloor;

fn offered(n: u64) -> Vec<(DestinationId, u32)> {
    (0..n).map(|i| (DestinationId::new(i), 1u32)).collect()
}

/// One owned pool name per pool, not one per member per pick.
///
/// Keyed `(String, DestinationId)` the floor allocates the pool name once for every offered member
/// on every pick, and holds one owned copy of it per member for the life of the unit. Keyed two
/// levels deep it allocates the name once, on first sight of the pool, and every member lookup
/// after that borrows.
#[test]
fn the_floor_owns_one_pool_name_per_pool_not_one_per_member() {
    let floor = WeightedFloor::new();
    let wide = offered(64);
    let narrow = offered(4);

    for _ in 0..10 {
        floor.take_turn("wide", &wide);
        floor.take_turn("narrow", &narrow);
    }

    let (pool_names, credits) = floor.tracked();
    assert_eq!(
        pool_names, 2,
        "one owned pool name per pool, whatever the membership"
    );
    assert_eq!(
        credits, 68,
        "the credits themselves are still one per member per pool"
    );
}

/// And the rotation itself is unchanged: the pick ORDER is the previous release's behaviour and is
/// what the oracle pins, so the restructure has to be invisible in the sequence.
#[test]
fn the_rotation_order_is_byte_identical_across_the_restructure() {
    let floor = WeightedFloor::new();
    let members = vec![
        (DestinationId::new(0), 5u32),
        (DestinationId::new(1), 3u32),
        (DestinationId::new(2), 1u32),
    ];
    let picked: Vec<DestinationId> = (0..18)
        .filter_map(|_| floor.take_turn("p", &members))
        .collect();
    let expected: Vec<DestinationId> = [0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 1, 0, 2, 0, 1, 0, 1, 0]
        .into_iter()
        .map(DestinationId::new)
        .collect();
    assert_eq!(picked, expected, "the smooth weighted rotation over 5/3/1");

    // The same destination in a second pool is a second, independent rotation.
    let other: Vec<DestinationId> = (0..3)
        .filter_map(|_| floor.take_turn("q", &members))
        .collect();
    let expected_other: Vec<DestinationId> = [0, 1, 0].into_iter().map(DestinationId::new).collect();
    assert_eq!(other, expected_other);
}

/// A pool the floor has never seen still rotates from a clean slate, and seeing it does not disturb
/// a pool already running.
#[test]
fn a_new_pool_starts_its_own_rotation_without_touching_an_existing_one() {
    let floor = WeightedFloor::new();
    let members = offered(3);

    let first = floor.take_turn("a", &members);
    floor.take_turn("b", &members);
    floor.take_turn("b", &members);
    let second = floor.take_turn("a", &members);

    assert_eq!(first, Some(DestinationId::new(0)));
    assert_eq!(
        second,
        Some(DestinationId::new(1)),
        "pool a's rotation carried on from where it was, whatever pool b did"
    );
}
