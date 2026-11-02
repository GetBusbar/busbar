// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pick costs per member.

use crate::ports::DestinationId;
use crate::select::WeightedFloor;

fn offered(n: u64) -> Vec<(DestinationId, u32)> {
    (0..n).map(|i| (DestinationId::new(i), 1u32)).collect()
}

/// And the rotation itself is unchanged: the pick ORDER is the previous release's behaviour and is
#[test]
fn the_rotation_order_is_byte_identical_across_the_restructure() {
    let floor = WeightedFloor::new();
    let members = vec![
        (DestinationId::new(0), 5u32),
        (DestinationId::new(1), 3u32),
        (DestinationId::new(2), 1u32),
    ];
    let picked: Vec<DestinationId> = (0..18).filter_map(|_| floor.take_turn(&members)).collect();
    let expected: Vec<DestinationId> = [0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 1, 0, 2, 0, 1, 0, 1, 0]
        .into_iter()
        .map(DestinationId::new)
        .collect();
    assert_eq!(picked, expected, "the smooth weighted rotation over 5/3/1");

    let second_pool = WeightedFloor::new();
    let other: Vec<DestinationId> = (0..3)
        .filter_map(|_| second_pool.take_turn(&members))
        .collect();
    let expected_other: Vec<DestinationId> =
        [0, 1, 0].into_iter().map(DestinationId::new).collect();
    assert_eq!(other, expected_other);
}

/// A pool the floor has never seen still rotates from a clean slate, and seeing it does not disturb
#[test]
fn a_new_pool_starts_its_own_rotation_without_touching_an_existing_one() {
    let (a, b) = (WeightedFloor::new(), WeightedFloor::new());
    let members = offered(3);

    let first = a.take_turn(&members);
    b.take_turn(&members);
    b.take_turn(&members);
    let second = a.take_turn(&members);

    assert_eq!(first, Some(DestinationId::new(0)));
    assert_eq!(
        second,
        Some(DestinationId::new(1)),
        "pool a's rotation carried on from where it was, whatever pool b did"
    );
}

/// The membership with the blocklist applied is read on every hop of every walk, and the pool that
#[test]
fn an_unblocked_pools_membership_is_borrowed_not_copied() {
    use crate::pool::{Member, Pool};
    use std::borrow::Cow;

    let members = vec![
        Member::new(DestinationId::new(0), "a", 1),
        Member::new(DestinationId::new(1), "b", 1),
    ];
    let pool = Pool::new("p", members.clone());
    assert!(
        matches!(pool.admissible_members(), Cow::Borrowed(_)),
        "an empty blocklist has nothing to filter, so nothing is copied"
    );
    assert_eq!(pool.admissible_members().as_ref(), members.as_slice());

    let mut blocked = Pool::new("p", members);
    blocked.failover.exclusions = vec!["b".to_string()];
    let admissible = blocked.admissible_members();
    assert!(
        matches!(admissible, Cow::Owned(_)),
        "a real blocklist yields a filtered membership of its own"
    );
    assert_eq!(
        admissible
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a"]
    );
}
