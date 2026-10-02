// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pick costs per member.
//!
//! The weighted floor runs once per hop of every route walk, so anything it does per OFFERED MEMBER
//! is paid on the request path times pool membership. The pool name is a borrowed `&str` for the
//! whole walk, and there is no reason for a turn of the rotation to own a copy of it once per
//! member. This crate forbids unsafe, so the count cannot be taken with a counting allocator; what
//! is measured instead is the shape that decides it — how many keys carry a pool name at all.

use super::harness::{ok_frames, Script};
use super::{member, Node};
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
    let expected_other: Vec<DestinationId> =
        [0, 1, 0].into_iter().map(DestinationId::new).collect();
    assert_eq!(other, expected_other);
}

/// The request's own bytes are rendered once and handed to the wire where they lie.
///
/// The transport renders the envelope into the arena — that is what the arena is for, and it is the
/// only allocation the hot path is meant to make for these bytes. Copying them straight back out
/// into an owned buffer pays for the whole request body a second time on the money path and gives
/// the wire a buffer the arena never saw. The address is the proof: the same allocation is the same
/// address, and a copy is somewhere else.
#[test]
fn the_bytes_that_go_on_the_wire_are_the_arenas_own_and_not_a_copy_of_them() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());

    let encoded = node.transport.encoded_at.lock().unwrap().clone();
    let written = node.transport.written_at.lock().unwrap().clone();
    assert_eq!(encoded.len(), 1, "one envelope was rendered");
    assert_eq!(
        written, encoded,
        "the wire was handed the arena's own bytes rather than a second copy of them"
    );
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

/// The membership with the blocklist applied is read on every hop of every walk, and the pool that
/// blocklists nobody is the common case by a wide margin. That case has nothing to compute, so it
/// has nothing to copy either: it hands back a borrow of the pool's own membership, and only a pool
/// that actually excludes somebody pays for the filtered copy.
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
