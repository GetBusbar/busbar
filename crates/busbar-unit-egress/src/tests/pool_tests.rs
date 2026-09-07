// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pool's own accessors, stated directly.
//!
//! Nothing here drives a walk. These are the four readings every consumer in the crate takes off a
//! pool — where a member sits, whether a name is in the table at all, and how many pools there
//! are — and each is asserted at a value only the real answer produces, so a reading that answered
//! a constant would fail rather than agree with itself.

use super::member;
use crate::pool::{Member, Pool, PoolTable};
use crate::ports::DestinationId;

fn three_member_pool() -> Pool {
    Pool::new(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
            member(DestinationId::new(2), "c"),
        ],
    )
}

/// Every position is its own, and a destination the pool does not carry has none. Asserted at three
/// distinct positions so no single constant can stand in for the answer.
#[test]
fn a_members_position_is_where_the_operator_put_it() {
    let pool = three_member_pool();
    assert_eq!(pool.position_of(DestinationId::new(0)), Some(0));
    assert_eq!(pool.position_of(DestinationId::new(1)), Some(1));
    assert_eq!(pool.position_of(DestinationId::new(2)), Some(2));
}

/// A destination that is not in the membership has no position — the answer a caller reads as "this
/// pool does not name that member", and the one that must never be a position of somebody else.
#[test]
fn a_destination_the_pool_does_not_carry_has_no_position() {
    let pool = three_member_pool();
    assert_eq!(pool.position_of(DestinationId::new(9)), None);
}

/// The match is on the destination the caller asked about and not on its complement: a pool whose
/// first member is somebody else must not answer with that member's position.
#[test]
fn a_position_is_the_asked_for_member_and_not_the_first_that_differs() {
    let pool = three_member_pool();
    // Position 0 is destination 0. Asking about destination 2 must reach position 2, which a
    // first-that-differs reading would answer as 0.
    assert_eq!(pool.position_of(DestinationId::new(2)), Some(2));
    // And asking about destination 0 must reach position 0, which the same inverted reading would
    // answer as 1.
    assert_eq!(pool.position_of(DestinationId::new(0)), Some(0));
}

/// The blocklist is applied once, before the walk: an excluded member is removed from the
/// membership rather than ranked last.
#[test]
fn the_blocklist_removes_a_member_from_the_membership() {
    let mut pool = three_member_pool();
    pool.failover.exclusions = vec!["b".to_string()];
    let admissible = pool.admissible_members();
    let names: Vec<&str> = admissible.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["a", "c"]);
}

/// A pool that blocklists nobody borrows its own membership rather than copying it — the common
/// case every hop of every walk pays for.
#[test]
fn a_pool_with_no_blocklist_borrows_its_own_membership() {
    let pool = three_member_pool();
    assert!(matches!(
        pool.admissible_members(),
        std::borrow::Cow::Borrowed(_)
    ));
    assert_eq!(pool.admissible_members().len(), 3);
}

/// The table counts what was put in it, and an insert of the same name replaces rather than adds.
#[test]
fn the_table_counts_the_pools_it_holds() {
    let mut table = PoolTable::new();
    assert_eq!(table.len(), 0);
    assert!(table.is_empty());

    table.insert(Pool::new("primary", vec![]));
    assert_eq!(table.len(), 1);
    assert!(!table.is_empty());

    table.insert(Pool::new("secondary", vec![]));
    assert_eq!(table.len(), 2);
    assert!(!table.is_empty());

    // A third distinct name, so the count is asserted at a value no small constant stands in for.
    table.insert(Pool::new("tertiary", vec![]));
    assert_eq!(table.len(), 3);
}

/// Re-inserting a name replaces that pool and does not grow the table.
#[test]
fn re_inserting_a_name_replaces_rather_than_grows() {
    let mut table = PoolTable::new();
    table.insert(Pool::new("primary", vec![]));
    table.insert(Pool::new(
        "primary",
        vec![Member::new(DestinationId::new(4), "d", 1)],
    ));
    assert_eq!(table.len(), 1);
    assert_eq!(
        table
            .get("primary")
            .expect("the pool is there")
            .members
            .len(),
        1
    );
}

/// Emptiness is a fact about the table and not about the pools in it: a table holding one pool with
/// no members is not empty.
#[test]
fn a_table_holding_an_empty_pool_is_not_itself_empty() {
    let mut table = PoolTable::new();
    table.insert(Pool::new("primary", vec![]));
    assert!(!table.is_empty());
    assert_eq!(table.len(), 1);
}
