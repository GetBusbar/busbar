// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three-way lane cross-check.

use std::collections::{BTreeMap, BTreeSet};

use crate::{cross_check_lane, LaneLegs, LegDeclaration, MeterPolicy};

fn legs(admit: Option<&str>, verified: Option<&str>, response: Option<&str>) -> LaneLegs {
    LaneLegs {
        admit_locator: admit.map(str::to_string),
        verified: verified.map(str::to_string),
        response: response.map(str::to_string),
    }
}

fn policy_with_pool() -> MeterPolicy {
    let mut policy = MeterPolicy::default();
    policy.lane_expansions.insert(
        "frontier".to_string(),
        BTreeSet::from(["fast".to_string(), "slow".to_string()]),
    );
    policy.lane_prices = BTreeMap::from([
        ("fast".to_string(), 900u128),
        ("slow".to_string(), 100u128),
        ("other".to_string(), 50u128),
    ]);
    policy
}

/// All three legs agree: the lane actually reached is the answer, and nothing is disputed.
#[test]
fn three_agreeing_legs_price_against_the_lane_that_was_reached() {
    let check = cross_check_lane(
        &legs(Some("fast"), Some("fast"), Some("fast")),
        &LegDeclaration::default(),
        &policy_with_pool(),
    );
    assert_eq!(check.lane.as_deref(), Some("fast"));
    assert!(!check.disputed);
}

/// The request-side leg is MEMBERSHIP, not equality. A caller naming a pool agrees with any member
/// of that pool, so a pool name never mismatches its own lane.
#[test]
fn a_pool_name_agrees_with_any_of_its_member_lanes() {
    let policy = policy_with_pool();
    for served in ["fast", "slow"] {
        let check = cross_check_lane(
            &legs(Some("frontier"), Some(served), Some(served)),
            &LegDeclaration::default(),
            &policy,
        );
        assert!(!check.disputed, "{served} is a member of the named pool");
        assert_eq!(check.lane.as_deref(), Some(served));
    }
}

/// A lane the named pool does NOT contain is a mismatch, and the answer is the cheaper of the
/// candidate lanes. Posting the lower is the same rule the rest of the settlement follows: a plane
/// cannot profit from a mismatch it caused.
#[test]
fn a_lane_outside_the_named_pool_is_a_mismatch_and_prices_at_the_cheaper_entry() {
    let check = cross_check_lane(
        &legs(Some("frontier"), Some("other"), Some("other")),
        &LegDeclaration::default(),
        &policy_with_pool(),
    );
    assert!(check.disputed);
    assert_eq!(
        check.lane.as_deref(),
        Some("other"),
        "the cheapest of the candidates, which here is the served lane itself"
    );
}

/// The response-side leg is an EQUALITY: a response naming a different lane from the one that was
/// reached is a mismatch, and the cheaper of the two prices.
#[test]
fn a_response_naming_a_different_lane_is_a_mismatch() {
    let check = cross_check_lane(
        &legs(Some("fast"), Some("fast"), Some("slow")),
        &LegDeclaration::default(),
        &policy_with_pool(),
    );
    assert!(check.disputed);
    assert_eq!(
        check.lane.as_deref(),
        Some("slow"),
        "one hundred is cheaper than nine hundred"
    );
}

/// A leg the plane does not DECLARE is not compared at all: a plane that never names a lane in its
/// responses is not disputed for the absence.
#[test]
fn a_leg_the_plane_never_declares_is_skipped() {
    let declared = LegDeclaration {
        admit_locator: true,
        verified: true,
        response: false,
    };
    let check = cross_check_lane(
        &legs(Some("fast"), Some("fast"), None),
        &declared,
        &policy_with_pool(),
    );
    assert!(!check.disputed);
    assert_eq!(check.lane.as_deref(), Some("fast"));
}

/// A leg the plane DOES declare and then fails to produce is a dispute: one fewer check stands
/// between a wrong lane and an invoice, and that is worth a verdict.
#[test]
fn a_declared_leg_that_never_arrives_is_disputed() {
    let check = cross_check_lane(
        &legs(Some("fast"), Some("fast"), None),
        &LegDeclaration::default(),
        &policy_with_pool(),
    );
    assert!(check.disputed);
}

/// A name with no declared expansion stands for itself, so an ordinary lane name needs no
/// configuration to agree with itself.
#[test]
fn an_unexpanded_name_stands_for_itself() {
    let policy = MeterPolicy::default();
    let check = cross_check_lane(
        &legs(Some("plain"), Some("plain"), Some("plain")),
        &LegDeclaration::default(),
        &policy,
    );
    assert!(!check.disputed);
    assert_eq!(policy.expansion_of("plain").len(), 1);
}

/// An unpriced lane sorts as the cheapest thing there is, which is the conservative reading when
/// the legs disagree about a lane nobody has a price for.
#[test]
fn an_unpriced_lane_is_the_cheapest_candidate() {
    let policy = policy_with_pool();
    assert_eq!(policy.price_of("nobody-prices-this"), 0);
    let check = cross_check_lane(
        &legs(Some("fast"), Some("fast"), Some("nobody-prices-this")),
        &LegDeclaration::default(),
        &policy,
    );
    assert!(check.disputed);
    assert_eq!(check.lane.as_deref(), Some("nobody-prices-this"));
}
