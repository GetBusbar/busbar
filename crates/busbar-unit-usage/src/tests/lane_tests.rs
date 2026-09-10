// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three-way lane cross-check.

use std::collections::BTreeSet;

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
fn a_lane_outside_the_named_pool_is_a_mismatch_and_prices_at_the_first_candidate_by_name() {
    let check = cross_check_lane(
        &legs(Some("frontier"), Some("other"), Some("other")),
        &LegDeclaration::default(),
        &policy_with_pool(),
    );
    assert!(check.disputed);
    assert_eq!(
        check.lane.as_deref(),
        Some("fast"),
        "the first candidate by name; the expansion's members join the served lane as candidates"
    );
}

/// The response-side leg is an EQUALITY: a response naming a different lane from the one that was
/// reached is a mismatch, and the first of the two candidates by name is what the posting prices
/// against.
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
        Some("fast"),
        "the first candidate by name, stable for a given pair of candidates"
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

/// **THE DISPUTED PICK IS THE FIRST CANDIDATE BY NAME, AND IT ALWAYS WAS.**
///
/// This unit used to hold a comparable price per lane and sort the candidates on it. The
/// composition root only ever built that table EMPTY — the one type that could fill it is
/// constructed by `::default()` at every site in the shipped binary — so every candidate compared
/// equal and the name decided the answer on every unit the node has ever run. What a lane costs
/// belongs to the dated card; a second copy of it inside the unit that meters was an answer to a
/// question this unit is not asked, and the answer it would have given was never the one it gave.
///
/// Driven both ways round, so the pick is a property of the names and not of the order the legs
/// happen to arrive in.
#[test]
fn a_disputed_lane_is_decided_by_name_and_is_stable_either_way_round() {
    let policy = policy_with_pool();
    for (verified, response) in [
        ("fast", "nobody-prices-this"),
        ("nobody-prices-this", "fast"),
    ] {
        let check = cross_check_lane(
            &legs(Some(verified), Some(verified), Some(response)),
            &LegDeclaration::default(),
            &policy,
        );
        assert!(check.disputed);
        assert_eq!(
            check.lane.as_deref(),
            Some("fast"),
            "the same two candidates must pick the same lane whichever leg carried which"
        );
    }
}
