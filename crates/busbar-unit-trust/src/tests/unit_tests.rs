// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: what the loop actually receives from the verify step.

use busbar_caps::{KernelSeal, LaneId, ReasonCode, StepName, TrustToken, UnitToken, Verify};

use super::destination_tests::AllYes;
use super::Pools;
use crate::destination::{DestinationFacts, OriginKind};
use crate::unit::{Trust, VerifyRequest};

const UNPRICED: &str = "no configured rate for model 'arbitrary'";

/// The pinned arrival epoch these tests ask every readiness peek at.
const NOW: u64 = 7;

fn kernel() -> (KernelSeal, TrustToken, UnitToken<Verify>) {
    let seal = KernelSeal::acquire_for_kernel();
    let trust = TrustToken::mint(&seal);
    let token = UnitToken::mint(&seal);
    (seal, trust, token)
}

fn request<'a>(candidates: &'a [DestinationFacts], pool: &'a str) -> VerifyRequest<'a> {
    VerifyRequest {
        origin: OriginKind::Client,
        candidates,
        pool,
        now: NOW,
        unpriced_message: UNPRICED,
    }
}

#[test]
fn a_permitted_candidate_is_sealed_on_its_lane() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let decision = Trust.verify(
        &request(&candidates, "p"),
        &Pools::default(),
        &AllYes::default(),
        &super::destination_tests::AllAdmitted,
        &trust,
        &token,
    );
    let sealed = decision.into_result(&seal).expect("verified");
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].lane(), &LaneId::new("lane-a"));
}

#[test]
fn a_kind_the_origin_may_not_reach_is_dropped_rather_than_refused() {
    let (seal, trust, token) = kernel();
    // A provider push proposing an administrative verb: the candidate is dropped and the step still
    // proceeds, because an empty set is a legitimate answer here.
    let candidates = vec![super::destination_tests::kinds::kernel_verb()];
    let req = VerifyRequest {
        origin: OriginKind::Provider,
        ..request(&candidates, "p")
    };
    let sealed = Trust
        .verify(
            &req,
            &Pools::default(),
            &AllYes::default(),
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds");
    assert!(sealed.is_empty());
}

#[test]
fn a_candidate_failing_its_own_rule_is_dropped() {
    let (seal, trust, token) = kernel();
    let candidates = vec![
        super::destination_tests::kinds::upstream(),
        super::destination_tests::kinds::nested_plane(),
    ];
    let facts = AllYes {
        nested: false,
        ..AllYes::default()
    };
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &facts,
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds");
    assert_eq!(
        sealed.len(),
        1,
        "only the candidate whose rule passed is sealed"
    );
}

#[test]
fn an_all_excluded_pool_still_proceeds_with_an_empty_set() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let facts = AllYes {
        allow_listed: false,
        ..AllYes::default()
    };
    let decision = Trust.verify(
        &request(&candidates, "p"),
        &Pools::default(),
        &facts,
        &super::destination_tests::AllAdmitted,
        &trust,
        &token,
    );
    let sealed = decision
        .into_result(&seal)
        .expect("an empty set proceeds through the door rather than refusing here");
    assert!(sealed.is_empty());
}

#[test]
fn the_pool_allow_list_refuses_at_the_verify_step() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let refusal = Trust
        .verify(
            &request(&candidates, "cold"),
            &Pools::allowing(&["fast"]),
            &AllYes::default(),
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect_err("the key may not use this pool");
    // Its own reason, not a plain scope denial: the ladder answers this before it asks about
    // pricing at all, and the two carry different statuses on the wire.
    assert_eq!(refusal.reason(), ReasonCode::PoolNotPermitted);
    assert_eq!(refusal.step(), Some(StepName::Verify));
    assert!(!refusal.under_hold(), "nothing is charged before the door");
}

#[test]
fn a_reachable_fallback_pool_refuses_the_same_way() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let pools = Pools {
        allowed: Some(vec!["a".to_string()]),
        ..Pools::default()
    }
    .falls_back("a", "b");
    let refusal = Trust
        .verify(
            &request(&candidates, "a"),
            &pools,
            &AllYes::default(),
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect_err("the fallback pool is not allowed");
    assert_eq!(refusal.reason(), ReasonCode::PoolNotPermitted);
}

#[test]
fn an_unpriced_name_refuses_for_having_no_rate() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let pools = Pools::with_card_missing(&["arbitrary"]);
    let refusal = Trust
        .verify(
            &request(&candidates, "arbitrary"),
            &pools,
            &AllYes::default(),
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect_err("no configured rate");
    // Not `Unpriced`, which is a class the present card does not price: nothing is wrong with the
    // caller's budget here, the name they supplied simply cannot be billed.
    assert_eq!(refusal.reason(), ReasonCode::NoRate);
}

/// THE BREAKER IS CONSULTED AT THE SEAL, and it answers what the pre-walk's filter answers.
///
/// Two paths ask about the same open breaker: the pre-walk that filters a lane out before the credit
/// walk, and this step. They must give one answer — a step that sealed a lane the walk excludes is a
/// second opinion about health, and the pick order stops being a stated policy the moment there are
/// two of them.
#[test]
fn a_breaker_open_lane_is_excluded_at_the_seal_exactly_as_the_pre_walk_excludes_it() {
    let (seal, trust, token) = kernel();
    let lanes = super::Lanes::with(|l| {
        l.open_breaker.insert(0);
    });
    assert!(
        !crate::lane::survives_prewalk_filter(
            crate::lane::LaneCandidate { idx: 0, weight: 1 },
            &lanes,
            &lanes,
            "p",
            NOW,
        ),
        "the pre-walk excludes the open lane"
    );

    let candidates = vec![super::destination_tests::kinds::upstream()];
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &AllYes::default(),
            &lanes,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds: an excluded lane is not a refusal");
    assert!(
        sealed.is_empty(),
        "a lane the pre-walk excludes is not sealed by the step beside it"
    );
}

/// A lane the breaker admits is sealed, and the peek asked about exactly that lane.
#[test]
fn an_admitted_lane_is_sealed_and_the_breaker_was_asked_about_it() {
    let (seal, trust, token) = kernel();
    let lanes = super::Lanes::default();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &AllYes::default(),
            &lanes,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds");
    assert_eq!(sealed.len(), 1);
    assert_eq!(
        *lanes.peeks.borrow(),
        vec![0],
        "the readiness peek, not the admission: an enumeration is not a dispatch"
    );
    assert!(
        lanes.admissions.borrow().is_empty(),
        "the one admission happens after selection, not here"
    );
}

/// A card that prices this destination above its own maximum excludes it.
#[test]
fn a_unit_price_over_the_cards_maximum_is_not_sealed() {
    let (seal, trust, token) = kernel();
    let lanes = super::Lanes::default();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let facts = AllYes {
        price_within_max: false,
        ..AllYes::default()
    };
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &facts,
            &lanes,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds");
    assert!(sealed.is_empty());
}

/// THE NETWORK GUARD IS PART OF THE SEALED STEP, not a library beside it.
///
/// The name is allow-listed, its transport key resolves and its lane is permitted — everything the
/// deployment's own tables have to say about it says yes. What it ANSWERS with is the metadata
/// address, and the address a name answers with is part of where a unit may go. A guard that only
/// ran when a transport remembered to call it was a guard with one caller per carrier.
#[test]
fn a_name_answering_with_the_metadata_address_is_not_sealed() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let facts = AllYes {
        resolves_to: Some("169.254.169.254"),
        ..AllYes::default()
    };
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &facts,
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds: an excluded candidate is not a refusal");
    assert!(
        sealed.is_empty(),
        "an allow-listed name that resolves to the metadata address is not sealed"
    );
}

/// The loopback answer is refused for the same reason, and the ordinary upstream still seals.
#[test]
fn a_loopback_answer_is_excluded_while_the_ordinary_upstream_still_seals() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let loopback = AllYes {
        resolves_to: Some("127.0.0.1"),
        ..AllYes::default()
    };
    let excluded = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &loopback,
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds");
    assert!(excluded.is_empty());

    let public = AllYes {
        resolves_to: Some("93.184.216.34"),
        ..AllYes::default()
    };
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &public,
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds");
    assert_eq!(
        sealed.len(),
        1,
        "the normal upstream is sealed exactly as it was"
    );
    assert_eq!(sealed[0].lane(), &LaneId::new("lane-a"));
}

/// A DESTINATION WITH NO LANE IS NOT AN EXCLUSION AND NOT A REFUSAL — it is simply not priced on a
/// lane, and the sealed set is the set of things that are.
///
/// A kernel verb is reached through the route plan rather than through this pool walk, so there is
/// no lane to seal it against and inventing one would be inventing a price. The step still
/// proceeds, and the lane-carrying candidate beside it seals exactly as it would alone.
#[test]
fn a_lane_less_destination_leaves_the_sealed_set_without_refusing_the_step() {
    let (seal, trust, token) = kernel();
    let candidates = vec![
        super::destination_tests::kinds::upstream(),
        super::destination_tests::kinds::kernel_verb(),
    ];
    let sealed = Trust
        .verify(
            &request(&candidates, "p"),
            &Pools::default(),
            &AllYes::default(),
            &super::destination_tests::AllAdmitted,
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect("the step proceeds: a lane-less destination is not a refusal");
    assert_eq!(
        sealed.len(),
        1,
        "only the lane-carrying candidate is priced on a lane"
    );
    assert_eq!(sealed[0].lane(), &LaneId::new("lane-a"));
}
