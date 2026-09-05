// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: what the loop actually receives from the verify step.

use busbar_caps::{KernelSeal, LaneId, ReasonCode, StepName, TrustToken, UnitToken, Verify};

use super::destination_tests::AllYes;
use super::Pools;
use crate::destination::{DestinationFacts, OriginKind};
use crate::unit::{Trust, VerifyRequest};

const UNPRICED: &str = "no configured rate for model 'arbitrary'";

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
        .verify(&req, &Pools::default(), &AllYes::default(), &trust, &token)
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
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect_err("the key may not use this pool");
    assert_eq!(refusal.reason(), ReasonCode::ScopeDenied);
    assert_eq!(refusal.step(), StepName::Verify);
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
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect_err("the fallback pool is not allowed");
    assert_eq!(refusal.reason(), ReasonCode::ScopeDenied);
}

#[test]
fn an_unpriced_name_refuses_as_unpriced() {
    let (seal, trust, token) = kernel();
    let candidates = vec![super::destination_tests::kinds::upstream()];
    let pools = Pools::with_card_missing(&["arbitrary"]);
    let refusal = Trust
        .verify(
            &request(&candidates, "arbitrary"),
            &pools,
            &AllYes::default(),
            &trust,
            &token,
        )
        .into_result(&seal)
        .expect_err("no configured rate");
    assert_eq!(refusal.reason(), ReasonCode::Unpriced);
}
