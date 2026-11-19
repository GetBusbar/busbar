// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::auth::{ChainVerdict, SignedRequestAuthority};
use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::NewKeySpec;
use crate::host_services::{
    KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute, ServingGeneration,
};
use busbar_contract::kinds::codes::KindCode;
use busbar_contract::services::Caller;

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("no child expected");
    }
}
struct Posted;
impl super::super::EndPost for Posted {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}

pub(super) async fn fixture() -> (Arc<GovState>, String) {
    let gov = Arc::new(
        GovState::new_with_core(
            crate::real_store::core().await,
            None,
            Some(TokenSigner::from_secret_bytes(&[17; 32], DEFAULT_KID)),
        )
        .await
        .unwrap(),
    );
    let (_, token) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "request-bound".into(),
                ..Default::default()
            },
            2000,
            1000,
        )
        .await
        .unwrap();
    (gov, token.expose(&crate::seal::lend()).to_owned())
}

pub(super) fn verified(gov: &GovState, token: &str) -> SignedRequestAuthority {
    match crate::auth::keys_arm_verdict(Some(gov), Some(token), 1000, None) {
        ChainVerdict::Identified {
            signed_authority: Some(authority),
            ..
        } => authority,
        _ => panic!("actual signed verifier did not retain request authority"),
    }
}

pub(super) fn context(
    unit: u64,
    authority: SignedRequestAuthority,
) -> (InvocationContext, NativeInvocationAdmission) {
    let core = Arc::new(KernelServices::new());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core
        .units()
        .pre_admitted_signed_for(unit, &caller, authority, 0));
    let generation = Arc::new(ServingGeneration::new(core, Arc::new(NoChildren)));
    (
        InvocationContext::new(generation, caller, unit).unwrap(),
        lease,
    )
}

fn admit(
    gov: Arc<GovState>,
    context: InvocationContext,
) -> (super::super::PlaneMoney, AdmittedRequest) {
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let receipt = RequestAllocation::new(
        context,
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        1000,
    )
    .unwrap()
    .local(&routes)
    .unwrap();
    let money = super::super::PlaneMoney::new(gov, Arc::new(Posted));
    let admitted = money
        .admit_existing(
            receipt.begin().unwrap(),
            Arc::from([]),
            super::super::money::FeeRefund::CallerStatus,
            crate::config::groups::ExhaustionMode::FinishUnit,
        )
        .unwrap();
    (money, admitted)
}

#[tokio::test]
async fn signed_verifier_receipt_binds_once_to_the_original_record_before_money() {
    let (gov, token) = fixture().await;
    let authority = verified(&gov, &token);
    let duplicate = authority.clone();
    let (ctx, _lease) = context(61, authority);
    let core = Arc::new(KernelServices::new());
    let other = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    assert!(!core
        .units()
        .pre_admitted_signed_for(62, &other, duplicate, 0));
    assert!(core.units().get(62).is_none());
    let (_money, admitted) = admit(gov.clone(), ctx.clone());
    let proof = admitted.signed_authority().expect("installed actual proof");
    assert!(Arc::ptr_eq(proof.original_key(), admitted.key()));
    assert!(proof.current_key(&gov, 1001, None).is_ok());
    let expired = proof.current_key(&gov, 2000, None).unwrap_err();
    assert_eq!(
        crate::governance::selected_policy::SelectedPolicyRefusal::from(expired),
        crate::governance::selected_policy::SelectedPolicyRefusal::CurrentAuthority(
            crate::governance::current_credential::CurrentCredentialRefusal::Expired
        )
    );
    assert!(Arc::ptr_eq(proof.original_key(), admitted.key()));
    assert!(
        admitted.signed_authority().is_some(),
        "current refusal does not replace or retire original custody"
    );
    ctx.retire();
    assert!(admitted.signed_authority().is_none());
    assert!(admitted.matches_money_identity(&admitted.book, &admitted.open, &admitted.grant));
    assert!(!admitted.matches_money_identity(&admitted.book, &Arc::new(()), &admitted.grant));
    assert!(!admitted.matches_money(&admitted.book, &admitted.open, &admitted.grant));
}

#[tokio::test]
async fn concurrent_equal_key_requests_never_borrow_another_verification_occurrence() {
    let (gov, token) = fixture().await;
    let (first, _lease_a) = context(63, verified(&gov, &token));
    let (second, _lease_b) = context(64, verified(&gov, &token));
    assert!(Arc::ptr_eq(
        first.principal().unwrap(),
        second.principal().unwrap()
    ));
    let (_money_a, a) = admit(gov.clone(), first);
    let (_money_b, b) = admit(gov, second);
    assert!(
        !std::ptr::eq(a.signed_authority().unwrap(), b.signed_authority().unwrap()),
        "equal original key Arcs are not request identity"
    );
    let core = Arc::new(KernelServices::new());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let _lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        65,
        &caller,
        crate::host_units::UnitRecord {
            principal: Some(a.key().clone()),
            depth: 0
        }
    ));
    let unsigned = InvocationContext::new(
        Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
        caller,
        65,
    )
    .unwrap();
    let (_money, unsigned) = admit(a.governance.clone(), unsigned);
    assert!(
        unsigned.signed_authority().is_none(),
        "a key-only allocation cannot acquire a signed proof"
    );
}

#[tokio::test]
async fn signed_receipt_refuses_a_different_governance_authority_domain() {
    let (gov, token) = fixture().await;
    let (foreign, _) = fixture().await;
    let (ctx, _lease) = context(66, verified(&gov, &token));
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let receipt = RequestAllocation::new(
        ctx.clone(),
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        1000,
    )
    .unwrap()
    .local(&routes)
    .unwrap();
    let money = super::super::PlaneMoney::new(foreign, Arc::new(Posted));
    assert!(money
        .admit_existing(
            receipt.begin().unwrap(),
            Arc::from([]),
            super::super::money::FeeRefund::CallerStatus,
            crate::config::groups::ExhaustionMode::FinishUnit
        )
        .is_err());
    assert!(!ctx.effects_allowed());
}
