// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::{
    KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute, ServingGeneration,
};
use crate::host_units::UnitRecord;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::Caller;

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("pre-admission cannot nest");
    }
}

fn context(unit: u64) -> (InvocationContext, NativeInvocationAdmission) {
    let core = Arc::new(KernelServices::new());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        unit,
        &caller,
        UnitRecord {
            principal: Some(Arc::new(VirtualKey {
                id: "payer".into(),
                enabled: true,
                ..Default::default()
            })),
            depth: 0,
        }
    ));
    let generation = Arc::new(ServingGeneration::new(core, Arc::new(NoChildren)));
    (
        InvocationContext::new(generation, caller, unit).unwrap(),
        lease,
    )
}

fn allocation(context: InvocationContext) -> RequestAllocation {
    RequestAllocation::new(
        context,
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        100,
    )
    .unwrap()
}

#[test]
fn allocation_is_take_once_and_local_is_explicit() {
    let (context, _lease) = context(1);
    let pending = allocation(context.clone());
    assert!(RequestAllocation::new(
        context.clone(),
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        100
    )
    .is_err());
    assert!(!context.effects_allowed());
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let receipt = pending.local(&routes).unwrap();
    assert_eq!(receipt.pool(), "seat\u{1f}");
    assert_eq!(receipt.domain(), &RequestDomain::Local);
    let committing = receipt.begin().unwrap();
    assert!(committing.is_live());
    assert_eq!(committing.key().id, "payer");
    assert!(!context.effects_allowed());
    drop(committing);
    assert!(!context.effects_allowed());
}

#[test]
fn ended_or_reused_record_cannot_admit() {
    let (context, _lease) = context(2);
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let receipt = allocation(context.clone()).local(&routes).unwrap();
    context.generation().core().units().ended(2);
    assert!(receipt.begin().is_err());
    assert!(!context.effects_allowed());
}

#[test]
fn foreign_seat_and_foreign_walk_cannot_bind_a_route() {
    let (ctx, _lease) = context(3);
    let routes = RequestRoutes::new("other", None, None, None).unwrap();
    assert!(allocation(ctx).local(&routes).is_err());
    let (first, _lease_a) = context(4);
    let (second, _lease_b) = context(5);
    let walk = RequestWalk::new(&second).unwrap();
    assert!(!walk.accepts(&first));
}

#[test]
fn unknown_forward_never_becomes_local_or_registration() {
    let (context, _lease) = context(6);
    let walk = RequestWalk::new(&context).unwrap();
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    assert!(allocation(context)
        .forward(&routes, &walk, Some("unknown"))
        .is_err());
}

#[test]
fn pending_registration_does_not_replace_an_existing_unit() {
    let (context, _lease) = context(7);
    let stranger = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    assert!(!context.generation().core().units().pre_admitted_for(
        7,
        &stranger,
        UnitRecord::default()
    ));
    assert_eq!(context.principal().unwrap().id, "payer");
    assert!(!context.effects_allowed());
}
