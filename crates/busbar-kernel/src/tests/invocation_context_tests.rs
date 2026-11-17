// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use futures::FutureExt;

#[derive(Default)]
struct HeldRoute(Mutex<Option<NestDone>>);
impl NestRoute for HeldRoute {
    fn nest(&self, _context: InvocationContext, _: Nest, done: NestDone) {
        *self.0.lock().unwrap() = Some(done);
    }
}

fn caller(name: &str) -> Caller {
    Caller::for_test(
        Arc::from(name),
        busbar_contract::abi::mechanism::KindCode::Plane,
    )
}

#[test]
fn invocation_refuses_missing_unit_and_another_instance() {
    let core = Arc::new(KernelServices::new());
    core.admit("plane", InstanceFacts::default())
        .now_or_never()
        .unwrap()
        .unwrap();
    let generation = Arc::new(ServingGeneration::new(
        core.clone(),
        Arc::new(HeldRoute::default()),
    ));
    let owner = caller("plane");
    assert!(InvocationContext::new(generation.clone(), owner.clone(), 7).is_err());
    core.units()
        .admitted(7, crate::host_units::UnitRecord::default());
    assert!(
        InvocationContext::new(generation.clone(), owner.clone(), 7).is_err(),
        "numeric unit alone grants no invocation authority"
    );
    core.units()
        .admitted_for(7, &owner, crate::host_units::UnitRecord::default());
    assert!(
        InvocationContext::new(generation.clone(), caller("plane"), 7).is_err(),
        "another incarnation of the same named plane cannot take a unit"
    );
    let context = InvocationContext::new(generation, owner.clone(), 7).unwrap();
    assert!(context.accepts(&owner));
    assert!(!context.accepts(&caller("elsewhere")));
    core.units()
        .admitted(7, crate::host_units::UnitRecord::default());
    assert!(
        !context.accepts(&owner),
        "reusing a numeric unit cannot restore authority"
    );
}

#[test]
fn native_invocation_requires_exact_opened_owner_without_legacy_service_grants() {
    let core = Arc::new(KernelServices::new());
    let generation = Arc::new(ServingGeneration::new(
        Arc::clone(&core),
        Arc::new(HeldRoute::default()),
    ));
    let owner = caller("native");
    core.units()
        .admitted_for(17, &owner, crate::host_units::UnitRecord::default());
    assert!(InvocationContext::new(Arc::clone(&generation), owner.clone(), 17).is_err());
    let admission = core.admit_native_invocation(&owner).unwrap();
    assert!(
        core.admit_native_invocation(&owner).is_err(),
        "one live lease owns each incarnation"
    );
    assert!(
        core.facts(&owner).is_none(),
        "native execution admission grants no legacy services"
    );
    let context = InvocationContext::new(Arc::clone(&generation), owner.clone(), 17).unwrap();
    assert!(context.accepts(&owner));
    assert!(!context.accepts(&caller("native")));
    let other_core = Arc::new(KernelServices::new());
    let other_generation = Arc::new(ServingGeneration::new(
        other_core,
        Arc::new(HeldRoute::default()),
    ));
    assert!(InvocationContext::new(other_generation, owner.clone(), 17).is_err());
    drop(admission);
    assert!(
        !context.accepts(&owner),
        "retired instance admission cannot be reconstructed from a number"
    );
}

#[test]
fn pending_nested_dispatch_keeps_its_original_generation_until_reply() {
    let core = Arc::new(KernelServices::new());
    core.admit("plane", InstanceFacts::default())
        .now_or_never()
        .unwrap()
        .unwrap();
    let route = Arc::new(HeldRoute::default());
    let generation = Arc::new(ServingGeneration::new(core.clone(), route.clone()));
    let old = Arc::downgrade(&generation);
    let owner = caller("plane");
    core.units()
        .admitted_for(7, &owner, crate::host_units::UnitRecord::default());
    let context = InvocationContext::new(generation.clone(), owner.clone(), 7).unwrap();
    context
        .nest(
            &owner,
            NestAsk {
                verb: "POST".into(),
                target: "/child".into(),
                body: vec![],
            },
            Box::new(|_| {}),
        )
        .unwrap();
    drop(context);
    drop(generation);
    let replacement = Arc::new(ServingGeneration::new(core, Arc::new(HeldRoute::default())));
    assert!(
        old.upgrade().is_some(),
        "pending child pins the dispatched generation"
    );
    route.0.lock().unwrap().take().unwrap()(NestReply::Answered {
        status: 200,
        fields: vec![],
        body: vec![],
    });
    assert!(
        old.upgrade().is_none(),
        "completed child releases its generation"
    );
    assert_eq!(Arc::strong_count(&replacement), 1);
}

#[test]
fn native_generation_metadata_stays_with_its_retained_snapshot() {
    let core = Arc::new(KernelServices::new());
    let first = ServingGeneration::try_new(core.clone(), Arc::new(HeldRoute::default())).unwrap();
    let retained = first.routing_generation();
    let next = ServingGeneration::try_new(core, Arc::new(HeldRoute::default())).unwrap();
    assert_ne!(retained, crate::registry::Generation::FIRST);
    assert!(next.routing_generation() > retained);
    assert_eq!(first.routing_generation(), retained);
}
