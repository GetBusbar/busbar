// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use futures::FutureExt;

#[derive(Default)]
struct HeldRoute(Mutex<Option<NestDone>>);
impl NestRoute for HeldRoute {
    fn nest(&self, _: Nest, done: NestDone) {
        *self.0.lock().unwrap() = Some(done);
    }
}

fn caller(name: &str) -> Caller {
    Caller::for_test(Arc::from(name), busbar_contract::abi::mechanism::KindCode::Plane)
}

#[test]
fn invocation_refuses_missing_unit_and_another_instance() {
    let core = Arc::new(KernelServices::new());
    core.admit("plane", InstanceFacts::default()).now_or_never().unwrap().unwrap();
    let generation = Arc::new(ServingGeneration::new(core.clone(), Arc::new(HeldRoute::default())));
    let owner = caller("plane");
    assert!(InvocationContext::new(generation.clone(), owner.clone(), 7).is_err());
    core.units().admitted(7, crate::host_units::UnitRecord::default());
    let context = InvocationContext::new(generation, owner.clone(), 7).unwrap();
    assert!(context.accepts(&owner));
    assert!(!context.accepts(&caller("elsewhere")));
    core.units().admitted(7, crate::host_units::UnitRecord::default());
    assert!(!context.accepts(&owner), "reusing a numeric unit cannot restore authority");
}

#[test]
fn pending_nested_dispatch_keeps_its_original_generation_until_reply() {
    let core = Arc::new(KernelServices::new());
    core.admit("plane", InstanceFacts::default()).now_or_never().unwrap().unwrap();
    core.units().admitted(7, crate::host_units::UnitRecord::default());
    let route = Arc::new(HeldRoute::default());
    let generation = Arc::new(ServingGeneration::new(core.clone(), route.clone()));
    let old = Arc::downgrade(&generation);
    let owner = caller("plane");
    let context = InvocationContext::new(generation.clone(), owner.clone(), 7).unwrap();
    context.nest(&owner, NestAsk { verb: "POST".into(), target: "/child".into(), body: vec![] }, Box::new(|_| {})).unwrap();
    drop(context);
    drop(generation);
    let replacement = Arc::new(ServingGeneration::new(core, Arc::new(HeldRoute::default())));
    assert!(old.upgrade().is_some(), "pending child pins the dispatched generation");
    route.0.lock().unwrap().take().unwrap()(NestReply::Answered { status: 200, fields: vec![], body: vec![] });
    assert!(old.upgrade().is_none(), "completed child releases its generation");
    assert_eq!(Arc::strong_count(&replacement), 1);
}
