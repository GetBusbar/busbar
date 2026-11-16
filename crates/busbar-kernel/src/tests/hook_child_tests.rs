// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::{
    InvocationContext, KernelServices, NestDone, NestRoute, ServingGeneration,
};
use crate::host_units::UnitRecord;
use busbar_contract::abi::mechanism::call::Outcome;
use std::ops::Deref;

#[derive(Default)]
struct Route {
    calls: Mutex<Vec<Nest>>,
    pending: Mutex<Vec<NestDone>>,
    hold: bool,
}
impl NestRoute for Route {
    fn nest(&self, _context: InvocationContext, nest: Nest, done: NestDone) {
        self.calls.lock().unwrap().push(nest);
        if self.hold {
            self.pending.lock().unwrap().push(done);
        } else {
            done(NestReply::Answered {
                status: 200,
                fields: vec![(b"private".to_vec(), b"hidden".to_vec())],
                body: b"answer".to_vec(),
            });
        }
    }
}
fn grant() -> Arc<Grant> {
    Arc::new(Grant {
        revision: 1,
        plane: "neutral-plane".into(),
        operation: "POST".into(),
        target: "/operation".into(),
        target_binding: "bounded-lane".into(),
        max_input_bytes: 32,
        max_output_bytes: 32,
        max_children: 1,
        timeout_ms: 1000,
        max_budget_micros: 100,
    })
}
#[derive(Clone)]
struct TestHost {
    services: Arc<KernelServices>,
    context: InvocationContext,
}
impl Deref for TestHost {
    type Target = KernelServices;
    fn deref(&self) -> &Self::Target {
        &self.services
    }
}

fn setup(route: Arc<Route>) -> (TestHost, Caller) {
    let services = Arc::new(KernelServices::new());
    let parent = Caller::for_test(Arc::from("parent"), KindCode::Plane);
    futures::FutureExt::now_or_never(services.admit("parent", Default::default()))
        .expect("fixture admission completes")
        .unwrap();
    services.units().admitted_for(
        7,
        &parent,
        UnitRecord {
            principal: Some(Arc::new(busbar_contract::records::VirtualKey {
                id: "principal".into(),
                ..Default::default()
            })),
            depth: 0,
        },
    );
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::new(services.clone(), route)),
        parent,
        7,
    )
    .unwrap();
    (
        TestHost { services, context },
        Caller::for_test(Arc::from("gate"), KindCode::Hook),
    )
}
fn request(child: &dyn HookChildInvocation, caller: &Caller, body: &[u8]) -> Option<Stored> {
    let result = Arc::new(Mutex::new(None));
    let reply = result.clone();
    match child.request(
        caller,
        body.to_vec(),
        Box::new(move |answer| *reply.lock().unwrap() = Some(answer)),
    ) {
        Ran::Now(answer) => Some(answer),
        Ran::Later => result.lock().unwrap().take(),
    }
}

#[tokio::test]
async fn child_inherits_principal_and_memoizes_across_invocation_retries() {
    let route = Arc::new(Route::default());
    let (services, caller) = setup(route.clone());
    SCOPE
        .scope(Scope::new(services.context.clone()), async {
            let g = grant();
            let child = invocation("gate", Some(&g), Duration::from_secs(1)).unwrap();
            let answer = request(&*child, &caller, b"payload").unwrap();
            assert_eq!(answer.bytes, b"answer");
            assert!(
                answer.spans.is_empty(),
                "no headers or credentials returned"
            );
            assert_eq!(
                request(&*child, &caller, b"payload").unwrap().bytes,
                b"answer"
            );
            drop(child);
            let mut changed = (*g).clone();
            changed.revision = 2;
            changed.target = "/different".into();
            let again =
                invocation("gate", Some(&Arc::new(changed)), Duration::from_secs(1)).unwrap();
            assert_eq!(
                request(&*again, &caller, b"payload").unwrap().bytes,
                b"answer"
            );
            assert_eq!(
                request(&*again, &caller, b"changed").unwrap().outcome,
                Outcome::Refused
            );
            let calls = route.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            let call = &calls[0];
            assert_eq!(call.parent, 7);
            assert_eq!(call.principal.as_ref().unwrap().id, "principal");
            assert_eq!(call.depth, 1);
            assert_eq!(call.ancestry.as_slice(), &[Arc::<str>::from("gate")]);
            assert_eq!(call.constraints.as_ref().unwrap().grant.revision, 1);
        })
        .await;
}

#[tokio::test]
async fn a_stage_reads_its_units_child_ancestry_once() {
    let route = Arc::new(Route::default());
    let (services, caller) = setup(route.clone());
    let probe = busbar_contract::stage_probe::Scope::open();
    SCOPE
        .scope(Scope::new(services.context.clone()), async {
            assert!(!recursive("gate"));
            let child = invocation("gate", Some(&grant()), Duration::from_secs(1)).unwrap();
            assert_eq!(
                request(&*child, &caller, b"payload").unwrap().bytes,
                b"answer"
            );
        })
        .await;
    assert_eq!(
        probe.count(busbar_contract::stage_probe::Derive::AncestryCheck),
        1,
        "the recursion check, the invocation and the child request share one ancestry read"
    );
    let calls = route.calls.lock().unwrap();
    assert_eq!(calls[0].ancestry.as_slice(), &[Arc::<str>::from("gate")]);
}

#[tokio::test]
async fn grant_refuses_wrong_caller_kind_payload_scope_and_changed_parent() {
    let route = Arc::new(Route::default());
    let (services, caller) = setup(route.clone());
    SCOPE
        .scope(Scope::new(services.context.clone()), async {
            let g = grant();
            let child = invocation("gate", Some(&g), Duration::from_secs(1)).unwrap();
            for stranger in [
                Caller::for_test(Arc::from("other"), KindCode::Hook),
                Caller::for_test(Arc::from("gate"), KindCode::Plane),
            ] {
                assert_eq!(
                    request(&*child, &stranger, b"p").unwrap().outcome,
                    Outcome::Refused
                );
            }
            assert_eq!(
                request(&*child, &caller, &[1; 33]).unwrap().outcome,
                Outcome::Refused
            );
            services.units().admitted(
                7,
                UnitRecord {
                    depth: crate::host_services::NEST_DEPTH_MAX,
                    ..Default::default()
                },
            );
            assert_eq!(
                request(&*child, &caller, b"p").unwrap().outcome,
                Outcome::Refused
            );
            assert!(route.calls.lock().unwrap().is_empty());
        })
        .await;
    assert!(invocation("gate", Some(&grant()), Duration::from_secs(1)).is_none());
}

#[tokio::test]
async fn recursive_hook_is_not_invoked_and_no_capability_survives_parent() {
    let route = Arc::new(Route::default());
    let (services, caller) = setup(route);
    services
        .units()
        .set_child_ancestry(7, vec![Arc::from("gate")]);
    SCOPE
        .scope(Scope::new(services.context.clone()), async {
            assert!(recursive("gate"));
            assert!(invocation("gate", Some(&grant()), Duration::from_secs(1)).is_none());
        })
        .await;
    // A unit's ancestry is fixed when it is nested; a stage entry reads it once.
    services.units().set_child_ancestry(7, Vec::new());
    SCOPE
        .scope(Scope::new(services.context.clone()), async {
            let child = invocation("gate", Some(&grant()), Duration::from_secs(1)).unwrap();
            services.units().ended(7);
            assert_eq!(
                request(&*child, &caller, b"p").unwrap().outcome,
                Outcome::Refused
            );
        })
        .await;
}

#[tokio::test]
async fn dropping_invocation_cancels_one_pending_child_without_reissuing_it() {
    let route = Arc::new(Route {
        hold: true,
        ..Default::default()
    });
    let (services, caller) = setup(route.clone());
    SCOPE
        .scope(Scope::new(services.context.clone()), async {
            let g = grant();
            let child = invocation("gate", Some(&g), Duration::from_secs(1)).unwrap();
            assert!(request(&*child, &caller, b"p").is_none());
            assert!(request(&*child, &caller, b"p").is_none());
            drop(child);
            assert!(route.calls.lock().unwrap()[0]
                .constraints
                .as_ref()
                .unwrap()
                .cancellation
                .is_cancelled());
            let again = invocation("gate", Some(&g), Duration::from_secs(1)).unwrap();
            assert_eq!(
                request(&*again, &caller, b"p").unwrap().outcome,
                Outcome::Refused
            );
            assert_eq!(route.calls.lock().unwrap().len(), 1);
            // The normal child route retains its settlement obligation until it reports completion.
            route.pending.lock().unwrap().pop().unwrap()(NestReply::Answered {
                status: 200,
                fields: Vec::new(),
                body: Vec::new(),
            });
        })
        .await;
}

#[tokio::test]
async fn depth_deadline_and_output_bounds_fail_closed() {
    for case in 0..3 {
        let route = Arc::new(Route::default());
        let (services, caller) = setup(route.clone());
        if case == 0 {
            services.units().admitted(
                7,
                UnitRecord {
                    depth: crate::host_services::NEST_DEPTH_MAX,
                    ..Default::default()
                },
            );
        }
        SCOPE
            .scope(Scope::new(services.context.clone()), async {
                let mut g = (*grant()).clone();
                if case == 2 {
                    g.max_output_bytes = 2;
                }
                let budget = if case == 1 {
                    Duration::ZERO
                } else {
                    Duration::from_secs(1)
                };
                let child = invocation("gate", Some(&Arc::new(g)), budget).unwrap();
                assert_eq!(
                    request(&*child, &caller, b"p").unwrap().outcome,
                    Outcome::Refused
                );
                assert_eq!(route.calls.lock().unwrap().len(), usize::from(case == 2));
            })
            .await;
    }
}

#[test]
fn grant_bounds_are_mandatory() {
    let mut g = (*grant()).clone();
    assert!(g.validate().is_ok());
    g.max_children = 2;
    assert!(g.validate().is_err());
    g.max_children = 1;
    g.max_budget_micros = 0;
    assert!(g.validate().is_err());
}
