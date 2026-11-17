// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::hook::{HookAnswer, HookCall, HookView};
use busbar_ports::CallCx;
use std::sync::Mutex;

struct NoChildren;
impl crate::host_services::NestRoute for NoChildren {
    fn nest(
        &self,
        _: crate::host_services::InvocationContext,
        _: crate::host_services::Nest,
        _: crate::host_services::NestDone,
    ) {
        panic!("this hook test has no child operation")
    }
}
pub(crate) struct Fixture {
    pub(crate) context: crate::host_services::InvocationContext,
    _admission: crate::host_services::NativeInvocationAdmission,
    pub(crate) selected: Selected,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        use crate::host_services::{InvocationContext, KernelServices, ServingGeneration};
        let core = Arc::new(KernelServices::new());
        let caller = busbar_contract::services::Caller::for_test(
            Arc::from("native-test"),
            busbar_contract::abi::mechanism::KindCode::Plane,
        );
        let admission = core.admit_native_invocation(&caller).unwrap();
        core.units()
            .admitted_for(7, &caller, crate::host_units::UnitRecord::default());
        let generation = Arc::new(ServingGeneration::new(core, Arc::new(NoChildren)));
        Self {
            context: InvocationContext::new(generation, caller, 7).unwrap(),
            _admission: admission,
            selected: Selected {
                rewrites: Vec::new(),
                gates: Vec::new(),
                policy: None,
                taps: Taps::default(),
                key: None,
                budget: Vec::new(),
                rate_headroom: None,
                cost: Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
                reads: Arc::new(|_, _, _, _| Box::pin(async { Ok(()) })),
            },
        }
    }
    fn selection(&self) -> Selection<'_> {
        Selection {
            route: 1,
            pool: "pool",
            container: "",
            dialect: "test",
            principal: None,
            key: self.context.principal().map(AsRef::as_ref),
            request_id: 7,
            now_s: 11,
        }
    }
    async fn invoke(
        &self,
        call: &Arc<Call>,
        projection: &Projection,
    ) -> Result<HookAnswer, call::Failed> {
        let selection = self.selection();
        let input = call::Input {
            projection,
            selected: &self.selected,
            selection: &selection,
            identity: b"admitted-identity",
            candidates: &[],
            quantities: &[],
            stage: &[],
            context: &self.context,
        };
        call::one(call, abi::POINT_ROUTE, &input).await
    }
}
#[derive(Default, Debug)]
struct Seen {
    prompt: bool,
    body: bool,
    identity: bool,
    end_user: bool,
    costs: Vec<Vec<(String, f64, Option<f64>)>>,
}
struct Spy {
    facts: u64,
    seen: Mutex<Vec<Seen>>,
}
impl HookPort for Spy {
    fn points(&self) -> u32 {
        (1 << abi::POINT_ROUTE) | (1 << abi::POINT_REWRITE) | (1 << abi::POINT_NOTIFY)
    }
    fn facts(&self) -> u64 {
        self.facts
    }
    fn on<'a>(&'a self, _: CallCx, _: u32, view: &'a HookView<'a>) -> HookCall<'a> {
        self.seen.lock().unwrap().push(Seen {
            prompt: view.conversation.is_some(),
            body: view.body.is_some(),
            identity: view.identity.is_some(),
            end_user: view
                .signals
                .iter()
                .any(|(key, _)| *key == busbar_plugin_abi::fail::fact::PJ_END_USER),
            costs: view
                .candidates
                .iter()
                .map(|candidate| {
                    candidate
                        .cost_terms
                        .iter()
                        .map(|term| {
                            (
                                term.class.to_owned(),
                                term.expected_units,
                                term.price_per_unit,
                            )
                        })
                        .collect()
                })
                .collect(),
        });
        HookCall::Done(Ok(abstain()))
    }
}
fn abstain() -> HookAnswer {
    HookAnswer {
        verb: abi::VERB_ABSTAIN,
        reject_status: None,
        order: Vec::new(),
        restrict: Vec::new(),
        message: None,
        rewrite: None,
    }
}
pub(crate) fn configured(
    port: Arc<dyn HookPort>,
    prompt: PromptAccess,
    user: UserAccess,
) -> Arc<Call> {
    Arc::new(Call {
        name: Arc::from("configured-name"),
        port,
        timeout: Duration::from_secs(1),
        prompt,
        user,
        signals: RequestedSignals::default(),
        on_error: PolicyOnError::Weighted,
        on_empty: PolicyOnError::Reject,
        fallbacks: Vec::new(),
        strategy: None,
    })
}
fn projection() -> Projection {
    Projection {
        facts: vec![(
            busbar_plugin_abi::fail::fact::PJ_END_USER,
            FactVal::Text("private-user".into()),
        )],
        conversation: Some(b"generic-conversation".to_vec().into()),
        expects: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_native_call_intersects_grants_and_demand_without_granting_body() {
    for prompt in [PromptAccess::No, PromptAccess::Ro, PromptAccess::Rw] {
        for user in [UserAccess::No, UserAccess::Ro] {
            for demand in [
                0,
                abi::FB_WANTS_PROMPT,
                abi::FB_WANTS_IDENTITY,
                abi::FB_WANTS_PROMPT | abi::FB_WANTS_IDENTITY | abi::FB_WANTS_BODY,
            ] {
                let fixture = Fixture::new();
                let spy = Arc::new(Spy {
                    facts: demand,
                    seen: Mutex::default(),
                });
                let call = configured(spy.clone(), prompt, user);
                assert!(fixture.invoke(&call, &projection()).await.is_ok());
                let seen = spy.seen.lock().unwrap();
                assert_eq!(seen.len(), 1);
                assert_eq!(
                    seen[0].prompt,
                    prompt.sends_prompt() && demand & abi::FB_WANTS_PROMPT != 0
                );
                assert_eq!(
                    seen[0].identity,
                    user.sends_user() && demand & abi::FB_WANTS_IDENTITY != 0
                );
                assert_eq!(seen[0].end_user, seen[0].identity);
                assert!(!seen[0].body, "BODY has no operator grant");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfirmed_content_read_cannot_escape_through_weighted_fallback() {
    let mut fixture = Fixture::new();
    fixture.selected.reads = Arc::new(|_, _, _, _| Box::pin(std::future::pending()));
    let spy = Arc::new(Spy {
        facts: abi::FB_WANTS_PROMPT,
        seen: Mutex::default(),
    });
    let mut call = configured(spy.clone(), PromptAccess::Ro, UserAccess::No);
    Arc::get_mut(&mut call).unwrap().timeout = Duration::from_millis(20);
    let projection = projection();
    let selection = fixture.selection();
    let input = call::Input {
        projection: &projection,
        selected: &fixture.selected,
        selection: &selection,
        identity: &[],
        candidates: &[],
        quantities: &[],
        stage: &[],
        context: &fixture.context,
    };
    let mut ran = Vec::new();
    let (_, answer) = call::chain(&call, abi::POINT_ROUTE, &input, &mut ran).await;
    assert_eq!(answer.verb, abi::VERB_REJECT);
    assert!(spy.seen.lock().unwrap().is_empty());
    assert_eq!(ran.len(), 1);
    assert!(ran[0].failed);
}

#[test]
fn rewrites_drop_stale_shape_and_overlay_only_actual_plane_facts() {
    use busbar_plugin_abi::fail::fact::*;
    let mut projected = projection();
    projected.facts.extend([
        (PJ_TOTAL_CHARS, FactVal::U(900)),
        (PJ_MESSAGE_COUNT, FactVal::U(7)),
        (PJ_TEXT_COMPLETE, FactVal::U(1)),
        (PJ_MODEL, FactVal::Text("m".into())),
    ]);
    let mut answer = Answer::default();
    answer.facts = vec![(PJ_TOTAL_CHARS, FactVal::U(3))];
    projected.rewritten(b"new".to_vec(), &answer);
    assert_eq!(projected.conversation.as_deref(), Some(&b"new"[..]));
    assert!(projected.facts.contains(&(PJ_TOTAL_CHARS, FactVal::U(3))));
    assert!(!projected
        .facts
        .iter()
        .any(|(key, _)| matches!(*key, PJ_MESSAGE_COUNT | PJ_TEXT_COMPLETE)));
    assert!(projected
        .facts
        .contains(&(PJ_MODEL, FactVal::Text("m".into()))));
    assert!(projected.shape().conversation.is_none());
    assert!(!projected
        .shape()
        .facts
        .iter()
        .any(|(key, _)| *key == PJ_END_USER));
}

#[test]
fn deferred_answers_keep_latest_expect_and_declared_defaults_without_fabricating_zero() {
    let classes = vec![
        UsageClass {
            class: "explicit".into(),
            unit: 1,
            expected_units: Some(99.0),
        },
        UsageClass {
            class: "default".into(),
            unit: 1,
            expected_units: Some(4.0),
        },
        UsageClass {
            class: "missing".into(),
            unit: 1,
            expected_units: None,
        },
    ];
    let mut projection = Projection::default();
    for (amount, scale) in [(100, 0), (125, 2)] {
        let mut answer = Answer::default();
        answer.expects.push(ExpectItem {
            class: "explicit".into(),
            amount,
            scale,
        });
        projection.absorb(&answer);
    }
    assert_eq!(
        quantities(&classes, &projection.expects).unwrap(),
        vec![("explicit".into(), 1.25), ("default".into(), 4.0)]
    );
    assert!(quantities(
        &classes,
        &[ExpectItem {
            class: "undeclared".into(),
            amount: 1,
            scale: 0
        }]
    )
    .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cost_terms_price_exact_lanes_and_keep_unpriced_expectations() {
    let mut fixture = Fixture::new();
    let card=serde_json::from_value(serde_json::json!({"plane/lane-a":{"units":{"units":"0.5"}},"plane/lane-b":{"units":{"units":2}}})).unwrap();
    fixture.selected.cost = Arc::new(CostModel::resolve_parts(
        Some(&card),
        0,
        &Default::default(),
    ));
    let spy = Arc::new(Spy {
        facts: 0,
        seen: Mutex::default(),
    });
    let mut call = configured(spy.clone(), PromptAccess::No, UserAccess::No);
    Arc::get_mut(&mut call)
        .unwrap()
        .signals
        .insert(busbar_contract::signal::Signal::CandidateRouteCost);
    let candidates = ["plane/lane-a", "plane/lane-b", "unknown"]
        .into_iter()
        .enumerate()
        .map(|(idx, lane)| CandidateView {
            facts: CandidateFacts {
                idx,
                model: "same-display-name".into(),
                ..Default::default()
            },
            lane: lane.into(),
        })
        .collect::<Vec<_>>();
    let projection = Projection::default();
    let selection = fixture.selection();
    let quantities = vec![("units".into(), 3.0)];
    let input = call::Input {
        projection: &projection,
        selected: &fixture.selected,
        selection: &selection,
        identity: &[],
        candidates: &candidates,
        quantities: &quantities,
        stage: &[],
        context: &fixture.context,
    };
    assert!(call::one(&call, abi::POINT_ROUTE, &input).await.is_ok());
    let seen = spy.seen.lock().unwrap();
    assert_eq!(
        seen[0].costs,
        vec![
            vec![("units".into(), 3.0, Some(0.5))],
            vec![("units".into(), 3.0, Some(2.0))],
            vec![("units".into(), 3.0, None)]
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_native_calls_do_not_block_each_others_deadlines() {
    struct Slow;
    impl HookPort for Slow {
        fn points(&self) -> u32 {
            1 << abi::POINT_ROUTE
        }
        fn facts(&self) -> u64 {
            0
        }
        fn on<'a>(&'a self, _: CallCx, _: u32, _: &'a HookView<'a>) -> HookCall<'a> {
            std::thread::sleep(Duration::from_millis(150));
            HookCall::Done(Ok(abstain()))
        }
    }
    let fixture = Fixture::new();
    let mut slow = configured(Arc::new(Slow), PromptAccess::No, UserAccess::No);
    Arc::get_mut(&mut slow).unwrap().timeout = Duration::from_millis(15);
    let spy = Arc::new(Spy {
        facts: 0,
        seen: Mutex::default(),
    });
    let fast = configured(spy.clone(), PromptAccess::No, UserAccess::No);
    let projection = Projection::default();
    let (slow_result, fast_result) = tokio::join!(
        fixture.invoke(&slow, &projection),
        fixture.invoke(&fast, &projection)
    );
    assert!(matches!(slow_result, Err(call::Failed::Port)));
    assert!(fast_result.is_ok());
    assert_eq!(spy.seen.lock().unwrap().len(), 1);
}
