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
        Self::with_bound(16)
    }
    fn with_bound(bound: usize) -> Self {
        use crate::host_services::{InvocationContext, KernelServices, ServingGeneration};
        let core = Arc::new(KernelServices::new().with_pool(Arc::new(
            crate::host_services::BlockingPool::new(tokio::runtime::Handle::current(), bound),
        )));
        let caller = busbar_contract::services::Caller::for_test(
            Arc::from("native-test"),
            busbar_contract::kinds::codes::KindCode::Plane,
        );
        let admission = core.admit_native_invocation(&caller).unwrap();
        core.units()
            .admitted_for(7, &caller, crate::host_units::UnitRecord::default());
        let generation = Arc::new(ServingGeneration::new(core, Arc::new(NoChildren)));
        Self {
            context: InvocationContext::new(generation, caller, 7).unwrap(),
            _admission: admission,
            selected: Selected {
                rewrites: Arc::default(),
                gates: Arc::default(),
                policy: None,
                taps: Taps::default(),
                key: None,
                budget: Vec::new(),
                rate_headroom: None,
                cost: Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
                reads: Arc::new(|_, _, _, _| Box::pin(async { Ok(()) })),
                counters: None,
            },
        }
    }
    async fn invoke(
        &self,
        call: &Arc<Call>,
        projection: &Projection,
    ) -> Result<call::Reply, call::Failed> {
        let lent = Lent::of(self, Vec::new(), Vec::new());
        let input = lent.input(projection, self);
        call::one(call, abi::POINT_ROUTE, &input).await
    }
}
/// What a hook input shares, owned by the test: the fixture's selection as it stands, pool
/// `pool`, dialect `test`, no principal, request 7.
struct Lent {
    selected: Arc<Selected>,
    scope: Arc<crate::plane_driver::RoutedScope>,
    dialect: Arc<str>,
    candidates: Candidates,
    quantities: Arc<[(Box<str>, f64)]>,
}
impl Lent {
    fn of(
        fixture: &Fixture,
        candidates: Vec<CandidateView>,
        quantities: Vec<(Box<str>, f64)>,
    ) -> Self {
        Self {
            selected: Arc::new(fixture.selected.clone()),
            scope: Arc::new(crate::plane_driver::RoutedScope {
                pool: "pool".into(),
                container: String::new(),
            }),
            dialect: Arc::from("test"),
            candidates: Candidates::new(candidates),
            quantities: Arc::from(quantities),
        }
    }
    fn input<'a>(&'a self, projection: &'a Projection, fixture: &'a Fixture) -> call::Input<'a> {
        call::Input {
            projection,
            selected: &self.selected,
            scope: &self.scope,
            dialect: &self.dialect,
            principal: None,
            request_id: 7,
            grant: None,
            candidates: &self.candidates,
            quantities: &self.quantities,
            stage: None,
            context: &fixture.context,
        }
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
        conversation: Some(Arc::new(b"generic-conversation".to_vec().into())),
        expects: Vec::new(),
    }
}

/// Hook 3.0, what one call is lent. The conversation: the operator's `prompt` grant AND the
/// image's `FB_WANTS_PROMPT`. The caller (here the end user the plane projected): the
/// operator's `user` grant alone, as v1.5.5 gave it; an image has no bit to ask for it (bit 4,
/// the retired `FB_WANTS_IDENTITY`, changes nothing set or clear), which is what lets
/// `hook-webrequest`, which declares `FB_WANTS_PROMPT` only, forward the caller a `user: ro`
/// grant gives it. The raw body and the verified identity records: never, whatever is granted
/// or declared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_is_lent_the_prompt_by_grant_and_demand_and_the_caller_by_the_operators_grant_alone()
{
    /// The fact bits hook 3.0 retired: 2 (`FB_WANTS_BODY`) and 4 (`FB_WANTS_IDENTITY`).
    const RETIRED: u64 = 2 | 4;
    assert_eq!(abi::FB_RETIRED, RETIRED);
    for prompt in [PromptAccess::No, PromptAccess::Ro, PromptAccess::Rw] {
        for user in [UserAccess::No, UserAccess::Ro] {
            for demand in [
                0,
                abi::FB_WANTS_PROMPT,
                RETIRED,
                abi::FB_WANTS_PROMPT | RETIRED,
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
                    seen[0].end_user,
                    user.sends_user(),
                    "the operator's `user` grant, and only it, lends the caller (demand {demand:#x})"
                );
                assert!(
                    !seen[0].identity,
                    "the verified identity records are not part of a hook 3.0 view"
                );
                assert!(!seen[0].body, "BODY has no operator grant");
            }
        }
    }
}

/// A hook is heard in two places and nowhere else: once the request's walk is resolved and
/// before its money is asked, and while its unit runs. RED before hooks ran on the native path:
/// a request whose money was not yet admitted could call no hook at all, so a hook could only be
/// heard after the unit was opened and the money held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_is_heard_once_the_walk_is_resolved_and_never_before() {
    use crate::host_services::{InvocationContext, KernelServices, ServingGeneration};
    use crate::plane_driver::request_admission::{RequestAllocation, RequestRoutes};
    let core = Arc::new(KernelServices::new().with_pool(Arc::new(
        crate::host_services::BlockingPool::new(tokio::runtime::Handle::current(), 16),
    )));
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from("seat"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    let _admission = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        41,
        &caller,
        crate::host_units::UnitRecord {
            principal: Some(Arc::new(busbar_contract::records::VirtualKey {
                id: "payer".into(),
                enabled: true,
                ..Default::default()
            })),
            depth: 0,
        }
    ));
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
        caller,
        41,
    )
    .unwrap();
    let mut fixture = Fixture::new();
    fixture.context = context.clone();
    let spy = Arc::new(Spy {
        facts: 0,
        seen: Mutex::default(),
    });
    let call = configured(spy.clone(), PromptAccess::No, UserAccess::No);
    let projection = Projection::default();

    // Registered, nothing resolved: the key's grant of the walk is not judged yet.
    assert!(!context.hooks_allowed());
    assert!(context.hook_grant().is_none());
    assert!(matches!(
        fixture.invoke(&call, &projection).await,
        Err(call::Failed::Port)
    ));
    let allocation = RequestAllocation::new(
        context.clone(),
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        100,
    )
    .unwrap();
    assert!(matches!(
        fixture.invoke(&call, &projection).await,
        Err(call::Failed::Port)
    ));
    assert!(
        spy.seen.lock().unwrap().is_empty(),
        "no hook is shown a request whose walk is not resolved"
    );

    // The walk is resolved and the money not asked: the hook is heard, and no effect is allowed.
    let receipt = allocation
        .local(&RequestRoutes::new("seat", None, None, None).unwrap())
        .unwrap();
    assert!(context.hooks_allowed());
    assert!(!context.effects_allowed());
    assert!(fixture.invoke(&call, &projection).await.is_ok());
    assert_eq!(spy.seen.lock().unwrap().len(), 1);

    // A notification fired now is handed over after the request has ended; nothing else is.
    let grant = context
        .hook_grant()
        .expect("a resolved request allows hooks");
    drop(receipt);
    assert!(!context.hooks_allowed(), "the admission ended unpaid");
    assert!(matches!(
        fixture.invoke(&call, &projection).await,
        Err(call::Failed::Port)
    ));
    let other = Fixture::new();
    let foreign = other.context.hook_grant().expect("an admitted unit");
    let lent = Lent::of(&fixture, Vec::new(), Vec::new());
    let mut input = lent.input(&projection, &fixture);
    input.grant = Some(&grant);
    assert!(call::one(&call, abi::POINT_NOTIFY, &input).await.is_ok());
    assert_eq!(spy.seen.lock().unwrap().len(), 2);

    // Another request's grant hands nothing over for this one.
    input.grant = Some(&foreign);
    assert!(matches!(
        call::one(&call, abi::POINT_NOTIFY, &input).await,
        Err(call::Failed::Port)
    ));
    assert_eq!(spy.seen.lock().unwrap().len(), 2);
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
    let lent = Lent::of(&fixture, Vec::new(), Vec::new());
    let input = lent.input(&projection, &fixture);
    let mut ran = Vec::new();
    let answer = call::chain(&call, abi::POINT_ROUTE, &input, &mut ran).await;
    assert!(matches!(answer, Err(call::Failed::Unconfirmed)));
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
    projected.rewritten(b"new".to_vec().into(), &answer);
    assert_eq!(
        projected.conversation.as_deref().map(|bytes| &**bytes),
        Some(&b"new"[..])
    );
    assert!(projected.facts.contains(&(PJ_TOTAL_CHARS, FactVal::U(3))));
    assert!(!projected
        .facts
        .iter()
        .any(|(key, _)| matches!(*key, PJ_MESSAGE_COUNT | PJ_TEXT_COMPLETE)));
    assert!(projected
        .facts
        .contains(&(PJ_MODEL, FactVal::Text("m".into()))));
    projected.shape();
    assert!(projected.conversation.is_none());
    assert!(!projected.facts.iter().any(|(key, _)| *key == PJ_END_USER));
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
    let mut out = Vec::new();
    quantities(&classes, &projection.expects, &mut out).unwrap();
    assert_eq!(
        out,
        vec![("explicit".into(), 1.25), ("default".into(), 4.0)]
    );
    assert!(quantities(
        &classes,
        &[ExpectItem {
            class: "undeclared".into(),
            amount: 1,
            scale: 0
        }],
        &mut out,
    )
    .is_err());
}

/// The stage narrows its candidate list in place while it is the list's only holder, copies the
/// kept members only when a hook call or a tap still holds the list and a member is really
/// removed, and leaves the holder's list as it was.
#[test]
fn candidates_narrow_in_place_and_copy_only_for_a_live_holder() {
    let view = |idx| CandidateView {
        facts: CandidateFacts {
            idx,
            ..Default::default()
        },
        lane: format!("lane-{idx}"),
    };
    let idxs = |list: &Candidates| list.iter().map(|c| c.facts.idx).collect::<Vec<_>>();
    let mut list = Candidates::new((0..4).map(view).collect());
    let first = Arc::as_ptr(&list.all);
    list.keep_only(&[0, 1, 2, 3]);
    assert_eq!(Arc::as_ptr(&list.all), first);
    assert_eq!(idxs(&list), [0, 1, 2, 3]);
    // The only holder: narrowed in place, in the list's order.
    list.keep_only(&[3, 1]);
    assert_eq!(Arc::as_ptr(&list.all), first);
    assert_eq!(idxs(&list), [1, 3]);
    let held = list.clone();
    // Held, but nothing removed: no copy.
    list.keep_only(&[1, 3]);
    assert_eq!(Arc::as_ptr(&list.all), first);
    // Held, and a member removed: the stage copies what it keeps; the holder's list is untouched.
    list.keep_only(&[3]);
    assert_ne!(Arc::as_ptr(&list.all), first);
    assert_eq!(idxs(&list), [3]);
    assert_eq!(idxs(&held), [1, 3]);
    assert_eq!(Arc::strong_count(&held.all), 1);
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
    let quantities = vec![("units".into(), 3.0)];
    let lent = Lent::of(&fixture, candidates, quantities);
    let input = lent.input(&projection, &fixture);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fallbacks_reapply_their_own_grants_and_report_their_configured_names() {
    struct Unavailable;
    impl HookPort for Unavailable {
        fn points(&self) -> u32 {
            1 << abi::POINT_ROUTE
        }
        fn facts(&self) -> u64 {
            abi::FB_WANTS_PROMPT
        }
        fn on<'a>(&'a self, _: CallCx, _: u32, view: &'a HookView<'a>) -> HookCall<'a> {
            assert!(view.conversation.is_none());
            assert!(view.identity.is_none());
            assert!(
                !view
                    .signals
                    .iter()
                    .any(|(key, _)| *key == busbar_plugin_abi::fail::fact::PJ_END_USER),
                "a call granted no `user` is shown no caller, whatever its fallback is granted"
            );
            HookCall::Done(Err(busbar_ports::PortError::Refused {
                code: busbar_plugin_abi::fail::refused::R_UNSUPPORTED,
                text: "unavailable".into(),
                error: None,
            }))
        }
    }
    let mut fixture = Fixture::new();
    let reads = Arc::new(Mutex::new(Vec::new()));
    fixture.selected.reads = {
        let reads = reads.clone();
        Arc::new(move |names, _, _, identity| {
            reads
                .lock()
                .unwrap()
                .extend(names.iter().map(|name| (name.to_string(), identity)));
            Box::pin(async { Ok(()) })
        })
    };
    let spy = Arc::new(Spy {
        facts: abi::FB_WANTS_PROMPT,
        seen: Mutex::default(),
    });
    let mut fallback = configured(spy.clone(), PromptAccess::Ro, UserAccess::Ro);
    Arc::get_mut(&mut fallback).unwrap().name = Arc::from("fallback-configured-name");
    let mut primary = configured(Arc::new(Unavailable), PromptAccess::No, UserAccess::No);
    Arc::get_mut(&mut primary).unwrap().fallbacks.push(fallback);
    let projection = projection();
    let lent = Lent::of(&fixture, Vec::new(), Vec::new());
    let input = lent.input(&projection, &fixture);
    let mut ran = Vec::new();
    let result = call::chain(&primary, abi::POINT_ROUTE, &input, &mut ran).await;
    let Ok((called, answer)) = result else {
        panic!("the bounded fallback should answer")
    };
    assert_eq!(&*called.name, "fallback-configured-name");
    assert_eq!(answer.verb, abi::VERB_ABSTAIN);
    assert_eq!(
        *reads.lock().unwrap(),
        vec![("fallback-configured-name".into(), true)]
    );
    assert_eq!(
        ran.iter()
            .map(|record| (record.hook.as_str(), record.failed))
            .collect::<Vec<_>>(),
        vec![
            ("configured-name", true),
            ("fallback-configured-name", false)
        ]
    );
    let seen = spy.seen.lock().unwrap();
    assert!(seen[0].prompt && seen[0].end_user);
    assert!(!seen[0].identity && !seen[0].body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_retained_generation_pool_refuses_the_hook_without_starting_it() {
    let fixture = Fixture::with_bound(1);
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    fixture
        .context
        .offload_hook(Box::new(move || {
            let _ = entered.send(());
            let _ = blocked.recv();
        }))
        .unwrap();
    started.await.unwrap();
    let spy = Arc::new(Spy {
        facts: 0,
        seen: Mutex::default(),
    });
    let call = configured(spy.clone(), PromptAccess::No, UserAccess::No);
    let result = fixture.invoke(&call, &Projection::default()).await;
    let _ = release.send(());
    assert!(
        matches!(result, Err(call::Failed::Port)),
        "a hook cannot bypass its generation's full offload pool"
    );
    assert!(spy.seen.lock().unwrap().is_empty());
}

/// Records every candidate record a native hook call is shown (DES-NATIVE-HOOKS-PARITY r3 §E).
struct RecSpy(Mutex<Vec<abi::CandidateRec>>);
impl HookPort for RecSpy {
    fn points(&self) -> u32 {
        1 << abi::POINT_ROUTE
    }
    fn facts(&self) -> u64 {
        0
    }
    fn on<'a>(&'a self, _: CallCx, _: u32, view: &'a HookView<'a>) -> HookCall<'a> {
        self.0
            .lock()
            .unwrap()
            .extend(view.candidates.iter().map(|candidate| candidate.rec));
        HookCall::Done(Ok(abstain()))
    }
}

/// The candidate records one route call shows a hook that requested `signals`, over one member
/// with a sample of every opt-in signal: error rate 25%, breaker open, p95 120 ms.
async fn recs_shown(signals: &[busbar_contract::signal::Signal]) -> Vec<abi::CandidateRec> {
    let fixture = Fixture::new();
    let spy = Arc::new(RecSpy(Mutex::default()));
    let mut call = configured(spy.clone(), PromptAccess::No, UserAccess::No);
    for &signal in signals {
        Arc::get_mut(&mut call).unwrap().signals.insert(signal);
    }
    let candidates = [CandidateView {
        facts: CandidateFacts {
            idx: 0,
            model: "m".into(),
            error_rate: Some(0.25),
            breaker_state: Some("open"),
            latency_p95_ms: Some(120),
            ..Default::default()
        },
        lane: "plane/lane-a".into(),
    }];
    let projection = Projection::default();
    let lent = Lent::of(&fixture, candidates.into(), Vec::new());
    let input = lent.input(&projection, &fixture);
    assert!(call::one(&call, abi::POINT_ROUTE, &input).await.is_ok());
    let recs = spy.0.lock().unwrap().clone();
    recs
}

/// RED before §E (#459): a hook that did not request `candidate_error_rate` was shown it anyway
/// (the error_rate leak); nor is it shown the breaker or the p95.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_requesting_hook_sees_no_error_rate_breaker_or_p95() {
    let recs = recs_shown(&[]).await;
    assert_eq!(recs.len(), 1);
    let rec = recs[0];
    assert_eq!(
        rec.flags & RETIRED_C_HAS_ERROR_RATE,
        0,
        "the error rate is shown to no hook"
    );
    assert_eq!(rec.error_rate_ppm, 0);
    assert_eq!(rec.breaker, 0);
}

/// Presence bit 32 of `CandidateRec.flags`, `C_HAS_ERROR_RATE` until hook 3.0 retired it.
const RETIRED_C_HAS_ERROR_RATE: u32 = 32;

/// Hook 3.0 retired the error rate (no shipped hook read it; v1.5.5 never sent it). A hook
/// whose configuration still asks for `candidate_error_rate` is shown what every other hook is:
/// the bit clear and the field 0, and no other presence bit moved by the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_that_asks_for_the_retired_error_rate_is_shown_none() {
    let plain = recs_shown(&[]).await;
    let asked = recs_shown(&[busbar_contract::signal::Signal::CandidateErrorRate]).await;
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].flags & RETIRED_C_HAS_ERROR_RATE, 0);
    assert_eq!(asked[0].error_rate_ppm, 0);
    assert_eq!(asked[0].flags, plain[0].flags);
}
