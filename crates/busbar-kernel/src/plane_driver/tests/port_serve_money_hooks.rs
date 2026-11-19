// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hooks on the native request path (gap G7 of the inbound admission design, v1.5.5 row E24).
//! A native request is a pending admission: its walk is resolved, then its money is asked. The
//! route's hooks are heard between the two, so a hook that refuses has spoken before any unit
//! is opened and before anything is charged; a hook that allows lets the money be asked once.
//!
//! Each test drives one whole session (`port_serve::run_session`) over a real pending
//! admission whose monetary callback writes "money" into the test's order and then refuses
//! (402): "the money was asked", and when, is what the order shows. The plane is scripted.

use super::*;
use crate::config::{PolicyOnError, PromptAccess, UserAccess};
use crate::host_services::{
    BlockingPool, InvocationContext, KernelServices, NativeInvocationAdmission, Nest, NestDone,
    NestRoute, ServingGeneration,
};
use crate::plane_driver::native_hook_bindings::Bindings;
use crate::plane_driver::port_admission::Pending;
use crate::plane_driver::port_hooks::tests::configured;
use crate::plane_driver::port_hooks::{Call, HookRecords, Invocation, Selected, Taps};
use crate::plane_driver::port_serve::Ran;
use crate::plane_driver::request_admission::{RequestAllocation, RequestRoutes};
use crate::refusal::ClientRefusal;
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::hook::{HookAnswer, HookCall, HookPort, HookView};
use busbar_ports::{CallCx, FactVal};
use std::time::Duration;

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("a hook test nests no child")
    }
}

/// What happened, in order: each hook call by its hook's name, and each ask of the money.
type Order = Arc<Mutex<Vec<String>>>;

/// The facts one notification was shown.
type Shown = tokio::sync::mpsc::UnboundedSender<Vec<(u32, FactVal)>>;

/// One request as its session finds it on the native path: registered under its verified key,
/// its walk not resolved, its money not asked.
struct Request {
    pending: Pending,
    _admission: NativeInvocationAdmission,
}

fn out_of_budget() -> ClientRefusal {
    ClientRefusal {
        status: 402,
        code: busbar_plugin_abi::fail::refused::R_BUDGET,
        text: "budget exhausted".into(),
    }
}

fn request(order: &Order) -> Request {
    let core = Arc::new(KernelServices::new().with_pool(Arc::new(BlockingPool::new(
        tokio::runtime::Handle::current(),
        16,
    ))));
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from("seat"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    let admission = core.admit_native_invocation(&caller).unwrap();
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
    let allocation = RequestAllocation::new(
        context,
        Arc::new(crate::cost::CostModel::resolve_parts(
            None,
            0,
            &Default::default(),
        )),
        100,
    )
    .unwrap();
    let asked = Arc::clone(order);
    let pending = Pending::new(
        allocation,
        Arc::new(RequestRoutes::new("seat", None, None, None).unwrap()),
        None,
        move |_receipt| {
            asked.lock().unwrap().push("money".into());
            Err(out_of_budget())
        },
    );
    Request {
        pending,
        _admission: admission,
    }
}

/// The session's effects on the native path: the pending admission, its invocation, and the
/// route's hooks when it has any.
struct Admitting<'a> {
    pending: &'a Pending,
    hooks: Option<Invocation>,
}
impl Effects for Admitting<'_> {
    fn admission(&self) -> Option<&Pending> {
        Some(self.pending)
    }
    fn invocation(&self) -> Option<&InvocationContext> {
        Some(self.pending.context())
    }
    fn hooks(&self) -> Option<&Invocation> {
        self.hooks.as_ref()
    }
    fn emit(&self, _: u64, _: &[u8]) {
        panic!("a request that was never paid for emits nothing")
    }
}

/// A hook that writes its name into the order on each decision it is asked for, then answers
/// `answer` (`Err`: it is down) after `delay`. A notification is not a decision: it is not
/// written into the order, and the facts it was shown are sent to `shown`.
struct Hook {
    name: &'static str,
    order: Order,
    answer: Result<HookAnswer, ()>,
    delay: Duration,
    shown: Option<Shown>,
}
impl Hook {
    fn answering(name: &'static str, order: &Order, answer: Result<HookAnswer, ()>) -> Self {
        Self {
            name,
            order: Arc::clone(order),
            answer,
            delay: Duration::ZERO,
            shown: None,
        }
    }
}
impl HookPort for Hook {
    fn points(&self) -> u32 {
        (1 << abi::POINT_ROUTE) | (1 << abi::POINT_REWRITE) | (1 << abi::POINT_NOTIFY)
    }
    fn facts(&self) -> u64 {
        0
    }
    fn on<'a>(&'a self, _: CallCx, point: u32, view: &'a HookView<'a>) -> HookCall<'a> {
        if point == abi::POINT_NOTIFY {
            if let Some(shown) = &self.shown {
                let facts = view
                    .signals
                    .iter()
                    .map(|(key, value)| {
                        (
                            *key,
                            match value {
                                FactRef::U(value) => FactVal::U(*value),
                                FactRef::Text(value) => FactVal::Text((*value).into()),
                            },
                        )
                    })
                    .collect();
                let _ = shown.send(facts);
            }
            return HookCall::Done(Ok(verdict(abi::VERB_ABSTAIN, None)));
        }
        self.order.lock().unwrap().push(self.name.into());
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        HookCall::Done(match &self.answer {
            Ok(answer) => Ok(answer.clone()),
            Err(()) => Err(PortError::Refused {
                code: busbar_plugin_abi::fail::refused::R_UNSUPPORTED,
                text: "the hook is down".into(),
                error: None,
            }),
        })
    }
}

fn verdict(verb: u32, reject_status: Option<u16>) -> HookAnswer {
    HookAnswer {
        verb,
        reject_status,
        order: Vec::new(),
        restrict: Vec::new(),
        message: None,
        rewrite: None,
    }
}

/// The route's selection: its rewrites, its gates and its response taps, and nothing else.
fn selecting(
    rewrites: Vec<Arc<Call>>,
    gates: Vec<Arc<Call>>,
    response: Vec<Arc<Call>>,
) -> Selected {
    Selected {
        rewrites: rewrites.into(),
        gates: gates.into(),
        policy: None,
        taps: Taps {
            response: response.into(),
            ..Taps::default()
        },
        key: None,
        budget: Vec::new(),
        rate_headroom: None,
        cost: Arc::new(crate::cost::CostModel::resolve_parts(
            None,
            0,
            &Default::default(),
        )),
        reads: Arc::new(|_, _, _, _| Box::pin(async { Ok(()) })),
        counters: None,
    }
}

/// A plane that answers its request itself (no FORWARD): the request's walk is the local one.
fn answering_locally() -> Plane {
    Plane {
        request: vec![It::Respond(200), It::End],
        ..Plane::default()
    }
}

/// One session of `plane` for `request`, on this task as a request's own session runs. `binder`:
/// the seat's frozen hook policy; `None` is a seat with no hook at all.
async fn serve(
    plane: &Plane,
    request: &Request,
    binder: Option<Arc<Bindings>>,
) -> Result<Ran, SessionError> {
    serve_keeping(plane, request, binder, None).await
}

/// [`serve`], with the custody a refusal's hook records are handed to (`records`), as the
/// native path gives its session one for each request.
async fn serve_keeping(
    plane: &Plane,
    request: &Request,
    binder: Option<Arc<Bindings>>,
    records: Option<Arc<HookRecords>>,
) -> Result<Ran, SessionError> {
    let effects = Admitting {
        pending: &request.pending,
        hooks: binder.map(|binder| Invocation {
            binder,
            principal: None,
            now_s: 1,
            classes: Arc::default(),
            journal: None,
            unit: UnitKey::new(41),
            records,
        }),
    };
    let store = Store;
    let resolver = Resolver::new(&store, None);
    let refusals = CoreRefusals::new();
    let drive: Drive<'_> = Drive {
        resolver: &resolver,
        members: None,
        send: None,
        dialect: "test",
        refusals: &refusals,
        effects: &effects,
        books: &request.pending,
        carrier: None,
    };
    crate::plane_driver::port_serve::run_session(plane, &req(), b"{}", drive).await
}

/// [`serve`] on a route whose hooks are `selected`.
async fn serve_hooked(
    plane: &Plane,
    request: &Request,
    selected: &Selected,
) -> Result<Ran, SessionError> {
    serve(plane, request, Some(bindings(selected, gov_state().await))).await
}

fn ordered(order: &Order) -> Vec<String> {
    order.lock().unwrap().clone()
}

fn gate(hook: Hook) -> Arc<Call> {
    configured(Arc::new(hook), PromptAccess::No, UserAccess::No)
}

/// RED before hooks ran on the native path: the money was asked first (the unit opened and
/// held) and the hook was heard afterwards, if at all.
///
/// A refusing hook refuses at its own status, in core's words, and NOTHING is charged: the
/// monetary callback never runs, no unit is admitted, and no effect is allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusing_hook_refuses_at_its_own_status_and_nothing_is_charged() {
    let order = Order::default();
    let request = request(&order);
    let refusing = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_REJECT, Some(409))),
    ));
    let result = serve_hooked(
        &answering_locally(),
        &request,
        &selecting(Vec::new(), vec![refusing], Vec::new()),
    )
    .await;
    match result {
        Err(SessionError::HookRefused(refusal)) => {
            assert_eq!(refusal.status, 409, "the hook's own status");
            assert_eq!(refusal.text, "the request was refused by policy");
        }
        other => panic!("a refusing hook is the caller's refusal: {other:?}"),
    }
    assert_eq!(
        ordered(&order),
        ["gate"],
        "the hook spoke and the money was never asked"
    );
    assert!(request.pending.admitted().is_none(), "no unit was opened");
    assert!(!request.pending.context().effects_allowed());
}

/// RED before: see above. A hook that allows is heard BEFORE the money, and the money is then
/// asked exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_that_allows_is_heard_before_the_money_and_the_money_is_asked_once() {
    let order = Order::default();
    let request = request(&order);
    let allowing = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_ABSTAIN, None)),
    ));
    let result = serve_hooked(
        &answering_locally(),
        &request,
        &selecting(Vec::new(), vec![allowing], Vec::new()),
    )
    .await;
    match result {
        Err(SessionError::AdmissionRefused(refusal)) => assert_eq!(refusal.status, 402),
        other => panic!("the money's own answer is the request's: {other:?}"),
    }
    assert_eq!(ordered(&order), ["gate", "money"]);
}

/// RED before: see above. A hook the operator granted `prompt: rw` modifies the request: its
/// REWRITE is handed to the plane before the money is asked. One granted `ro` may look and
/// may not change: its REWRITE is dropped, and the request goes on unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_that_rewrites_changes_the_planes_request_before_the_money() {
    for (granted, applied) in [(PromptAccess::Rw, true), (PromptAccess::Ro, false)] {
        let order = Order::default();
        let request = request(&order);
        let rewriting = configured(
            Arc::new(Hook::answering(
                "rewrite",
                &order,
                Ok(HookAnswer {
                    rewrite: Some(b"rewritten".to_vec()),
                    ..verdict(abi::VERB_REWRITE, None)
                }),
            )),
            granted,
            UserAccess::No,
        );
        let plane = answering_locally();
        let result = serve_hooked(
            &plane,
            &request,
            &selecting(vec![rewriting], Vec::new(), Vec::new()),
        )
        .await;
        assert!(
            matches!(result, Err(SessionError::AdmissionRefused(_))),
            "{result:?}"
        );
        assert_eq!(ordered(&order), ["rewrite", "money"]);
        let rewrites = plane.rewrites.lock().unwrap().clone();
        if applied {
            assert_eq!(rewrites, [b"rewritten".to_vec()]);
        } else {
            assert!(rewrites.is_empty(), "a hook granted `ro` rewrites nothing");
        }
    }
}

/// RED before: see above. A hook that fails or does not answer in time is handled as v1.5.5
/// handled it, by the operator's `on_error`, and in every case before the money:
/// `reject` refuses the request with v1.5.5's 503 and nothing is charged; `weighted` lets the
/// request go on as if the hook had no opinion; a fallback that answers decides in the failed
/// hook's place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_that_fails_or_times_out_follows_the_operators_on_error_before_the_money() {
    let required = |hook: Hook, timeout: Duration| {
        let mut call = gate(hook);
        let held = Arc::get_mut(&mut call).unwrap();
        held.on_error = PolicyOnError::Reject;
        held.timeout = timeout;
        call
    };
    let unavailable = |result: Result<Ran, SessionError>| match result {
        Err(SessionError::HookRefused(refusal)) => {
            assert_eq!(refusal.status, 503);
            assert_eq!(
                refusal.text,
                "A required gate could not complete. Please retry shortly."
            );
        }
        other => panic!("a required hook that cannot decide refuses the request: {other:?}"),
    };

    // Down, and required.
    let order = Order::default();
    let request_down = request(&order);
    let down = required(
        Hook::answering("gate", &order, Err(())),
        Duration::from_secs(1),
    );
    unavailable(
        serve_hooked(
            &answering_locally(),
            &request_down,
            &selecting(Vec::new(), vec![down], Vec::new()),
        )
        .await,
    );
    assert_eq!(ordered(&order), ["gate"], "nothing was charged");
    assert!(request_down.pending.admitted().is_none());

    // Too slow, and required: its answer, a refusal at 409, came too late to be the request's.
    let order = Order::default();
    let request_slow = request(&order);
    let slow = required(
        Hook {
            delay: Duration::from_millis(300),
            ..Hook::answering("gate", &order, Ok(verdict(abi::VERB_REJECT, Some(409))))
        },
        Duration::from_millis(20),
    );
    unavailable(
        serve_hooked(
            &answering_locally(),
            &request_slow,
            &selecting(Vec::new(), vec![slow], Vec::new()),
        )
        .await,
    );
    // (The abandoned call may not even have started yet: only the money is asserted.)
    assert!(
        !ordered(&order).iter().any(|what| what == "money"),
        "nothing was charged"
    );
    assert!(request_slow.pending.admitted().is_none());

    // Down, and advisory (`on_error: weighted`): the request goes on to its money.
    let order = Order::default();
    let request_advisory = request(&order);
    let advisory = gate(Hook::answering("gate", &order, Err(())));
    let result = serve_hooked(
        &answering_locally(),
        &request_advisory,
        &selecting(Vec::new(), vec![advisory], Vec::new()),
    )
    .await;
    assert!(
        matches!(result, Err(SessionError::AdmissionRefused(_))),
        "{result:?}"
    );
    assert_eq!(ordered(&order), ["gate", "money"]);

    // Down, with a fallback that refuses: the fallback's refusal is the request's.
    let order = Order::default();
    let request_fallback = request(&order);
    let mut primary = required(
        Hook::answering("gate", &order, Err(())),
        Duration::from_secs(1),
    );
    Arc::get_mut(&mut primary)
        .unwrap()
        .fallbacks
        .push(gate(Hook::answering(
            "fallback",
            &order,
            Ok(verdict(abi::VERB_REJECT, Some(451))),
        )));
    let result = serve_hooked(
        &answering_locally(),
        &request_fallback,
        &selecting(Vec::new(), vec![primary], Vec::new()),
    )
    .await;
    match result {
        Err(SessionError::HookRefused(refusal)) => assert_eq!(refusal.status, 451),
        other => panic!("{other:?}"),
    }
    assert_eq!(ordered(&order), ["gate", "fallback"]);
}

/// The facts one response-stage notification is shown, or a panic when none arrives.
async fn response_stage(
    received: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<(u32, FactVal)>>,
) -> Vec<(u32, FactVal)> {
    tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await
        .expect("the response stage reaches its hook")
        .expect("the hook is still held")
}

/// RED before: see above. The response stage reaches its hook with v1.5.5's facts, on a request
/// that never reached its money: the status the caller was answered and why. A hook's own
/// refusal is `rejected_by_gate` at the hook's status (the completion that lets an audit hook
/// see a denial); a money refusal after the hooks allowed the request is `failed` at the
/// money's status. The notification is fired while the request still allows its hooks and is
/// delivered although the request's admission has ended by the time it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_response_stage_tells_its_hook_how_a_request_ended_before_or_at_its_money() {
    /// `S_RESPONSE_TOKENS_OUT` until hook 3.0 retired it: never sent.
    const RETIRED_TOKENS_OUT: u32 = 0x10B;
    for (verb, status, outcome, asked) in [
        (abi::VERB_REJECT, 409, "rejected_by_gate", vec!["gate"]),
        (abi::VERB_ABSTAIN, 402, "failed", vec!["gate", "money"]),
    ] {
        let order = Order::default();
        let request = request(&order);
        let (shown, mut received) = tokio::sync::mpsc::unbounded_channel();
        let deciding = gate(Hook::answering(
            "gate",
            &order,
            Ok(verdict(verb, Some(409))),
        ));
        let listening = gate(Hook {
            shown: Some(shown),
            ..Hook::answering("tap", &order, Ok(verdict(abi::VERB_ABSTAIN, None)))
        });
        let result = serve_hooked(
            &answering_locally(),
            &request,
            &selecting(Vec::new(), vec![deciding], vec![listening]),
        )
        .await;
        assert!(result.is_err(), "{result:?}");
        assert_eq!(ordered(&order), asked);
        let facts = response_stage(&mut received).await;
        assert!(facts.contains(&(abi::S_STAGE, FactVal::U(abi::STAGE_RESPONSE))));
        assert!(facts.contains(&(abi::S_STATUS, FactVal::U(status))));
        assert!(facts.contains(&(abi::S_OUTCOME, FactVal::Text(outcome.into()))));
        assert!(
            !facts.iter().any(|(key, _)| *key == RETIRED_TOKENS_OUT),
            "the retired output-token fact is never sent"
        );
        assert!(
            received.try_recv().is_err(),
            "the response stage fires once ({outcome})"
        );
    }
}

/// A route with no hook is unchanged: its money is asked once, no hook is called, and nothing is
/// built for the feature (`run_pending_session` goes from the resolved walk straight to the
/// money: the stage is `None`). The same holds on a seat that has hooks for a route they are
/// not bound to. Green before and after: this is the behaviour the change must not move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_with_no_hook_asks_its_money_once_and_calls_no_hook() {
    let order = Order::default();
    let request_plain = request(&order);
    let result = serve(&answering_locally(), &request_plain, None).await;
    match result {
        Err(SessionError::AdmissionRefused(refusal)) => assert_eq!(refusal.status, 402),
        other => panic!("{other:?}"),
    }
    assert_eq!(ordered(&order), ["money"]);

    let order = Order::default();
    let request_elsewhere = request(&order);
    let elsewhere = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_REJECT, Some(409))),
    ));
    let binder = Arc::new(Bindings::selecting(
        vec![req().route + 1],
        "pool",
        &selecting(Vec::new(), vec![elsewhere], Vec::new()),
        gov_state().await,
    ));
    let result = serve(&answering_locally(), &request_elsewhere, Some(binder)).await;
    assert!(
        matches!(result, Err(SessionError::AdmissionRefused(_))),
        "{result:?}"
    );
    assert_eq!(
        ordered(&order),
        ["money"],
        "a hook bound to another route is not called for this one"
    );
}

/// The record host of [`a_native_record_write_waits_for_the_money_and_is_never_made_without_it`]:
/// each STORE it is asked to make goes into the order, as "store".
struct Recording(Order);
impl IntentHost for Recording {
    fn lookup<'a>(
        &'a self,
        _: Scope,
        _: u32,
        _: u32,
        _: &'a [u8],
        _: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn store<'a>(
        &'a self,
        _: Scope,
        _: u32,
        _: u64,
        _: &'a [u8],
        _: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        self.0.lock().unwrap().push("store".into());
        Box::pin(std::future::ready(Ok(())))
    }
    fn delete<'a>(&'a self, _: Scope, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn commit<'a>(
        &'a self,
        _: Scope,
        _: &'a [CommitOp<'a>],
    ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>> {
        Box::pin(std::future::ready(Ok(CommitOutcome::Applied)))
    }
    fn work<'a>(
        &'a self,
        _: &'a crate::plane_driver::port_intents::WorkIntent<'a>,
    ) -> BoxFut<'a, WorkOutcome<'a>> {
        Box::pin(std::future::ready(WorkOutcome::unsupported()))
    }
    fn push<'a>(&'a self, _: u64, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

/// A native request's record write (the MCP session record an `initialize` stores) is held by the
/// pending admission's screen: it is made only once the money admitted the request, so a request
/// the money refuses never writes. The money is asked first, and the write never follows a refusal.
#[tokio::test]
async fn a_native_record_write_waits_for_the_money_and_is_never_made_without_it() {
    let order = Order::default();
    let request = request(&order);
    let plane = Plane {
        request: vec![It::Store(b"session"), It::Respond(200), It::End],
        ..Plane::default()
    };
    let effects = Admitting {
        pending: &request.pending,
        hooks: None,
    };
    let host = Recording(Arc::clone(&order));
    // The verified caller: a caller-scoped write has a scope to be made in.
    let resolver = Resolver::new(&host, None).with_principal("payer", &[]);
    let refusals = CoreRefusals::new();
    let drive: Drive<'_> = Drive {
        resolver: &resolver,
        members: None,
        send: None,
        dialect: "test",
        refusals: &refusals,
        effects: &effects,
        books: &request.pending,
        carrier: None,
    };
    let result = crate::plane_driver::port_serve::run_session(&plane, &req(), b"{}", drive).await;
    assert!(
        matches!(&result, Err(SessionError::AdmissionRefused(refusal)) if refusal.status == 402),
        "{result:?}"
    );
    assert_eq!(
        ordered(&order),
        ["money"],
        "the write waited for the money, and the refused request wrote nothing"
    );
}

/// What a refusal's custody was handed: each record's hook, its head, and whether it failed.
fn kept(records: &HookRecords) -> Vec<(String, busbar_kernel_audit::HookHead, bool)> {
    records
        .rows()
        .iter()
        .map(|row| (row.hook.as_str().to_owned(), row.head, row.failed))
        .collect()
}

/// RED before the refusal's custody took the stage's records: a hook that refused before the
/// money left no record naming it (the stage held its records for a unit that never opened and
/// dropped them with the request).
///
/// The refusal's own custody is handed the records of every hook that ran, in the order they
/// ran, the refusing hook's among them with the head `veto`. No unit is needed to hold them:
/// none was opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_refusal_before_the_money_hands_its_records_to_the_refusal() {
    let order = Order::default();
    let request = request(&order);
    let allowing = configured(
        Arc::new(Hook::answering(
            "first",
            &order,
            Ok(verdict(abi::VERB_ABSTAIN, None)),
        )),
        PromptAccess::No,
        UserAccess::No,
    );
    let refusing = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_REJECT, Some(409))),
    ));
    let records = Arc::new(HookRecords::default());
    // A rewrite is asked before the gates: `first` runs, then `gate` refuses.
    let result = serve_keeping(
        &answering_locally(),
        &request,
        Some(bindings(
            &selecting(vec![allowing], vec![refusing], Vec::new()),
            gov_state().await,
        )),
        Some(Arc::clone(&records)),
    )
    .await;
    assert!(
        matches!(&result, Err(SessionError::HookRefused(refusal)) if refusal.status == 409),
        "{result:?}"
    );
    assert!(request.pending.admitted().is_none(), "no unit was opened");
    assert_eq!(ordered(&order), ["first", "gate"]);
    assert_eq!(
        kept(&records),
        [
            (
                "first".to_owned(),
                busbar_kernel_audit::HookHead::Pass,
                false
            ),
            (
                "gate".to_owned(),
                busbar_kernel_audit::HookHead::Veto,
                false
            ),
        ],
        "the refusal names the hook that refused"
    );
    assert_eq!(
        records.refused_by().as_deref(),
        Some("gate"),
        "the hook that refused, by its configured name"
    );
}

/// RED before, for the same reason: a request its hooks allowed and its money then refused
/// kept no record of the hooks that ran for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_money_refusal_after_the_hooks_keeps_the_records_of_the_hooks_that_ran() {
    let order = Order::default();
    let request = request(&order);
    let allowing = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_ABSTAIN, None)),
    ));
    let records = Arc::new(HookRecords::default());
    let result = serve_keeping(
        &answering_locally(),
        &request,
        Some(bindings(
            &selecting(Vec::new(), vec![allowing], Vec::new()),
            gov_state().await,
        )),
        Some(Arc::clone(&records)),
    )
    .await;
    assert!(
        matches!(&result, Err(SessionError::AdmissionRefused(refusal)) if refusal.status == 402),
        "{result:?}"
    );
    assert_eq!(ordered(&order), ["gate", "money"]);
    assert_eq!(
        kept(&records),
        [(
            "gate".to_owned(),
            busbar_kernel_audit::HookHead::Pass,
            false
        )]
    );
    assert_eq!(records.refused_by(), None, "no hook refused: the money did");
}

/// One verified request on a route that opens no unit (its record says money none): registered
/// under its verified key, with no admission to resolve and no money to ask.
struct Unbilled {
    context: InvocationContext,
    records: Arc<HookRecords>,
    _admission: NativeInvocationAdmission,
}

fn unbilled_request(unit: u64) -> Unbilled {
    let core = Arc::new(KernelServices::new().with_pool(Arc::new(BlockingPool::new(
        tokio::runtime::Handle::current(),
        16,
    ))));
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from("seat"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    let admission = core.admit_native_invocation(&caller).unwrap();
    assert!(
        core.units()
            .admitted_unbilled(
                unit,
                &caller,
                crate::host_units::UnitRecord {
                    principal: Some(Arc::new(busbar_contract::records::VirtualKey {
                        id: "caller".into(),
                        enabled: true,
                        ..Default::default()
                    })),
                    depth: 0,
                },
                None,
            )
            .is_some(),
        "a verified request with no unit is registered once"
    );
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
        caller,
        unit,
    )
    .unwrap();
    Unbilled {
        context,
        records: Arc::new(HookRecords::default()),
        _admission: admission,
    }
}

/// The session's effects on a route that opens no unit: no pending admission, the request's
/// invocation, and the route's hooks when it has any.
struct Unpaid<'a> {
    context: Option<&'a InvocationContext>,
    hooks: Option<Invocation>,
}
impl Effects for Unpaid<'_> {
    fn invocation(&self) -> Option<&InvocationContext> {
        self.context
    }
    fn hooks(&self) -> Option<&Invocation> {
        self.hooks.as_ref()
    }
    fn emit(&self, _: u64, _: &[u8]) {
        panic!("a request with no unit emits nothing to a line")
    }
}

/// The books of a session with no unit: nothing is billed.
struct NoBooks;
impl Books for NoBooks {
    fn ended(&self, _: Ending, _: &SessionUsage) {}
    fn audit(&self, _: &AuditRow) {}
}

/// One session of `plane` on a route that opens no unit. `request`: the verified request and
/// its invocation, `None` for a route with no hook (the listener hands such a route none).
async fn serve_unbilled(
    plane: &Plane,
    request: Option<&Unbilled>,
    binder: Option<Arc<Bindings>>,
) -> Result<Ran, SessionError> {
    let effects = Unpaid {
        context: request.map(|request| &request.context),
        hooks: binder.zip(request).map(|(binder, request)| Invocation {
            binder,
            principal: None,
            now_s: 1,
            classes: Arc::default(),
            journal: None,
            unit: UnitKey::new(request.context.unit()),
            records: Some(Arc::clone(&request.records)),
        }),
    };
    let store = Store;
    let resolver = Resolver::new(&store, None);
    let refusals = CoreRefusals::new();
    let drive: Drive<'_> = Drive {
        resolver: &resolver,
        members: None,
        send: None,
        dialect: "test",
        refusals: &refusals,
        effects: &effects,
        books: &NoBooks,
        carrier: None,
    };
    crate::plane_driver::port_serve::run_session(plane, &req(), b"{}", drive).await
}

/// RED before a route that opens no unit ran its hooks: such a route with a hook bound was
/// left unmounted (its session was handed no invocation to call a hook under), so it could not
/// be served at all.
///
/// A refusing hook refuses at its own status, in core's words, and nothing runs after it: the
/// hook after it is not asked, the plane's answer is not released, and no effect is allowed.
/// The refusal names the hook that refused, with no unit to hold the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusing_hook_on_a_route_that_opens_no_unit_refuses_and_nothing_runs_after_it() {
    let order = Order::default();
    let request = unbilled_request(51);
    assert!(
        request.context.hooks_allowed(),
        "a verified request with no unit is shown to its route's hooks"
    );
    assert!(
        !request.context.effects_allowed(),
        "and is given no effect: it opened no unit"
    );
    // A rewrite is asked before the gates: the refusing hook is first, the other after it.
    let refusing = configured(
        Arc::new(Hook::answering(
            "gate",
            &order,
            Ok(verdict(abi::VERB_REJECT, Some(409))),
        )),
        PromptAccess::No,
        UserAccess::No,
    );
    let after = gate(Hook::answering(
        "after",
        &order,
        Ok(verdict(abi::VERB_ABSTAIN, None)),
    ));
    let result = serve_unbilled(
        &answering_locally(),
        Some(&request),
        Some(bindings(
            &selecting(vec![refusing], vec![after], Vec::new()),
            gov_state().await,
        )),
    )
    .await;
    match result {
        Err(SessionError::HookRefused(refusal)) => {
            assert_eq!(refusal.status, 409, "the hook's own status");
            assert_eq!(refusal.text, "the request was refused by policy");
        }
        other => panic!("a refusing hook is the caller's refusal: {other:?}"),
    }
    assert_eq!(
        ordered(&order),
        ["gate"],
        "the hook after the refusal was never asked"
    );
    assert!(!request.context.effects_allowed());
    assert_eq!(
        kept(&request.records),
        [(
            "gate".to_owned(),
            busbar_kernel_audit::HookHead::Veto,
            false
        )],
        "the refusal's record names the hook, with no unit to hold it"
    );
    assert_eq!(request.records.refused_by().as_deref(), Some("gate"));
}

/// RED before, for the same reason. A hook that allows is heard, in the order a billed route
/// hears its hooks (each rewrite, then the gates), the plane then answers, and still no effect
/// is allowed and no money is asked: there is none to ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_opens_no_unit_hears_its_hooks_in_the_billed_order_and_is_served() {
    let order = Order::default();
    let request = unbilled_request(52);
    let rewrite = configured(
        Arc::new(Hook::answering(
            "rewrite",
            &order,
            Ok(verdict(abi::VERB_ABSTAIN, None)),
        )),
        PromptAccess::No,
        UserAccess::No,
    );
    let allowing = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_ABSTAIN, None)),
    ));
    let result = serve_unbilled(
        &answering_locally(),
        Some(&request),
        Some(bindings(
            &selecting(vec![rewrite], vec![allowing], Vec::new()),
            gov_state().await,
        )),
    )
    .await;
    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(ordered(&order), ["rewrite", "gate"]);
    assert!(!request.context.effects_allowed(), "it opened no unit");
    assert_eq!(
        kept(&request.records),
        [
            (
                "rewrite".to_owned(),
                busbar_kernel_audit::HookHead::Pass,
                false
            ),
            (
                "gate".to_owned(),
                busbar_kernel_audit::HookHead::Pass,
                false
            ),
        ]
    );
    assert_eq!(request.records.refused_by(), None);
}

/// A request with no unit can never be given one: no monetary allocation is built from its
/// invocation, so nothing can be charged or admitted under it; and its end closes it to hooks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_opens_no_unit_can_never_be_charged() {
    let request = unbilled_request(53);
    assert!(request.context.opens_no_unit());
    assert!(
        RequestAllocation::new(
            request.context.clone(),
            Arc::new(crate::cost::CostModel::resolve_parts(
                None,
                0,
                &Default::default(),
            )),
            100,
        )
        .is_err(),
        "no money is asked under a request that opens no unit"
    );
    assert!(request.context.hooks_allowed());
    assert!(!request.context.effects_allowed());
    request.context.retire();
    assert!(!request.context.hooks_allowed());
}

/// Green before and after: a route that opens no unit and has no hook bound pays nothing for
/// the feature. Its session is handed no invocation, no stage is built and no hook is called;
/// the same holds on a seat whose hooks are bound to another route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_opens_no_unit_and_has_no_hook_pays_nothing() {
    let result = serve_unbilled(&answering_locally(), None, None).await;
    assert!(result.is_ok(), "{:?}", result.err());

    let order = Order::default();
    let elsewhere = gate(Hook::answering(
        "gate",
        &order,
        Ok(verdict(abi::VERB_REJECT, Some(409))),
    ));
    let binder = Arc::new(Bindings::selecting(
        vec![req().route + 1],
        "pool",
        &selecting(Vec::new(), vec![elsewhere], Vec::new()),
        gov_state().await,
    ));
    let request = unbilled_request(54);
    let result = serve_unbilled(&answering_locally(), Some(&request), Some(binder)).await;
    assert!(result.is_ok(), "{:?}", result.err());
    assert!(
        ordered(&order).is_empty(),
        "a hook bound to another route is not called for this one"
    );
    assert!(request.records.rows().is_empty());
}
