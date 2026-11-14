// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invocation-scoped child dispatch. Targets and limits originate in host configuration.
use crate::host_services::{KernelServices, Nest, NestReply};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::{Caller, HookChildInvocation, Later, Ran, Stored};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// A single immutable operation binding. Payload bytes cannot change any of these fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub revision: u64,
    pub plane: String,
    pub operation: String,
    pub target: String,
    pub target_binding: String,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_children: u32,
    pub timeout_ms: u64,
    pub max_budget_micros: u64,
}
impl Grant {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.revision == 0
            || self.plane.is_empty()
            || self.operation.is_empty()
            || self.target_binding.is_empty()
            || !self.target.starts_with('/')
            || self.target.contains(['\r', '\n', '#'])
            || self.operation.contains(char::is_whitespace)
            || self.max_input_bytes == 0
            || self.max_input_bytes > 1024 * 1024
            || self.max_output_bytes == 0
            || self.max_output_bytes > 1024 * 1024
            || self.max_children != 1
            || self.timeout_ms == 0
            || self.timeout_ms > 60_000
            || self.max_budget_micros == 0
        {
            return Err("invalid hook child dispatch grant");
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Cancellation {
    cancelled: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.wake.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
    pub async fn cancelled(&self) {
        loop {
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            wake.await;
        }
    }
}

/// Host-only restrictions handed to the ordinary nested route.
#[derive(Debug, Clone)]
pub struct Constraints {
    pub grant: Arc<Grant>,
    pub deadline: Instant,
    pub cancellation: Arc<Cancellation>,
}

struct State {
    active: usize,
    request: Option<Vec<u8>>,
    answer: Option<Stored>,
    waiting: Vec<Later>,
}
impl Drop for State {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(request) = self.request.as_mut() {
            request.zeroize();
        }
    }
}
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("started", &self.request.is_some())
            .field("answered", &self.answer.is_some())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct Memo {
    parent: Arc<crate::host_units::UnitRecord>,
    grant: Arc<Grant>,
    state: Mutex<State>,
    cancellation: Arc<Cancellation>,
}
impl Memo {
    fn new(grant: Arc<Grant>, parent: Arc<crate::host_units::UnitRecord>) -> Self {
        Self {
            parent,
            grant,
            state: Mutex::new(State {
                active: 0,
                request: None,
                answer: None,
                waiting: Vec::new(),
            }),
            cancellation: Arc::default(),
        }
    }
    fn finish(&self, answer: Stored) {
        let waiting = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.answer.is_some() {
                return;
            }
            state.answer = Some(answer.clone());
            std::mem::take(&mut state.waiting)
        };
        for done in waiting {
            done(answer.clone());
        }
    }
}

struct Invocation {
    services: Weak<KernelServices>,
    unit: u64,
    hook: Arc<str>,
    memo: Arc<Memo>,
    deadline: Instant,
}
impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookChildInvocation")
            .field("unit", &self.unit)
            .field("hook", &self.hook)
            .finish()
    }
}
impl Drop for Invocation {
    fn drop(&mut self) {
        let answer = Stored::refused("hook invocation ended");
        let waiting = {
            let mut state = self.memo.state.lock().unwrap_or_else(|p| p.into_inner());
            state.active -= 1;
            if state.active != 0 || state.request.is_none() {
                return;
            }
            self.memo.cancellation.cancel();
            if state.answer.is_some() {
                return;
            }
            state.answer = Some(answer.clone());
            std::mem::take(&mut state.waiting)
        };
        for done in waiting {
            done(answer.clone());
        }
    }
}
impl HookChildInvocation for Invocation {
    fn request(&self, caller: &Caller, payload: Vec<u8>, later: Later) -> Ran {
        let Some(services) = self.services.upgrade() else {
            return Ran::Now(Stored::refused("child host ended"));
        };
        let grant = &self.memo.grant;
        if caller.kind() != KindCode::Hook
            || caller.namespace().as_ref() != self.hook.as_ref()
            || payload.len() > grant.max_input_bytes
        {
            return Ran::Now(Stored::refused("hook child grant refused"));
        }
        let Some(parent) = services.units().get(self.unit) else {
            return Ran::Now(Stored::refused("hook parent ended"));
        };
        if !Arc::ptr_eq(&parent, &self.memo.parent) {
            return Ran::Now(Stored::refused("hook parent authority changed"));
        }
        let mut ancestry = ancestry_of(&services, self.unit);
        if ancestry.iter().any(|name| name == &self.hook) {
            return Ran::Now(Stored::refused("hook child cycle"));
        }
        {
            let mut state = self.memo.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(first) = &state.request {
                if first != &payload {
                    return Ran::Now(Stored::refused("hook child payload changed"));
                }
                if let Some(answer) = &state.answer {
                    return Ran::Now(answer.clone());
                }
                if state.waiting.len() >= 16 {
                    return Ran::Now(Stored::refused("too many hook child polls"));
                }
                state.waiting.push(later);
                return Ran::Later;
            }
            if Instant::now() >= self.deadline || self.memo.cancellation.is_cancelled() {
                return Ran::Now(Stored::refused("hook child invocation expired"));
            }
            state.request = Some(payload.clone());
            state.waiting.push(later);
        }
        ancestry.push(self.hook.clone());
        let memo = self.memo.clone();
        services.dispatch_hook_child(
            Nest {
                parent: self.unit,
                depth: parent.depth.saturating_add(1),
                principal: parent.principal.clone(),
                ask: busbar_contract::services::NestAsk {
                    verb: grant.operation.clone(),
                    target: grant.target.clone(),
                    body: payload,
                },
                ancestry,
                constraints: Some(Constraints {
                    grant: grant.clone(),
                    deadline: self.deadline,
                    cancellation: self.memo.cancellation.clone(),
                }),
            },
            Box::new(move |reply| {
                let answer = match reply {
                    NestReply::Answered { status, body, .. }
                        if body.len() <= memo.grant.max_output_bytes =>
                    {
                        let mut answer = Stored::ready(u64::from(status));
                        answer.bytes = body;
                        answer
                    }
                    NestReply::Answered { .. } => {
                        Stored::refused("hook child response exceeded bound")
                    }
                    NestReply::Unserved(why) | NestReply::Failed(why) => Stored::refused(why),
                };
                memo.finish(answer);
            }),
        );
        Ran::Later
    }
}

pub(crate) struct Scope {
    pub services: Arc<KernelServices>,
    pub unit: u64,
}

/// The hook children a unit was nested through, for the cycle check.
fn ancestry_of(services: &KernelServices, unit: u64) -> Vec<Arc<str>> {
    busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::AncestryCheck);
    services.units().child_ancestry(unit)
}
tokio::task_local! { pub(crate) static SCOPE: Scope; }

/// Only request-stage host execution can mint this authority. Repeated stage entries keep the
/// original grant and child result in the admitted unit record.
pub(crate) fn invocation(
    hook: &str,
    grant: Option<&Arc<Grant>>,
    budget: Duration,
) -> Option<Arc<dyn HookChildInvocation>> {
    let grant = grant?;
    SCOPE
        .try_with(|scope| {
            if ancestry_of(&scope.services, scope.unit)
                .iter()
                .any(|h| h.as_ref() == hook)
            {
                return None;
            }
            let parent = scope.services.units().get(scope.unit)?;
            let memo = scope.services.units().hook_child(scope.unit, hook, || {
                Arc::new(Memo::new(grant.clone(), parent))
            })?;
            // A configuration reload never reclassifies an admitted parent.
            let duration = Duration::from_millis(memo.grant.timeout_ms).min(budget);
            let deadline = Instant::now().checked_add(duration)?;
            {
                let mut state = memo.state.lock().unwrap_or_else(|p| p.into_inner());
                state.active = state.active.checked_add(1)?;
            }
            Some(Arc::new(Invocation {
                services: Arc::downgrade(&scope.services),
                unit: scope.unit,
                hook: Arc::from(hook),
                deadline,
                memo,
            }) as Arc<dyn HookChildInvocation>)
        })
        .ok()
        .flatten()
}

pub(crate) fn recursive(hook: &str) -> bool {
    SCOPE
        .try_with(|s| {
            ancestry_of(&s.services, s.unit)
                .iter()
                .any(|h| h.as_ref() == hook)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_services::{NestDone, NestRoute};
    use crate::host_units::UnitRecord;
    use busbar_contract::abi::mechanism::call::Outcome;

    #[derive(Default)]
    struct Route {
        calls: Mutex<Vec<Nest>>,
        pending: Mutex<Vec<NestDone>>,
        hold: bool,
    }
    impl NestRoute for Route {
        fn nest(&self, nest: Nest, done: NestDone) {
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
    fn setup(route: Arc<Route>) -> (Arc<KernelServices>, Caller) {
        let services = Arc::new(KernelServices::new());
        services.attach_nest(route);
        services.units().admitted(
            7,
            UnitRecord {
                principal: Some(Arc::new(busbar_contract::records::VirtualKey {
                    id: "principal".into(),
                    ..Default::default()
                })),
                depth: 0,
            },
        );
        (
            services,
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
            .scope(Scope { services, unit: 7 }, async {
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
            .scope(Scope { services, unit: 7 }, async {
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
            .scope(
                Scope {
                    services: services.clone(),
                    unit: 7,
                },
                async {
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
                },
            )
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
            .scope(
                Scope {
                    services: services.clone(),
                    unit: 7,
                },
                async {
                    assert!(recursive("gate"));
                    assert!(invocation("gate", Some(&grant()), Duration::from_secs(1)).is_none());
                    services.units().set_child_ancestry(7, Vec::new());
                    let child = invocation("gate", Some(&grant()), Duration::from_secs(1)).unwrap();
                    services.units().ended(7);
                    assert_eq!(
                        request(&*child, &caller, b"p").unwrap().outcome,
                        Outcome::Refused
                    );
                },
            )
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
            .scope(Scope { services, unit: 7 }, async {
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
                .scope(Scope { services, unit: 7 }, async {
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
}
