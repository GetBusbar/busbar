// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invocation-scoped child dispatch. Targets and limits originate in host configuration.
use crate::host_services::{InvocationContext, Nest, NestReply};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::{Caller, HookChildInvocation, Later, Ran, Stored};
use std::sync::{Arc, Mutex};
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
    context: InvocationContext,
    unit: u64,
    hook: Arc<str>,
    /// The parent's ancestry, read once when the invocation was minted and carried to the
    /// child request (SINGLE-PATH SP-P14); it is fixed when the parent is nested.
    ancestry: Arc<[Arc<str>]>,
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
        let services = self.context.generation().core();
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
        if self.ancestry.iter().any(|name| name == &self.hook) {
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
        let mut ancestry = self.ancestry.to_vec();
        ancestry.push(self.hook.clone());
        let memo = self.memo.clone();
        let dispatched = self.context.dispatch_hook_child(
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
        if let Err(why) = dispatched {
            self.memo.finish(Stored::refused(why));
        }
        Ran::Later
    }
}

pub(crate) struct Scope {
    context: InvocationContext,
    ancestry: Arc<[Arc<str>]>,
}

impl Scope {
    pub(crate) fn new(context: InvocationContext) -> Self {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::AncestryCheck);
        let ancestry = context
            .generation()
            .core()
            .units()
            .child_ancestry(context.unit())
            .into();
        Self { context, ancestry }
    }

    fn ancestry(&self) -> &Arc<[Arc<str>]> {
        &self.ancestry
    }
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
            let ancestry = scope.ancestry();
            if ancestry.iter().any(|h| h.as_ref() == hook) {
                return None;
            }
            let parent = scope
                .context
                .generation()
                .core()
                .units()
                .get(scope.context.unit())?;
            let memo = scope.context.generation().core().units().hook_child(
                scope.context.unit(),
                hook,
                || Arc::new(Memo::new(grant.clone(), parent)),
            )?;
            // A configuration reload never reclassifies an admitted parent.
            let duration = Duration::from_millis(memo.grant.timeout_ms).min(budget);
            let deadline = Instant::now().checked_add(duration)?;
            {
                let mut state = memo.state.lock().unwrap_or_else(|p| p.into_inner());
                state.active = state.active.checked_add(1)?;
            }
            Some(Arc::new(Invocation {
                context: scope.context.clone(),
                unit: scope.context.unit(),
                hook: Arc::from(hook),
                ancestry: Arc::clone(ancestry),
                deadline,
                memo,
            }) as Arc<dyn HookChildInvocation>)
        })
        .ok()
        .flatten()
}

pub(crate) fn recursive(hook: &str) -> bool {
    SCOPE
        .try_with(|s| s.ancestry().iter().any(|h| h.as_ref() == hook))
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "tests/hook_child_tests.rs"]
mod tests;
