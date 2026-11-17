// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use super::super::hooks::{Constraint, HooksRan, Restrict};
use super::super::port_serve::Drive;
use super::super::port_session::{Answer, Calls, ClientSink, Effects, SessionError, Task};
use super::super::port_upstream::Wants;
use super::{call, CandidateView, Invocation, Projection, Selected, Selection};
use crate::host_services::InvocationContext;
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::{plane::PlaneIn, FactVal, PortError};

/// Sink-time output is held as securely as the projection until enforcement succeeds.
pub(crate) struct Buffered<'a> {
    inner: &'a dyn Effects,
    emits: RefCell<Vec<(u64, busbar_contract::secure::SecureVec)>>,
}
impl<'a> Buffered<'a> {
    pub(crate) fn new(inner: &'a dyn Effects) -> Self {
        Self {
            inner,
            emits: RefCell::new(Vec::new()),
        }
    }
    pub(crate) fn release(&self) {
        for (carrier, bytes) in self.emits.borrow_mut().drain(..) {
            self.inner.emit(carrier, &bytes);
        }
    }
}
impl Effects for Buffered<'_> {
    fn invocation(&self) -> Option<&InvocationContext> {
        self.inner.invocation()
    }
    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.emits
            .borrow_mut()
            .push((carrier, bytes.to_vec().into()));
    }
}

#[derive(Clone)]
pub(crate) struct Stage {
    selected: Selected,
    projection: Projection,
    candidates: Vec<CandidateView>,
    quantities: Vec<(Box<str>, f64)>,
    scope: super::super::RoutedScope,
    route: u32,
    dialect: Arc<str>,
    principal: Option<Arc<str>>,
    identity: busbar_contract::secure::SecureVec,
    request_id: u64,
    now_s: u64,
    context: InvocationContext,
    journal: Option<Arc<dyn super::HookJournal>>,
    unit: busbar_contract::UnitKey,
}
impl Stage {
    fn selection(&self) -> Selection<'_> {
        Selection {
            route: self.route,
            pool: &self.scope.pool,
            container: &self.scope.container,
            dialect: &self.dialect,
            principal: self.principal.as_deref(),
            key: self.context.principal().map(AsRef::as_ref),
            request_id: self.request_id,
            now_s: self.now_s,
        }
    }
    fn input<'a>(
        &'a self,
        selection: &'a Selection<'a>,
        stage: &'a [(u32, FactVal)],
    ) -> call::Input<'a> {
        call::Input {
            projection: &self.projection,
            selected: &self.selected,
            selection,
            identity: &self.identity,
            candidates: &self.candidates,
            quantities: &self.quantities,
            stage,
            context: &self.context,
        }
    }
    fn report(&self, hooks: Vec<busbar_kernel_audit::record::HookApplied>) {
        if let Some(journal) = &self.journal {
            journal.hooks_ran(&HooksRan {
                unit: self.unit,
                hooks,
            });
        }
    }
    fn taps(&self, calls: &[Arc<super::Call>], facts: Vec<(u32, FactVal)>) {
        if calls.is_empty() {
            return;
        }
        let mut held = self.clone();
        if !facts.is_empty() {
            held.projection = held.projection.shape();
        }
        let calls = calls.to_vec();
        crate::hooks::taps::spawn_bounded_tap(async move {
            let selection = held.selection();
            let input = held.input(&selection, &facts);
            let mut ran = Vec::new();
            for call in calls {
                let result = call::one(&call, abi::POINT_NOTIFY, &input).await;
                ran.push(call::record(&call, result.as_ref().ok()));
            }
            held.report(ran);
        });
    }
}

/// Hooks for outcomes after request enforcement. No later-stage tap receives conversation bytes.
pub(crate) struct Observed<'a> {
    pub(crate) inner: &'a dyn Effects,
    pub(crate) stage: Stage,
    responded: Cell<bool>,
}
impl<'a> Observed<'a> {
    pub(crate) fn new(inner: &'a dyn Effects, stage: Stage) -> Self {
        Self {
            inner,
            stage,
            responded: Cell::new(false),
        }
    }
}
impl Effects for Observed<'_> {
    fn invocation(&self) -> Option<&InvocationContext> {
        self.inner.invocation()
    }
    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.inner.emit(carrier, bytes);
    }
    fn client(&self) -> Option<&dyn ClientSink> {
        self.inner.client()
    }
    fn routing(&self, attempt: u32, model: &str) {
        self.stage.taps(
            &self.stage.selected.taps.routing,
            vec![
                (abi::S_STAGE, FactVal::U(abi::STAGE_ROUTING)),
                (abi::S_ATTEMPT, FactVal::U(attempt.into())),
                (abi::S_STAGE_MODEL, FactVal::Text(model.into())),
            ],
        );
        self.inner.routing(attempt, model);
    }
    fn response(&self, status: u16) {
        if !self.responded.replace(true) {
            self.stage.taps(
                &self.stage.selected.taps.response,
                vec![
                    (abi::S_STAGE, FactVal::U(abi::STAGE_RESPONSE)),
                    (abi::S_STATUS, FactVal::U(status.into())),
                ],
            );
        }
        self.inner.response(status);
    }
}

pub(crate) fn enforce<K: Calls + ?Sized>(
    invocation: &Invocation,
    task: &mut Task<'_, K>,
    answers: &mut Vec<Answer>,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_>,
    effects: &dyn Effects,
) -> Result<Stage, SessionError> {
    let context = effects
        .invocation()
        .ok_or(SessionError::HookPrerequisite)?
        .clone();
    let mut projection = Projection::default();
    for answer in answers.iter() {
        projection.absorb(answer);
    }
    let wants = answers
        .iter()
        .find_map(|answer| answer.forward.as_ref())
        .map(|forward| Wants::from_facts(&forward.wants));
    let mut scope = super::super::RoutedScope::default();
    let mut candidates = Vec::new();
    if let Some(wants) = &wants {
        let members = drive
            .members
            .as_deref_mut()
            .ok_or(SessionError::HookPrerequisite)?;
        scope = members
            .hook_scope(wants)
            .ok_or(SessionError::HookPrerequisite)?;
        let found = members
            .hook_candidates(wants)
            .ok_or(SessionError::HookPrerequisite)?;
        for facts in found.members {
            let lane = members
                .hook_lane(wants, facts.idx)
                .ok_or(SessionError::HookPrerequisite)?;
            candidates.push(CandidateView { facts, lane });
        }
    }
    let selection = Selection {
        route: req.route,
        pool: &scope.pool,
        container: &scope.container,
        dialect: drive.dialect,
        principal: invocation.principal.as_deref(),
        key: context.principal().map(AsRef::as_ref),
        request_id: req.request_id,
        now_s: invocation.now_s,
    };
    let selected = invocation
        .binder
        .select(&selection)
        .map_err(|_| SessionError::HookPrerequisite)?;
    let mut stage = Stage {
        selected,
        projection,
        candidates,
        quantities: Vec::new(),
        scope,
        route: req.route,
        dialect: drive.dialect.into(),
        principal: invocation.principal.clone(),
        identity: req.identity.to_vec().into(),
        request_id: req.request_id,
        now_s: invocation.now_s,
        context,
        journal: invocation.journal.clone(),
        unit: invocation.unit,
    };
    let handle = tokio::runtime::Handle::current();
    let mut ran = Vec::new();
    let result = (|| {
        for rewrite in stage.selected.rewrites.clone() {
            let selection = stage.selection();
            let input = stage.input(&selection, &[]);
            let (called, answer) =
                handle.block_on(call::chain(&rewrite, abi::POINT_REWRITE, &input, &mut ran));
            if answer.verb == abi::VERB_REJECT {
                return Err(SessionError::HookRefused(drive.refusals.for_hook(
                    req.route,
                    &called.name,
                    answer.reject_status,
                    answer.message.as_deref(),
                )));
            }
            if answer.verb != abi::VERB_REWRITE || !called.prompt.can_rewrite() {
                continue;
            }
            if let Some(bytes) = answer.rewrite {
                match task.rewrite(&bytes, effects) {
                    Ok(answer) => {
                        stage.projection.rewritten(bytes, &answer);
                        answers.push(answer);
                    }
                    Err(SessionError::Port(PortError::Refused {
                        code: busbar_plugin_abi::fail::refused::R_INVALID,
                        ..
                    })) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        stage.quantities = super::quantities(&invocation.classes, &stage.projection.expects)?;
        stage.taps(&stage.selected.taps.request, Vec::new());
        let selection = stage.selection();
        let input = stage.input(&selection, &[]);
        let gate_results = handle.block_on(futures::future::join_all(
            stage.selected.gates.iter().map(|gate| async {
                let mut records = Vec::new();
                let result = call::chain(gate, abi::POINT_ROUTE, &input, &mut records).await;
                (result, records)
            }),
        ));
        let mut constraint = Constraint::default();
        for ((called, answer), records) in gate_results {
            ran.extend(records);
            apply(
                &mut constraint,
                &called,
                &answer,
                req.route,
                drive.refusals,
                &stage.candidates,
            )?;
        }
        if constraint.order.is_none() && constraint.prioritize.is_none() {
            if let Some(policy) = &stage.selected.policy {
                let (called, answer) =
                    handle.block_on(call::chain(policy, abi::POINT_ROUTE, &input, &mut ran));
                apply(
                    &mut constraint,
                    &called,
                    &answer,
                    req.route,
                    drive.refusals,
                    &stage.candidates,
                )?;
            }
        }
        let kept = constraint
            .enforce(
                stage
                    .candidates
                    .iter()
                    .map(|c| (c.facts.idx, c.facts.tags.as_slice())),
            )
            .map_err(|r| {
                SessionError::HookRefused(drive.refusals.for_hook(req.route, &r.name, None, None))
            })?;
        if !constraint.restricts.is_empty() {
            constraint.keep = Some(kept);
        }
        if let Some(wants) = &wants {
            if !drive
                .members
                .as_deref_mut()
                .is_some_and(|members| members.hook_constrain(wants, constraint))
            {
                return Err(SessionError::HookPrerequisite);
            }
        }
        stage.taps(
            &stage.selected.taps.candidate,
            vec![(abi::S_STAGE, FactVal::U(abi::STAGE_CANDIDATE))],
        );
        Ok(())
    })();
    stage.report(ran);
    result?;
    // Request content is no longer needed by the synchronous runtime after its request taps own it.
    stage.projection = stage.projection.shape();
    Ok(stage)
}

fn apply(
    constraint: &mut Constraint,
    call: &super::Call,
    answer: &busbar_ports::hook::HookAnswer,
    route: u32,
    refusals: &dyn crate::refusal::RefusalMap,
    candidates: &[CandidateView],
) -> Result<(), SessionError> {
    match answer.verb {
        abi::VERB_REJECT => {
            return Err(SessionError::HookRefused(refusals.for_hook(
                route,
                &call.name,
                answer.reject_status,
                answer.message.as_deref(),
            )))
        }
        abi::VERB_RESTRICT => constraint.restricts.push(Restrict {
            tags_any: answer.restrict.iter().map(ToString::to_string).collect(),
            on_empty: call.on_empty,
            name: call.name.clone(),
        }),
        abi::VERB_PREFER | abi::VERB_PRIORITIZE => {
            let order: Vec<_> = answer
                .order
                .iter()
                .map(|index| *index as usize)
                .filter(|index| {
                    candidates
                        .iter()
                        .any(|candidate| candidate.facts.idx == *index)
                })
                .collect();
            if !order.is_empty() {
                if answer.verb == abi::VERB_PREFER {
                    constraint.order = Some(order);
                    constraint.prioritize = None;
                } else {
                    constraint.prioritize = Some(order);
                    constraint.order = None;
                }
                constraint.policy = Some(call.name.clone());
            }
        }
        _ => {}
    }
    Ok(())
}
