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
    fn response_tap(&self, status: u16, gate: bool, output: Option<u64>) {
        let outcome = if gate {
            "rejected_by_gate"
        } else if (200..300).contains(&status) {
            "ok"
        } else {
            "failed"
        };
        let mut facts = vec![
            (abi::S_STAGE, FactVal::U(abi::STAGE_RESPONSE)),
            (abi::S_STATUS, FactVal::U(status.into())),
            (abi::S_OUTCOME, FactVal::Text(outcome.into())),
        ];
        if let Some(output) = output {
            facts.push((abi::S_RESPONSE_TOKENS_OUT, FactVal::U(output)));
        }
        self.taps(&self.selected.taps.response, facts);
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
        for call in calls {
            let mut held = self.clone();
            if !facts.is_empty() {
                held.projection = held.projection.shape();
            }
            let facts = facts.clone();
            let call = Arc::clone(call);
            crate::hooks::taps::spawn_bounded_tap(async move {
                let selection = held.selection();
                let input = held.input(&selection, &facts);
                let result = call::one(&call, abi::POINT_NOTIFY, &input).await;
                held.report(vec![call::record(&call, result.as_ref().ok())]);
            });
        }
    }
}

/// Hooks for outcomes after request enforcement. No later-stage tap receives conversation bytes.
pub(crate) struct Observed<'a> {
    pub(crate) inner: &'a dyn Effects,
    pub(crate) stage: Stage,
    responded: Cell<bool>,
    output: Cell<Option<u64>>,
}
impl<'a> Observed<'a> {
    pub(crate) fn new(inner: &'a dyn Effects, stage: Stage) -> Self {
        Self {
            inner,
            stage,
            responded: Cell::new(false),
            output: Cell::new(None),
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
    fn routing(&self, attempt: u32, model: &str, remaining: Option<usize>, failed: Option<&str>) {
        let mut facts = vec![
            (abi::S_STAGE, FactVal::U(abi::STAGE_ROUTING)),
            (abi::S_ATTEMPT, FactVal::U(attempt.into())),
            (abi::S_STAGE_MODEL, FactVal::Text(model.into())),
        ];
        if let Some(remaining) = remaining {
            facts.push((abi::S_REMAINING_CANDIDATES, FactVal::U(remaining as u64)));
        }
        if let Some(failed) = failed {
            facts.push((abi::S_PREVIOUS_FAILURE, FactVal::Text(failed.into())));
        }
        self.stage.taps(&self.stage.selected.taps.routing, facts);
        self.inner.routing(attempt, model, remaining, failed);
    }
    fn observed_usage(&self, usage: &super::super::usage::SessionUsage) {
        let output = usage
            .last()
            .iter()
            .find(|reported| {
                &*reported.class == "output"
                    && reported.source == busbar_plugin_abi::plane::SRC_REPORTED
            })
            .and_then(|reported| {
                let divisor = 10_u64.pow(reported.scale);
                (reported.amount % divisor == 0).then_some(reported.amount / divisor)
            });
        self.output.set(output);
        self.inner.observed_usage(usage);
    }
    fn response(&self, status: u16) {
        if !self.responded.replace(true) {
            self.stage.response_tap(status, false, self.output.get());
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
            let (called, answer) = handle
                .block_on(call::chain(&rewrite, abi::POINT_REWRITE, &input, &mut ran))
                .map_err(|_| unavailable(req.route, drive.refusals))?;
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
                let bytes = busbar_contract::secure::SecureVec::from(bytes);
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
            stage.selected.gates.iter().map(|gate| {
                let input = &input;
                async move {
                    let mut records = Vec::new();
                    let result = call::chain(gate, abi::POINT_ROUTE, input, &mut records).await;
                    (result, records)
                }
            }),
        ));
        let mut outcomes = Vec::new();
        for (outcome, records) in gate_results {
            ran.extend(records);
            outcomes.push(outcome);
        }
        let mut judged = Vec::new();
        for outcome in outcomes {
            let (called, mut answer) =
                outcome.map_err(|_| unavailable(req.route, drive.refusals))?;
            normalize(&mut answer, &stage.candidates);
            if answer.verb == abi::VERB_REJECT {
                return Err(SessionError::HookRefused(drive.refusals.for_hook(
                    req.route,
                    &called.name,
                    answer.reject_status,
                    answer.message.as_deref(),
                )));
            }
            judged.push((called, answer));
        }
        let mut constraint = Constraint::default();
        // Restrictions are reconciled before any order.
        for (called, answer) in &judged {
            if answer.verb == abi::VERB_RESTRICT {
                apply(
                    &mut constraint,
                    called,
                    answer,
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
            .map_err(|_| unavailable(req.route, drive.refusals))?;
        stage
            .candidates
            .retain(|candidate| kept.contains(&candidate.facts.idx));
        for (called, answer) in &judged {
            if matches!(answer.verb, abi::VERB_PREFER | abi::VERB_PRIORITIZE) {
                apply(
                    &mut constraint,
                    called,
                    answer,
                    req.route,
                    drive.refusals,
                    &stage.candidates,
                )?;
            }
        }
        let selection = stage.selection();
        let input = stage.input(&selection, &[]);
        if constraint.order.is_none() {
            if let Some(policy) = &stage.selected.policy {
                let (called, mut answer) = handle
                    .block_on(call::chain(policy, abi::POINT_ROUTE, &input, &mut ran))
                    .map_err(|_| unavailable(req.route, drive.refusals))?;
                normalize(&mut answer, &stage.candidates);
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
            .map_err(|_| unavailable(req.route, drive.refusals))?;
        if !constraint.restricts.is_empty() {
            stage
                .candidates
                .retain(|candidate| kept.contains(&candidate.facts.idx));
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
            vec![
                (abi::S_STAGE, FactVal::U(abi::STAGE_CANDIDATE)),
                (
                    abi::S_REMAINING_CANDIDATES,
                    FactVal::U(stage.candidates.len() as u64),
                ),
            ],
        );
        Ok(())
    })();
    stage.report(ran);
    if let Err(SessionError::HookRefused(refusal)) = &result {
        stage.response_tap(refusal.status, true, None);
    }
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
            tags_any: answer
                .restrict
                .iter()
                .map(|tag| tag.trim())
                .filter(|tag| !tag.is_empty())
                .map(str::to_owned)
                .collect(),
            on_empty: call.on_empty.clone(),
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
                } else {
                    constraint.prioritize = Some(order);
                }
                constraint.policy = Some(call.name.clone());
            } else if answer.verb == abi::VERB_PREFER {
                constraint.order = None;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize(answer: &mut busbar_ports::hook::HookAnswer, candidates: &[CandidateView]) {
    if matches!(answer.verb, abi::VERB_PREFER | abi::VERB_PRIORITIZE) {
        let mut seen = Vec::new();
        answer.order.retain(|index| {
            let valid = candidates
                .iter()
                .any(|candidate| candidate.facts.idx == *index as usize)
                && !seen.contains(index);
            if valid {
                seen.push(*index);
            }
            valid
        });
        if answer.order.is_empty() {
            answer.verb = abi::VERB_ABSTAIN;
        }
    }
}

fn unavailable(route: u32, refusals: &dyn crate::refusal::RefusalMap) -> SessionError {
    SessionError::HookRefused(refusals.for_port(
        route,
        &PortError::Failed {
            code: busbar_plugin_abi::fail::failed::F_UNAVAILABLE,
            text: "a required native hook could not complete".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        },
    ))
}
