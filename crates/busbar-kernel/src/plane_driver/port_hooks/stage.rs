// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::super::hooks::{Constraint, HooksRan, Restrict};
use super::super::port_serve::Drive;
use super::super::port_session::{Answer, Calls, ClientSink, Effects, Owned, SessionError, Task};
use super::super::port_upstream::{Members, UpSend, Wants};
use super::{
    call, CandidateView, Candidates, Invocation, Projection, RouteCounters, Selected, Selection,
};
use crate::host_services::InvocationContext;
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::{plane::PlaneIn, FactVal, PortError};

pub(crate) use super::super::port_session::Buffered;

/// One request's hook stage. What a hook call or a tap may keep after the request has moved on
/// (the selection, the scope, the identity, the candidates, the quantities) is held shared, so a
/// call's worker and a tap's copy of the stage take a count of each and copy none of it.
#[derive(Clone)]
pub(crate) struct Stage {
    selected: Arc<Selected>,
    projection: Projection,
    candidates: Candidates,
    quantities: Arc<[(Box<str>, f64)]>,
    scope: Arc<super::super::RoutedScope>,
    dialect: Arc<str>,
    principal: Option<super::super::port_auth::Subject>,
    identity: Arc<busbar_contract::secure::SecureVec>,
    request_id: u64,
    context: InvocationContext,
    journal: Option<Arc<dyn super::HookJournal>>,
    unit: busbar_contract::UnitKey,
}
impl Stage {
    /// The stage as one hook call is shown it; `stage` is a tap's facts, absent on a request call.
    fn input<'a>(&'a self, stage: Option<&'a Arc<call::StageFacts>>) -> call::Input<'a> {
        call::Input {
            projection: &self.projection,
            selected: &self.selected,
            scope: &self.scope,
            dialect: &self.dialect,
            principal: self.principal.as_ref(),
            request_id: self.request_id,
            identity: Some(&self.identity),
            candidates: &self.candidates,
            quantities: &self.quantities,
            stage,
            context: &self.context,
        }
    }
    fn response_tap(&self, status: u16, gate: bool, output: Option<u64>) {
        // No response tap is configured: no facts are made.
        if self.selected.taps.response.is_empty() {
            return;
        }
        let outcome = if gate {
            "rejected_by_gate"
        } else if (200..300).contains(&status) {
            "ok"
        } else {
            "failed"
        };
        let mut facts = call::StageFacts::new();
        facts.push((abi::S_STAGE, FactVal::U(abi::STAGE_RESPONSE)));
        facts.push((abi::S_STATUS, FactVal::U(status.into())));
        facts.push((abi::S_OUTCOME, FactVal::Text(outcome.into())));
        if let Some(output) = output {
            facts.push((abi::S_RESPONSE_TOKENS_OUT, FactVal::U(output)));
        }
        self.taps(&self.selected.taps.response, facts);
    }
    fn report(&self, hooks: &[busbar_kernel_audit::record::HookApplied]) {
        if let Some(journal) = &self.journal {
            journal.hooks_ran(&HooksRan {
                unit: self.unit,
                hooks,
            });
        }
    }
    /// Every tap of one stage event shares the event's one list of facts.
    fn taps(&self, calls: &[Arc<super::Call>], facts: call::StageFacts) {
        if calls.is_empty() {
            return;
        }
        let shared = (!facts.is_empty()).then(|| Arc::new(facts));
        for call in calls {
            self.tap(call, shared.clone());
        }
    }
    fn tap(&self, call: &Arc<super::Call>, facts: Option<Arc<call::StageFacts>>) {
        let mut held = self.clone();
        if facts.is_some() {
            held.projection.shape();
        }
        let call = Arc::clone(call);
        crate::hooks::taps::spawn_bounded_tap(async move {
            let input = held.input(facts.as_ref());
            let result = call::one(&call, abi::POINT_NOTIFY, &input).await;
            held.report(&[call::record(
                &call,
                result.as_ref().ok().map(|reply| &**reply),
            )]);
        });
    }
}

/// Hooks for outcomes after request enforcement. No later-stage tap receives conversation bytes.
pub(crate) struct Observed<'a> {
    pub(crate) inner: &'a dyn Effects,
    pub(crate) stage: Stage,
    responded: Owned<bool>,
    output: Owned<Option<u64>>,
}
impl<'a> Observed<'a> {
    pub(crate) fn new(inner: &'a dyn Effects, stage: Stage) -> Self {
        Self {
            inner,
            stage,
            responded: Owned::new(false),
            output: Owned::new(None),
        }
    }
}
impl Effects for Observed<'_> {
    fn admission_owner(&self) -> Option<&Arc<super::super::port_admission::Pending>> {
        self.inner.admission_owner()
    }
    fn data(&self) -> Option<&Arc<crate::auth::native_data::NativeDataPending>> {
        self.inner.data()
    }
    fn admission(&self) -> Option<&super::super::port_admission::Pending> {
        self.inner.admission()
    }
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
        // The facts (and their copies of the model and the failure) are made only for a
        // configured routing tap.
        if !self.stage.selected.taps.routing.is_empty() {
            let mut facts = call::StageFacts::new();
            facts.push((abi::S_STAGE, FactVal::U(abi::STAGE_ROUTING)));
            facts.push((abi::S_ATTEMPT, FactVal::U(attempt.into())));
            facts.push((abi::S_STAGE_MODEL, FactVal::Text(model.into())));
            if let Some(remaining) = remaining {
                facts.push((abi::S_REMAINING_CANDIDATES, FactVal::U(remaining as u64)));
            }
            if let Some(failed) = failed {
                facts.push((abi::S_PREVIOUS_FAILURE, FactVal::Text(failed.into())));
            }
            self.stage.taps(&self.stage.selected.taps.routing, facts);
        }
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

pub(crate) async fn enforce<K: Calls + ?Sized, M: Members, S: UpSend>(
    invocation: &Invocation,
    task: &mut Task<'_, K>,
    answers: &mut Vec<Answer>,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_, M, S>,
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
        principal: invocation
            .principal
            .as_ref()
            .map(super::super::port_auth::Subject::as_str),
        key: context.principal().map(AsRef::as_ref),
        request_id: req.request_id,
        now_s: invocation.now_s,
    };
    let selected = invocation
        .binder
        .select(&selection)
        .map_err(|_| SessionError::HookPrerequisite)?;
    let mut stage = Stage {
        selected: Arc::new(selected),
        projection,
        candidates: Candidates::new(candidates),
        quantities: Arc::default(),
        scope: Arc::new(scope),
        dialect: drive.dialect.into(),
        principal: invocation.principal.clone(),
        identity: Arc::new(req.identity.to_vec().into()),
        request_id: req.request_id,
        context,
        journal: invocation.journal.clone(),
        unit: invocation.unit,
    };
    let mut ran: Vec<busbar_kernel_audit::record::HookApplied> = Vec::new();
    let result = async {
        // The stage is rewritten inside the loop, so each rewrite call is held by its own Arc.
        for at in 0..stage.selected.rewrites.len() {
            let rewrite = Arc::clone(&stage.selected.rewrites[at]);
            let input = stage.input(None);
            let (called, mut answer) = call::chain(&rewrite, abi::POINT_REWRITE, &input, &mut ran)
                .await
                .map_err(|_| unavailable(req.route, drive.refusals))?;
            if answer.verb == abi::VERB_REJECT {
                return Err(rejected(
                    &called,
                    &answer,
                    req.route,
                    drive.refusals,
                    stage.selected.counters.as_deref(),
                ));
            }
            if answer.verb != abi::VERB_REWRITE || !called.prompt.can_rewrite() {
                continue;
            }
            if let Some(bytes) = answer.rewrite.take() {
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
        // The quantities are worked out once, here, and moved into the stage's one shared list
        // (a rewrite's timed-out worker that still holds the empty one keeps it).
        let mut quantities = Vec::with_capacity(invocation.classes.len());
        super::quantities(
            &invocation.classes,
            &stage.projection.expects,
            &mut quantities,
        )?;
        stage.quantities = Arc::from(quantities);
        stage.taps(&stage.selected.taps.request, call::StageFacts::new());
        let input = stage.input(None);
        let gate_results = futures::future::join_all(stage.selected.gates.iter().map(|gate| {
            let input = &input;
            async move {
                // One gate's records: its own and its fallbacks', in this gate's frame.
                let mut records =
                    smallvec::SmallVec::<[busbar_kernel_audit::record::HookApplied; 2]>::new();
                let result = call::chain(gate, abi::POINT_ROUTE, input, &mut records).await;
                (result, records)
            }
        }))
        .await;
        let mut outcomes = smallvec::SmallVec::<[_; 8]>::new();
        for (outcome, records) in gate_results {
            ran.extend(records);
            outcomes.push(outcome);
        }
        let mut judged = smallvec::SmallVec::<[_; 8]>::new();
        for outcome in outcomes {
            let (called, mut answer) =
                outcome.map_err(|_| unavailable(req.route, drive.refusals))?;
            normalize(&mut answer, &stage.candidates);
            if answer.verb == abi::VERB_REJECT {
                return Err(rejected(
                    &called,
                    &answer,
                    req.route,
                    drive.refusals,
                    stage.selected.counters.as_deref(),
                ));
            }
            judged.push((called, answer));
        }
        let mut constraint = Constraint::default();
        // Restrictions are reconciled before any order.
        for (called, answer) in &mut judged {
            if answer.verb == abi::VERB_RESTRICT {
                apply(
                    &mut constraint,
                    called,
                    answer,
                    req.route,
                    drive.refusals,
                    &stage.candidates,
                    stage.selected.counters.as_deref(),
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
        stage.candidates.keep_only(&kept);
        for (called, answer) in &mut judged {
            if matches!(answer.verb, abi::VERB_PREFER | abi::VERB_PRIORITIZE) {
                apply(
                    &mut constraint,
                    called,
                    answer,
                    req.route,
                    drive.refusals,
                    &stage.candidates,
                    stage.selected.counters.as_deref(),
                )?;
            }
        }
        let input = stage.input(None);
        if constraint.order.is_none() {
            if let Some(policy) = &stage.selected.policy {
                let (called, mut answer) = call::chain(policy, abi::POINT_ROUTE, &input, &mut ran)
                    .await
                    .map_err(|_| unavailable(req.route, drive.refusals))?;
                normalize(&mut answer, &stage.candidates);
                apply(
                    &mut constraint,
                    &called,
                    &mut answer,
                    req.route,
                    drive.refusals,
                    &stage.candidates,
                    stage.selected.counters.as_deref(),
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
            stage.candidates.keep_only(&kept);
            constraint.keep = Some(kept);
        }
        let ordered = constraint.order.is_some() || constraint.prioritize.is_some();
        let decided = constraint.policy.clone().filter(|_| ordered);
        if let Some(wants) = &wants {
            if !drive
                .members
                .as_deref_mut()
                .is_some_and(|members| members.hook_constrain(wants, constraint))
            {
                return Err(SessionError::HookPrerequisite);
            }
        }
        if let (Some(counters), Some(decider)) = (stage.selected.counters.as_deref(), &decided) {
            counters.selected(decider);
        }
        // The facts are made only for a configured candidate tap.
        if !stage.selected.taps.candidate.is_empty() {
            let mut facts = call::StageFacts::new();
            facts.push((abi::S_STAGE, FactVal::U(abi::STAGE_CANDIDATE)));
            facts.push((
                abi::S_REMAINING_CANDIDATES,
                FactVal::U(stage.candidates.len() as u64),
            ));
            stage.taps(&stage.selected.taps.candidate, facts);
        }
        Ok(())
    }
    .await;
    stage.report(&ran);
    if let Err(SessionError::HookRefused(refusal)) = &result {
        stage.response_tap(refusal.status, true, None);
    }
    result?;
    // Request content is no longer needed by the synchronous runtime after its request taps own it.
    stage.projection.shape();
    Ok(stage)
}

/// A restricting hook's own tags, as its restrict keeps them: moved out of the answer, each
/// without surrounding space, the empty ones dropped. A tag is copied only when it has space to
/// trim off.
fn restrict_tags(mut tags: Vec<Box<str>>) -> Vec<Box<str>> {
    tags.retain_mut(|tag| {
        let kept = tag.trim();
        if kept.len() != tag.len() {
            *tag = Box::from(kept);
        }
        !tag.is_empty()
    });
    tags
}

fn apply(
    constraint: &mut Constraint,
    call: &super::Call,
    answer: &mut busbar_ports::hook::HookAnswer,
    route: u32,
    refusals: &dyn crate::refusal::RefusalMap,
    candidates: &[CandidateView],
    counters: Option<&RouteCounters>,
) -> Result<(), SessionError> {
    match answer.verb {
        abi::VERB_REJECT => return Err(rejected(call, answer, route, refusals, counters)),
        abi::VERB_RESTRICT => {
            constraint.restricts.push(Restrict {
                tags_any: restrict_tags(std::mem::take(&mut answer.restrict)),
                on_empty: call.on_empty.clone(),
                name: call.name.clone(),
            });
        }
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
                constraint.policy = Some(call.decider().clone());
            } else if answer.verb == abi::VERB_PREFER {
                constraint.order = None;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A VERB_REJECT: the client refusal, counted under the rejecting call's deciding name at the
/// refusal's status.
fn rejected(
    call: &super::Call,
    answer: &busbar_ports::hook::HookAnswer,
    route: u32,
    refusals: &dyn crate::refusal::RefusalMap,
    counters: Option<&RouteCounters>,
) -> SessionError {
    let refusal = refusals.for_hook(
        route,
        &call.name,
        answer.reject_status,
        answer.message.as_deref(),
    );
    if let Some(counters) = counters {
        counters.rejected(call.decider(), refusal.status);
    }
    SessionError::HookRefused(refusal)
}

fn normalize(answer: &mut busbar_ports::hook::HookAnswer, candidates: &[CandidateView]) {
    if matches!(answer.verb, abi::VERB_PREFER | abi::VERB_PRIORITIZE) {
        let mut seen = smallvec::SmallVec::<[_; 16]>::new();
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

#[cfg(test)]
mod tests {
    use super::restrict_tags;

    #[test]
    fn a_restricts_tags_are_the_hooks_own_trimmed_with_the_empty_ones_dropped() {
        let tags: Vec<Box<str>> = vec![
            " baa ".into(),
            "".into(),
            "gpu".into(),
            "   ".into(),
            "\teu\n".into(),
        ];
        let untouched = tags[2].as_ptr();
        let kept = restrict_tags(tags);
        assert_eq!(
            kept,
            vec![Box::<str>::from("baa"), "gpu".into(), "eu".into()]
        );
        assert_eq!(
            kept[1].as_ptr(),
            untouched,
            "a tag with nothing to trim is moved, never copied"
        );
    }

    /// ci/owed/cut-root SECURITY-OWED `a_global_gate_refuses_a_decisions_request_before_its_dial`
    /// and MONEY-OWED `a_screened_veto_through_the_node_admits_nothing`, the decision half: a
    /// gate hook's REJECT ends the stage as the caller's refusal (`SessionError::HookRefused`,
    /// which the port serves as a refusal and never as a dial: `port.rs`, `Served::Refused`). The
    /// refusal is core's policy refusal at the hook's own status when that is a client status,
    /// and 403 otherwise: a hook cannot make core answer success, a redirect or a server fault.
    /// Its message reaches the caller only when the operator exposed that hook by name.
    #[test]
    fn a_rejecting_gate_ends_the_stage_as_the_callers_policy_refusal() {
        use super::rejected;
        use crate::config::{PromptAccess, UserAccess};
        use crate::plane_driver::port_session::SessionError;
        use crate::refusal::CoreRefusals;
        use busbar_plugin_abi::fail::refused::R_POLICY;
        use busbar_plugin_abi::kinds::hook::hook as abi;
        use busbar_ports::hook::{HookAnswer, HookCall, HookPort, HookView};
        use std::sync::Arc;

        struct Silent;
        impl HookPort for Silent {
            fn points(&self) -> u32 {
                1 << abi::POINT_ROUTE
            }
            fn facts(&self) -> u64 {
                0
            }
            fn on<'a>(
                &'a self,
                _: busbar_ports::CallCx,
                _: u32,
                _: &'a HookView<'a>,
            ) -> HookCall<'a> {
                unreachable!("the refusal is built from the answer; the hook is not called again")
            }
        }
        let call = crate::plane_driver::port_hooks::tests::configured(
            Arc::new(Silent),
            PromptAccess::No,
            UserAccess::No,
        );
        let refusals = CoreRefusals::new();
        let reject = |status: Option<u16>| HookAnswer {
            verb: abi::VERB_REJECT,
            reject_status: status,
            order: Vec::new(),
            restrict: Vec::new(),
            message: Some("the hook's own words".into()),
            rewrite: None,
        };
        for (asked, served) in [
            (Some(409), 409),
            (Some(403), 403),
            (Some(451), 451),
            (None, 403),
            (Some(200), 403),
            (Some(302), 403),
            (Some(500), 403),
            (Some(599), 403),
        ] {
            let SessionError::HookRefused(refusal) =
                rejected(&call, &reject(asked), 7, &refusals, None)
            else {
                panic!("a REJECT is the caller's refusal (asked {asked:?})");
            };
            assert_eq!(refusal.status, served, "asked {asked:?}");
            assert_eq!(refusal.code, R_POLICY, "asked {asked:?}");
            assert_eq!(
                refusal.text, "the request was refused by policy",
                "a hook the operator did not expose adds nothing to core's text (asked {asked:?})"
            );
        }
    }
}
