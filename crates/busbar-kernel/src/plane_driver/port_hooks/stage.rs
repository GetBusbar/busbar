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
use crate::host_services::{HookGrant, InvocationContext};
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
    request_id: u64,
    context: InvocationContext,
    journal: Option<Arc<dyn super::HookJournal>>,
    unit: busbar_contract::UnitKey,
    /// The hook records of a stage that ran before its request's unit was open ([`Early`]);
    /// `None` for a stage whose unit was open before it ran, and for a node that keeps no journal.
    early: Option<Arc<Early>>,
}

/// Where a hook stage stands to its request's unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum When {
    /// The request's walk is resolved and its money has not been asked
    /// (`port_admission::Pending::resolve_walk`): a hook that refuses here has spoken before any
    /// unit is opened and before anything is charged.
    BeforeMoney,
    /// The request already runs as an open unit.
    UnitOpen,
}

/// The hook records made before the request's unit is open. The journal seals a hook's record
/// under its OPEN unit and has nowhere to put one for a unit it does not hold, and a stage that
/// runs before the request's money has no open unit yet: its records wait here and are handed
/// to the journal, in the order they were made, when the unit opens ([`Stage::unit_opened`]).
/// `Some`: still waiting. `None`: the unit is open and a record goes straight to the journal. A
/// request refused before its unit opened leaves them here: it has no unit record to seal them
/// under.
struct Early(std::sync::Mutex<Option<Vec<busbar_kernel_audit::record::HookApplied>>>);

impl Early {
    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<Vec<busbar_kernel_audit::record::HookApplied>>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Stage {
    /// The stage as one hook call is shown it; `stage` is a tap's facts, absent on a request call.
    /// `grant`: a tap's authority, taken when it was fired.
    fn input<'a>(
        &'a self,
        stage: Option<&'a Arc<call::StageFacts>>,
        grant: Option<&'a HookGrant>,
    ) -> call::Input<'a> {
        call::Input {
            projection: &self.projection,
            selected: &self.selected,
            scope: &self.scope,
            dialect: &self.dialect,
            principal: self.principal.as_ref(),
            request_id: self.request_id,
            grant,
            candidates: &self.candidates,
            quantities: &self.quantities,
            stage,
            context: &self.context,
        }
    }
    /// The response stage, as v1.5.5 gave it: the status the client was answered and the outcome
    /// (`ok`, `failed`, or `rejected_by_gate` for a refusal a hook itself made).
    fn response_tap(&self, status: u16, gate: bool, granted: Option<&HookGrant>) {
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
        self.taps(&self.selected.taps.response, facts, granted);
    }
    /// The authority to tell the response taps how the request ended if its money refuses it.
    /// Taken while the request still allows its hooks, before the money is asked: a money
    /// refusal ends the request's admission, and nothing can be taken after it. `None` when no
    /// response tap is configured: nothing is taken for a stage nobody listens to.
    pub(crate) fn completion(&self) -> Option<HookGrant> {
        if self.selected.taps.response.is_empty() {
            return None;
        }
        self.context.hook_grant()
    }
    /// The request's hooks allowed it and its money then refused it at `status`: the response
    /// taps, which saw the request, are told how it ended (`failed`). v1.5.5 asked the money
    /// first and so never showed a hook such a request; now that a hook is heard before the
    /// money, a tap that saw the request stage is not left without its completion.
    pub(crate) fn money_refused(&self, status: u16, completion: Option<&HookGrant>) {
        if completion.is_some() {
            self.response_tap(status, false, completion);
        }
    }
    fn report(&self, hooks: &[busbar_kernel_audit::record::HookApplied]) {
        let Some(journal) = &self.journal else {
            return;
        };
        if let Some(early) = &self.early {
            if let Some(waiting) = early.lock().as_mut() {
                waiting.extend_from_slice(hooks);
                return;
            }
        }
        journal.hooks_ran(&HooksRan {
            unit: self.unit,
            hooks,
        });
    }
    /// The request's unit is open: the records its hooks made before that are handed to the
    /// journal, in the order they were made, and every later one goes straight to it. The
    /// records are handed over under their lock, so a tap that finishes meanwhile is recorded
    /// after them, never before and never twice.
    pub(crate) fn unit_opened(&self) {
        let Some(early) = &self.early else {
            return;
        };
        let mut waiting = early.lock();
        let Some(records) = waiting.take() else {
            return;
        };
        if let (Some(journal), false) = (&self.journal, records.is_empty()) {
            journal.hooks_ran(&HooksRan {
                unit: self.unit,
                hooks: &records,
            });
        }
    }
    /// Every tap of one stage event shares the event's one list of facts and its one authority:
    /// `granted` when it was taken earlier, else the request's own, taken now, while the request
    /// allows its hooks. The notifications themselves run detached and may start after the
    /// request has ended. A request that allows no hook fires none, and says so in its record.
    fn taps(
        &self,
        calls: &[Arc<super::Call>],
        facts: call::StageFacts,
        granted: Option<&HookGrant>,
    ) {
        if calls.is_empty() {
            return;
        }
        let Some(grant) = granted.cloned().or_else(|| self.context.hook_grant()) else {
            for call in calls {
                self.report(&[call::record(call, None)]);
            }
            return;
        };
        let shared = (!facts.is_empty()).then(|| Arc::new(facts));
        for call in calls {
            self.tap(call, shared.clone(), grant.clone());
        }
    }
    fn tap(&self, call: &Arc<super::Call>, facts: Option<Arc<call::StageFacts>>, grant: HookGrant) {
        let mut held = self.clone();
        if facts.is_some() {
            held.projection.shape();
        }
        let call = Arc::clone(call);
        crate::hooks::taps::spawn_bounded_tap(async move {
            let input = held.input(facts.as_ref(), Some(&grant));
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
}
impl<'a> Observed<'a> {
    pub(crate) fn new(inner: &'a dyn Effects, stage: Stage) -> Self {
        Self {
            inner,
            stage,
            responded: Owned::new(false),
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
            self.stage
                .taps(&self.stage.selected.taps.routing, facts, None);
        }
        self.inner.routing(attempt, model, remaining, failed);
    }
    // Hook 3.0 retired the response stage's output-token fact (no shipped hook read it and
    // v1.5.5's response stage carried the outcome and the status only), so the stage keeps no
    // count of the usage it is shown.
    fn observed_usage(&self, usage: &super::super::usage::SessionUsage) {
        self.inner.observed_usage(usage);
    }
    fn response(&self, status: u16) {
        if !self.responded.replace(true) {
            self.stage.response_tap(status, false, None);
        }
        self.inner.response(status);
    }
}

/// One request's hook stage, in v1.5.5's order: each rewrite in turn (a rewrite the operator
/// granted `rw` is applied to the plane's request), the request taps, the gates at once and
/// judged in their priority order (a reject first, then every restriction, then an order), the
/// pool's routing policy when no gate ordered, the candidate taps. A hook that refuses ends the
/// stage as the caller's refusal at the hook's own status; one that fails or times out is
/// answered by its fallbacks and then by the operator's `on_error` (`weighted`: the request goes
/// on as if the hook had no opinion; `reject`: 503-class refusal; `first`: the candidates in
/// their configured order), exactly as v1.5.5 did.
///
/// `when` says where the request's unit stands. [`When::BeforeMoney`]: nothing is opened or
/// charged yet, and a refusal here leaves it so.
pub(crate) async fn enforce<K: Calls + ?Sized, M: Members, S: UpSend>(
    invocation: &Invocation,
    task: &mut Task<'_, K>,
    answers: &mut Vec<Answer>,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_, M, S>,
    effects: &dyn Effects,
    when: When,
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
        request_id: req.request_id,
        context,
        journal: invocation.journal.clone(),
        unit: invocation.unit,
        // Only a journal has records to keep, and only a unit that is not open yet makes them
        // wait.
        early: (when == When::BeforeMoney && invocation.journal.is_some())
            .then(|| Arc::new(Early(std::sync::Mutex::new(Some(Vec::new()))))),
    };
    let mut ran: Vec<busbar_kernel_audit::record::HookApplied> = Vec::new();
    let result = async {
        // The stage is rewritten inside the loop, so each rewrite call is held by its own Arc.
        for at in 0..stage.selected.rewrites.len() {
            let rewrite = Arc::clone(&stage.selected.rewrites[at]);
            let input = stage.input(None, None);
            let (called, mut answer) = call::chain(&rewrite, abi::POINT_REWRITE, &input, &mut ran)
                .await
                .map_err(|_| unavailable())?;
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
                        // Before the money, the request's walk is already resolved and the
                        // key's grant of it judged: a rewrite cannot restate the FORWARD onto
                        // another walk. (With the unit open the task checks the same against
                        // the admitted request.)
                        if when == When::BeforeMoney {
                            if let Some(forward) = &answer.forward {
                                let stated = Wants::from_facts(&forward.wants);
                                if !wants.as_ref().is_some_and(|resolved| {
                                    resolved.model == stated.model
                                        && resolved.upstream == stated.upstream
                                }) {
                                    return Err(SessionError::NotDriven);
                                }
                            }
                        }
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
        stage.taps(&stage.selected.taps.request, call::StageFacts::new(), None);
        let input = stage.input(None, None);
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
            let (called, mut answer) = outcome.map_err(|_| unavailable())?;
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
            .map_err(|_| unavailable())?;
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
        let input = stage.input(None, None);
        if constraint.order.is_none() {
            if let Some(policy) = &stage.selected.policy {
                let (called, mut answer) = call::chain(policy, abi::POINT_ROUTE, &input, &mut ran)
                    .await
                    .map_err(|_| unavailable())?;
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
            .map_err(|_| unavailable())?;
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
            stage.taps(&stage.selected.taps.candidate, facts, None);
        }
        Ok(())
    }
    .await;
    stage.report(&ran);
    if let Err(SessionError::HookRefused(refusal)) = &result {
        // The synthetic completion that lets an audit tap see a denial. Its authority is taken
        // here, while the refused request still allows its hooks: the caller ends the request's
        // admission as soon as this returns.
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

/// A hook the operator made required (`on_error: reject`, or a restriction whose `on_empty` is
/// `reject`) could not decide: v1.5.5's answer, a 503 with its own words. It is core's refusal,
/// never the hook's: nothing the hook said reaches the caller. (The port map's reading of an
/// unavailable backend is 502, which is an upstream's failure and not this.)
fn unavailable() -> SessionError {
    SessionError::HookRefused(crate::refusal::ClientRefusal {
        status: 503,
        code: busbar_plugin_abi::fail::failed::F_UNAVAILABLE,
        text: std::borrow::Cow::Borrowed(
            "A required gate could not complete. Please retry shortly.",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::restrict_tags;

    /// A hook's record is sealed under its request's OPEN unit. A stage that runs before the
    /// request's money has no open unit yet: its records wait and reach the journal, in the
    /// order they were made, when the unit opens, once; a tap's copy of the stage shares the
    /// wait. A stage whose unit was open before it ran records at once, as it always did.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_made_before_the_unit_opens_reach_the_journal_when_it_opens_and_not_before() {
        use super::{Early, Stage};
        use crate::plane_driver::hooks::{HookJournal, HooksRan};
        use crate::plane_driver::port_hooks::tests::Fixture;
        use crate::plane_driver::port_hooks::{Candidates, Projection};
        use busbar_kernel_audit::record::{HookApplied, HookHead};
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Kept(Mutex<Vec<(u64, String)>>);
        impl HookJournal for Kept {
            fn hooks_ran(&self, record: &HooksRan<'_>) {
                self.0.lock().unwrap().extend(
                    record
                        .hooks
                        .iter()
                        .map(|hook| (record.unit.get(), hook.hook.as_str().to_owned())),
                );
            }
        }
        let fixture = Fixture::new();
        let row = |name: &str| HookApplied {
            hook: busbar_contract::kept::Text::from(Arc::<str>::from(name)),
            head: HookHead::Pass,
            failed: false,
        };
        let stage = |journal: &Arc<Kept>, before_money: bool| Stage {
            selected: Arc::new(fixture.selected.clone()),
            projection: Projection::default(),
            candidates: Candidates::new(Vec::new()),
            quantities: Arc::default(),
            scope: Arc::default(),
            dialect: Arc::from("test"),
            principal: None,
            request_id: 7,
            context: fixture.context.clone(),
            journal: Some(journal.clone()),
            unit: busbar_contract::UnitKey::new(7),
            early: before_money.then(|| Arc::new(Early(Mutex::new(Some(Vec::new()))))),
        };
        let seen = |journal: &Kept| {
            journal
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|(unit, name)| format!("{unit}:{name}"))
                .collect::<Vec<_>>()
        };

        let journal = Arc::new(Kept::default());
        let early = stage(&journal, true);
        let tap = early.clone();
        early.report(&[row("gate")]);
        tap.report(&[row("request-tap")]);
        assert!(
            seen(&journal).is_empty(),
            "no unit is open: nothing is sealed under one"
        );
        early.unit_opened();
        assert_eq!(seen(&journal), ["7:gate", "7:request-tap"]);
        tap.report(&[row("response-tap")]);
        early.unit_opened();
        assert_eq!(
            seen(&journal),
            ["7:gate", "7:request-tap", "7:response-tap"],
            "after the unit opens a record goes straight to the journal, once"
        );

        let journal = Arc::new(Kept::default());
        let open = stage(&journal, false);
        open.report(&[row("gate")]);
        assert_eq!(seen(&journal), ["7:gate"]);
        open.unit_opened();
        assert_eq!(seen(&journal), ["7:gate"]);
    }

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
