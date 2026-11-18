// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use busbar_contract::secure::SecureVec;
use busbar_kernel_audit::record::{HookApplied, HookHead};
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::hook::{BudgetIn, CandidateIn, CostTermIn, HookAnswer, HookCall, HookView};
use busbar_ports::{CallCx, FactRef, FactVal};

use super::super::port_auth::Subject;
use super::super::RoutedScope;
use super::{Call, CandidateView, Projection, Selected};

/// One stage event's facts (a tap's): at most five today, held without a list of their own.
pub(super) type StageFacts = smallvec::SmallVec<[(u32, FactVal); 6]>;

/// What one hook call is shown. Everything that can outlive the caller (a timed-out hook keeps
/// running) is held shared by its owner, so the call's worker takes a count of each and copies
/// none of it.
pub(super) struct Input<'a> {
    pub projection: &'a Projection,
    pub selected: &'a Arc<Selected>,
    pub scope: &'a Arc<RoutedScope>,
    pub dialect: &'a Arc<str>,
    pub principal: Option<&'a Subject>,
    pub request_id: u64,
    /// The admitted identity; `None` only in the worker of a call not granted it.
    pub identity: Option<&'a Arc<SecureVec>>,
    pub candidates: &'a Arc<Vec<CandidateView>>,
    pub quantities: &'a Arc<Vec<(Box<str>, f64)>>,
    /// A stage tap's facts; `None` on a request-stage call.
    pub stage: Option<&'a Arc<StageFacts>>,
    pub context: &'a crate::host_services::InvocationContext,
}

impl<'a> Input<'a> {
    fn stage(&self) -> &'a [(u32, FactVal)] {
        self.stage.map_or(&[], |facts| facts.as_slice())
    }
}

/// How many candidates, tags and cost terms per candidate, and budget buckets one hook view lays
/// out in the call's own frame; a larger pool spills to the heap.
const CANDIDATES_INLINE: usize = 8;
const TAGS_INLINE: usize = 4;
const TERMS_INLINE: usize = 4;
const BUDGETS_INLINE: usize = 4;
type Tags<'a> = smallvec::SmallVec<[&'a str; TAGS_INLINE]>;
type Terms<'a> = smallvec::SmallVec<[CostTermIn<'a>; TERMS_INLINE]>;

/// Plugin rewrite bytes remain wiping-owned even when an abandoned worker or a gate drops its reply.
pub(super) struct Reply(HookAnswer);
impl std::ops::Deref for Reply {
    type Target = HookAnswer;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Reply {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        if let Some(bytes) = self.0.rewrite.as_mut() {
            busbar_contract::abi::sdk::wipe::wipe_bytes(bytes);
        }
    }
}

pub(super) enum Failed {
    Unconfirmed,
    Unprojected,
    Port,
}

fn ppm(value: f64) -> u32 {
    if !value.is_finite() {
        return 0;
    }
    (value.clamp(0.0, 1.0) * 1_000_000.0).round() as u32
}

/// Each actual call has its own grants and confirmed content read, including fallbacks.
pub(super) async fn one(call: &Arc<Call>, point: u32, input: &Input<'_>) -> Result<Reply, Failed> {
    prepare(call, point, input).await
}

async fn prepare(call: &Arc<Call>, point: u32, input: &Input<'_>) -> Result<Reply, Failed> {
    let deadline = Instant::now() + call.timeout;
    if call.port.points() & (1 << point) == 0 {
        return Err(Failed::Port);
    }
    let facts = call.port.facts();
    let content =
        input.stage.is_none() && call.prompt.sends_prompt() && facts & abi::FB_WANTS_PROMPT != 0;
    let identity = call.user.sends_user() && facts & abi::FB_WANTS_IDENTITY != 0;
    if content && input.projection.conversation.is_none() {
        return Err(Failed::Unprojected);
    }
    if content || identity {
        tokio::time::timeout_at(
            deadline.into(),
            (input.selected.reads)(
                &[&call.name],
                input.principal.map(Subject::as_str),
                &**input.dialect,
                identity,
            ),
        )
        .await
        .map_err(|_| Failed::Unconfirmed)?
        .map_err(|_| Failed::Unconfirmed)?;
    }
    // Both synchronous and I/O hooks run off the calling executor. The worker's input shares
    // what the request holds (a count of each, no copy) and retains it, with its wiping content
    // and its exact generation, until a timed-out worker actually returns. A call is lent the
    // conversation and the identity only when it is granted them.
    let projection = Projection {
        facts: input
            .projection
            .facts
            .iter()
            .filter(|(key, _)| identity || *key != busbar_plugin_abi::fail::fact::PJ_END_USER)
            .cloned()
            .collect(),
        conversation: if content {
            input.projection.conversation.clone()
        } else {
            None
        },
        expects: Vec::new(),
    };
    let selected = Arc::clone(input.selected);
    let scope = Arc::clone(input.scope);
    let dialect = Arc::clone(input.dialect);
    let principal = input.principal.cloned();
    let request_id = input.request_id;
    let identity = if identity {
        input.identity.cloned()
    } else {
        None
    };
    let candidates = Arc::clone(input.candidates);
    let quantities = Arc::clone(input.quantities);
    let stage = input.stage.cloned();
    let context = input.context.clone();
    let call = Arc::clone(call);
    let handle = tokio::runtime::Handle::current();
    let (sent, worker) = tokio::sync::oneshot::channel();
    let owner = context.clone();
    owner
        .offload_hook(Box::new(move || {
            let result = {
                let input = Input {
                    projection: &projection,
                    selected: &selected,
                    scope: &scope,
                    dialect: &dialect,
                    principal: principal.as_ref(),
                    request_id,
                    identity: identity.as_ref(),
                    candidates: &candidates,
                    quantities: &quantities,
                    stage: stage.as_ref(),
                    context: &context,
                };
                handle.block_on(async {
                    tokio::time::timeout_at(deadline.into(), invoke(&call, point, &input, deadline))
                        .await
                        .map_err(|_| Failed::Port)?
                })
            };
            // What the worker shared is let go before its answer is handed back, so a caller
            // still waiting for the answer is again the only holder of what it lent.
            drop((
                projection, selected, scope, dialect, principal, identity, candidates, quantities,
                stage, context, call,
            ));
            let _ = sent.send(result);
        }))
        .map_err(|_| Failed::Port)?;
    tokio::time::timeout_at(deadline.into(), worker)
        .await
        .map_err(|_| Failed::Port)?
        .map_err(|_| Failed::Port)?
}

async fn invoke(
    call: &Call,
    point: u32,
    input: &Input<'_>,
    deadline: Instant,
) -> Result<Reply, Failed> {
    let facts = call.port.facts();
    let content =
        input.stage.is_none() && call.prompt.sends_prompt() && facts & abi::FB_WANTS_PROMPT != 0;
    let identity = call.user.sends_user() && facts & abi::FB_WANTS_IDENTITY != 0;
    let mut signals = super::view::signals(&input.projection.facts, call, content);
    signals.push((abi::S_POOL, FactRef::Text(&input.scope.pool)));
    signals.push((abi::S_INGRESS_PROTOCOL, FactRef::Text(&**input.dialect)));
    if let Some(strategy) = &call.strategy {
        signals.push((abi::S_ROUTING_POLICY, FactRef::Text(strategy)));
    }
    if identity {
        if let Some(principal) = input.principal {
            signals.push((abi::S_USER_SUBJECT, FactRef::Text(principal.as_str())));
        }
        if let Some(key) = &input.selected.key {
            signals.push((abi::S_KEY_ID, FactRef::Text(&key.id)));
            signals.push((abi::S_KEY_NAME, FactRef::Text(&key.name)));
        }
    }
    for (key, value) in input.stage() {
        if *key == abi::S_RESPONSE_TOKENS_OUT
            && !call
                .signals
                .wants(busbar_contract::signal::Signal::ResponseTokensOut)
        {
            continue;
        }
        signals.push((
            *key,
            match value {
                busbar_ports::FactVal::U(n) => FactRef::U(*n),
                busbar_ports::FactVal::Text(text) => FactRef::Text(text),
            },
        ));
    }
    // The slices the view lends are laid out in this call's own frame: each candidate's tags and
    // cost terms, then the candidates and the budgets over them.
    let priced = call
        .signals
        .wants(busbar_contract::signal::Signal::CandidateRouteCost);
    let mut tags = smallvec::SmallVec::<[Tags<'_>; CANDIDATES_INLINE]>::new();
    let mut costs = smallvec::SmallVec::<[Terms<'_>; CANDIDATES_INLINE]>::new();
    for candidate in input.candidates.iter() {
        let own: Tags<'_> = candidate.facts.tags.iter().map(String::as_str).collect();
        tags.push(own);
        // No term at all for a call that did not ask for the route cost.
        let terms: Terms<'_> = input
            .quantities
            .iter()
            .filter(|_| priced)
            .map(|(class, expected_units)| CostTermIn {
                class,
                expected_units: *expected_units,
                price_per_unit: input.selected.cost.routing_price(&candidate.lane, class),
            })
            .collect();
        costs.push(terms);
    }
    let candidates: smallvec::SmallVec<[CandidateIn<'_>; CANDIDATES_INLINE]> = input
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let facts = &candidate.facts;
            let mut rec = abi::CandidateRec {
                index: u32::try_from(facts.idx).unwrap_or(u32::MAX),
                flags: 0,
                context_max: 0,
                cost_per_mtok_micros: 0,
                latency_ms: 0,
                budget_remaining_micros: 0,
                error_rate_ppm: 0,
                breaker: 0,
                rate_headroom_ppm: 0,
                _r: 0,
                weight: facts.weight,
                available_concurrency: u32::try_from(facts.available_concurrency)
                    .unwrap_or(u32::MAX),
            };
            if let Some(value) = facts.context_max {
                rec.flags |= abi::C_HAS_CONTEXT_MAX;
                rec.context_max = value as u64;
            }
            if let Some(value) = facts.cost_per_mtok {
                rec.flags |= abi::C_HAS_COST;
                rec.cost_per_mtok_micros = (value.max(0.0) * 1_000_000.0).round() as u64;
            }
            if let Some(value) = facts.latency_ms {
                rec.flags |= abi::C_HAS_LATENCY;
                rec.latency_ms = value.max(0.0).round() as u64;
            }
            if let Some(value) = facts.budget_remaining {
                rec.flags |= abi::C_HAS_BUDGET;
                rec.budget_remaining_micros = value;
            }
            // Opt-in: encoded only when this Call requested it (DES-NATIVE-HOOKS-PARITY r3 §E).
            if let Some(value) = facts.error_rate.filter(|_| {
                call.signals
                    .wants(busbar_contract::signal::Signal::CandidateErrorRate)
            }) {
                rec.flags |= abi::C_HAS_ERROR_RATE;
                rec.error_rate_ppm = ppm(value);
            }
            if let Some(value) = input.selected.rate_headroom {
                rec.flags |= abi::C_HAS_RATE_HEADROOM;
                rec.rate_headroom_ppm = ppm(value);
            }
            CandidateIn {
                rec,
                model: &facts.model,
                provider: &facts.provider,
                tier: facts.tier.as_deref(),
                tags: &tags[index],
                cost_terms: &costs[index],
            }
        })
        .collect();
    // An uncapped bucket has no finite remaining balance; never turn absence into zero.
    let budgets: smallvec::SmallVec<[BudgetIn<'_>; BUDGETS_INLINE]> = input
        .selected
        .budget
        .iter()
        .filter_map(|bucket| {
            Some(BudgetIn {
                id: &bucket.bucket_id,
                period: &bucket.budget_period,
                group: bucket.budget_group.as_deref(),
                pool: bucket.pool.as_deref(),
                remaining_micros: bucket.remaining_micros?,
                spend_micros_at_current_rate: Some(bucket.spend_micros_at_current_rate),
                window_start_s: bucket.window_start,
            })
        })
        .collect();
    let view = HookView {
        signals: &signals,
        candidates: &candidates,
        budgets: &budgets,
        conversation: if content {
            input
                .projection
                .conversation
                .as_deref()
                .map(|bytes| &**bytes)
        } else {
            None
        },
        body: None,
        identity: input.identity.filter(|_| identity).map(|bytes| &***bytes),
    };
    let cx = CallCx {
        deadline,
        request_id: input.request_id,
        stack: Default::default(),
    };
    let answer = match call.port.on(cx, point, &view) {
        HookCall::Done(result) => result,
        HookCall::Io(future) => future.await,
    }
    .map(Reply)
    .map_err(|_| Failed::Port);
    answer
}

pub(super) fn record(call: &Call, answer: Option<&HookAnswer>) -> HookApplied {
    let head = match answer.map(|answer| answer.verb) {
        Some(abi::VERB_REJECT) => HookHead::Veto,
        Some(abi::VERB_REWRITE | abi::VERB_PREFER | abi::VERB_PRIORITIZE | abi::VERB_RESTRICT) => {
            HookHead::Modify
        }
        _ => HookHead::Pass,
    };
    // The row shares the call's own configured key: a refcount, never a copy.
    HookApplied {
        hook: busbar_contract::kept::Text::from(Arc::clone(&call.name)),
        head,
        failed: answer.is_none(),
    }
}

/// `ran` takes one record per call attempted: the stage's own list, or a gate's few in its frame.
pub(super) async fn chain(
    call: &Arc<Call>,
    point: u32,
    input: &Input<'_>,
    ran: &mut impl Extend<HookApplied>,
) -> Result<(Arc<Call>, Reply), Failed> {
    for attempted in std::iter::once(call).chain(call.fallbacks.iter()) {
        let answer = one(attempted, point, input).await;
        ran.extend(std::iter::once(record(
            attempted,
            answer.as_ref().ok().map(|reply| &**reply),
        )));
        if let Ok(answer) = answer {
            return Ok((Arc::clone(attempted), answer));
        }
        if let Err(error @ (Failed::Unconfirmed | Failed::Unprojected)) = answer {
            return Err(error);
        }
    }
    let (verb, order) = match call.on_error {
        crate::config::PolicyOnError::Reject => return Err(Failed::Port),
        crate::config::PolicyOnError::First if point == abi::POINT_ROUTE => (
            abi::VERB_PREFER,
            input
                .candidates
                .iter()
                .filter_map(|candidate| u32::try_from(candidate.facts.idx).ok())
                .collect(),
        ),
        _ => (abi::VERB_ABSTAIN, Vec::new()),
    };
    Ok((
        Arc::clone(call),
        Reply(HookAnswer {
            verb,
            reject_status: None,
            order,
            restrict: Vec::new(),
            message: None,
            rewrite: None,
        }),
    ))
}
