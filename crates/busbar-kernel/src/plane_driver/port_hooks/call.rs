// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use busbar_kernel_audit::record::{HookApplied, HookHead};
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::hook::{BudgetIn, CandidateIn, CostTermIn, HookAnswer, HookCall, HookView};
use busbar_ports::{CallCx, FactRef};

use super::{Call, CandidateView, Projection, Selected, Selection};

pub(super) struct Input<'a> {
    pub projection: &'a Projection,
    pub selected: &'a Selected,
    pub selection: &'a Selection<'a>,
    pub identity: &'a [u8],
    pub candidates: &'a [CandidateView],
    pub quantities: &'a [(Box<str>, f64)],
    pub stage: &'a [(u32, busbar_ports::FactVal)],
    pub context: &'a crate::host_services::InvocationContext,
}

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
        use zeroize::Zeroize;
        if let Some(bytes) = self.0.rewrite.as_mut() {
            bytes.zeroize();
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
        input.stage.is_empty() && call.prompt.sends_prompt() && facts & abi::FB_WANTS_PROMPT != 0;
    let identity = call.user.sends_user() && facts & abi::FB_WANTS_IDENTITY != 0;
    if content && input.projection.conversation.is_none() {
        return Err(Failed::Unprojected);
    }
    if content || identity {
        tokio::time::timeout_at(
            deadline.into(),
            (input.selected.reads)(
                &[&call.name],
                input.selection.principal,
                input.selection.dialect,
                identity,
            ),
        )
        .await
        .map_err(|_| Failed::Unconfirmed)?
        .map_err(|_| Failed::Unconfirmed)?;
    }
    // Both synchronous and I/O hooks run off the calling executor. The owned input retains
    // wiping content and its exact generation until a timed-out worker actually returns.
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
    let selected = input.selected.clone();
    let pool = input.selection.pool.to_owned();
    let container = input.selection.container.to_owned();
    let dialect = input.selection.dialect.to_owned();
    let principal = input.selection.principal.map(str::to_owned);
    let route = input.selection.route;
    let request_id = input.selection.request_id;
    let now_s = input.selection.now_s;
    let identity = if identity {
        busbar_contract::secure::SecureVec::from(input.identity.to_vec())
    } else {
        Default::default()
    };
    let candidates = input.candidates.to_vec();
    let quantities = input.quantities.to_vec();
    let stage = input.stage.to_vec();
    let context = input.context.clone();
    let call = Arc::clone(call);
    let handle = tokio::runtime::Handle::current();
    let (sent, worker) = tokio::sync::oneshot::channel();
    let owner = context.clone();
    owner
        .offload_hook(Box::new(move || {
            let selection = Selection {
                route,
                pool: &pool,
                container: &container,
                dialect: &dialect,
                principal: principal.as_deref(),
                key: context.principal().map(AsRef::as_ref),
                request_id,
                now_s,
            };
            let input = Input {
                projection: &projection,
                selected: &selected,
                selection: &selection,
                identity: &identity,
                candidates: &candidates,
                quantities: &quantities,
                stage: &stage,
                context: &context,
            };
            let result = handle.block_on(async {
                tokio::time::timeout_at(
                    deadline.into(),
                    crate::hook_child::SCOPE.scope(
                        crate::hook_child::Scope::new(context.clone()),
                        invoke(&call, point, &input, deadline),
                    ),
                )
                .await
                .map_err(|_| Failed::Port)?
            });
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
        input.stage.is_empty() && call.prompt.sends_prompt() && facts & abi::FB_WANTS_PROMPT != 0;
    let identity = call.user.sends_user() && facts & abi::FB_WANTS_IDENTITY != 0;
    let mut signals = super::view::signals(&input.projection.facts, call);
    if !content {
        signals.retain(|(key, _)| *key != busbar_plugin_abi::fail::fact::PJ_TEXT_COMPLETE);
    }
    signals.push((abi::S_POOL, FactRef::Text(input.selection.pool)));
    signals.push((
        abi::S_INGRESS_PROTOCOL,
        FactRef::Text(input.selection.dialect),
    ));
    if let Some(strategy) = &call.strategy {
        signals.push((abi::S_ROUTING_POLICY, FactRef::Text(strategy)));
    }
    if identity {
        if let Some(principal) = input.selection.principal {
            signals.push((abi::S_USER_SUBJECT, FactRef::Text(principal)));
        }
        if let Some(key) = &input.selected.key {
            signals.push((abi::S_KEY_ID, FactRef::Text(&key.id)));
            signals.push((abi::S_KEY_NAME, FactRef::Text(&key.name)));
        }
    }
    for (key, value) in input.stage {
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
    let tags: Vec<Vec<&str>> = input
        .candidates
        .iter()
        .map(|candidate| candidate.facts.tags.iter().map(String::as_str).collect())
        .collect();
    let costs: Vec<Vec<CostTermIn<'_>>> = input
        .candidates
        .iter()
        .map(|candidate| {
            if !call
                .signals
                .wants(busbar_contract::signal::Signal::CandidateRouteCost)
            {
                return Vec::new();
            }
            input
                .quantities
                .iter()
                .map(|(class, expected_units)| CostTermIn {
                    class,
                    expected_units: *expected_units,
                    price_per_unit: input.selected.cost.routing_price(&candidate.lane, class),
                })
                .collect()
        })
        .collect();
    let candidates: Vec<_> = input
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
    let budgets: Vec<_> = input
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
            input.projection.conversation.as_deref()
        } else {
            None
        },
        body: None,
        identity: identity.then_some(input.identity),
    };
    let cx = CallCx {
        deadline,
        request_id: input.selection.request_id,
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
    HookApplied {
        hook: call.name.to_string(),
        head,
        failed: answer.is_none(),
    }
}

pub(super) async fn chain(
    call: &Arc<Call>,
    point: u32,
    input: &Input<'_>,
    ran: &mut Vec<HookApplied>,
) -> Result<(Arc<Call>, Reply), Failed> {
    for attempted in std::iter::once(call).chain(call.fallbacks.iter()) {
        let answer = one(attempted, point, input).await;
        ran.push(record(
            attempted,
            answer.as_ref().ok().map(|reply| &**reply),
        ));
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
