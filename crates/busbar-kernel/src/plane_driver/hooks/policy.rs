// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::hook::{
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
};
use busbar_contract::abi::host::hook::{CandidateStatics, DecideFrame, DecideView, NotifyFrame};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::hook_calls::{Answered, HookCalls};
use busbar_contract::hook_wire::reply as wire;
use busbar_contract::hooks::{
    Candidate, HookStatus, PolicyError, PolicyResult, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct HookPolicy {
    calls: Arc<dyn HookCalls>,

    name: Arc<str>,

    statics: std::sync::Mutex<Vec<Arc<CandidateStatics>>>,
}

const STATIC_HALVES: usize = 16;

impl HookPolicy {
    pub(crate) fn policy(calls: Arc<dyn HookCalls>, name: &str) -> Arc<dyn RoutingPolicy> {
        Arc::new(Self {
            calls,
            name: Arc::from(name),
            statics: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn statics_for(&self, candidates: &[Candidate<'_>]) -> Arc<CandidateStatics> {
        let mut kept = self
            .statics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(at) = kept.iter().position(|s| s.matches(candidates)) {
            let found = kept.remove(at);
            kept.insert(0, Arc::clone(&found));
            return found;
        }
        let built = CandidateStatics::build(candidates);
        kept.insert(0, Arc::clone(&built));
        kept.truncate(STATIC_HALVES);
        built
    }
}

impl std::fmt::Debug for HookPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookPolicy")
            .field("name", &self.name)
            .field("plugin", &self.calls.name())
            .finish()
    }
}

fn reject_of(verbs: u32, status: u16, message: &str) -> (u16, String) {
    let status = if verbs & VERB_HAS_REJECT_STATUS != 0 {
        wire::clamp_reject_status(status)
    } else {
        wire::REJECT_STATUS_DEFAULT
    };
    (status, wire::sanitize_reject_message(message))
}

fn unanswered<O>(name: &str, budget: Duration, a: Answered<O>) -> String {
    match a {
        Answered::TimedOut => format!("hook plugin deadline ({budget:?}) exceeded"),
        Answered::Broken(why) => why,
        Answered::Answer { error, .. } => format!(
            "hook {name} could not answer: {}",
            error.unwrap_or_default()
        ),
    }
}

fn lower_decide(
    out: &busbar_contract::abi::hook::DecideOut,
    frame: &DecideFrame,
    candidates: &[Candidate<'_>],
) -> RoutingDecision {
    decision(
        out.verbs,
        out.reject_status,
        || frame.reject_message(out.reject_message_written),
        || frame.restrict_tags(out.restrict_tags_written),
        || frame.order(out.order_written),
        candidates,
    )
}

pub(super) fn decision(
    verbs: u32,
    reject_status: u16,
    reject_message: impl FnOnce() -> String,
    restrict_tags: impl FnOnce() -> Vec<String>,
    order: impl FnOnce() -> Vec<usize>,
    candidates: &[Candidate<'_>],
) -> RoutingDecision {
    if verbs & VERB_REJECT != 0 {
        let (status, message) = reject_of(verbs, reject_status, &reject_message());
        return RoutingDecision::Reject { status, message };
    }
    if verbs & VERB_RESTRICT != 0 {
        let tags_any = restrict_tags()
            .into_iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        return RoutingDecision::Restrict { tags_any };
    }
    if verbs & VERB_PREFER == 0 {
        return RoutingDecision::Abstain;
    }
    let valid: std::collections::HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
    RoutingDecision::from_ranked(order(), &valid)
}

fn lower_transform(
    out: &busbar_contract::abi::hook::TransformOut,
    frame: &DecideFrame,
) -> TransformOutcome {
    transformed(
        out.verbs,
        out.reject_status,
        || frame.reject_message(out.reject_message_written),
        || frame.rewrite(out.rewrite_written),
    )
}

pub(super) fn transformed(
    verbs: u32,
    reject_status: u16,
    reject_message: impl FnOnce() -> String,
    rewrite: impl FnOnce() -> Vec<u8>,
) -> TransformOutcome {
    if verbs & VERB_REJECT != 0 {
        let (status, message) = reject_of(verbs, reject_status, &reject_message());
        return TransformOutcome::Reject { status, message };
    }
    if verbs & VERB_REWRITE == 0 {
        return TransformOutcome::Abstain;
    }
    serde_json::from_slice::<serde_json::Value>(&rewrite())
        .ok()
        .as_ref()
        .and_then(wire::parse_rewrite)
        .map_or(TransformOutcome::Abstain, TransformOutcome::Rewrite)
}

#[async_trait::async_trait]
impl RoutingPolicy for HookPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        let statics = self.statics_for(candidates);
        let frame = DecideFrame::first(DecideView::build_with(req, statics, candidates, ctx));
        match self.calls.decide(frame, budget).await {
            Answered::Answer {
                outcome: Outcome::Ready,
                out,
                frame,
                ..
            } => Ok(lower_decide(&out, &frame, candidates)),

            other => Err(PolicyError::from(unanswered(&self.name, budget, other))),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn name_arc(&self) -> Arc<str> {
        Arc::clone(&self.name)
    }

    async fn transform(&self, req: &RoutingRequest<'_>, budget: Duration) -> TransformOutcome {
        let ctx = RoutingContext {
            pool: req.pool,
            budget_remaining: None,
            budget: &[],
        };
        let frame = DecideFrame::first(DecideView::build(req, &[], &ctx));
        match self.calls.transform(frame, budget).await {
            Answered::Answer {
                outcome: Outcome::Ready,
                out,
                frame,
                ..
            } => lower_transform(&out, &frame),
            Answered::Answer { error, .. } => TransformOutcome::Failed {
                message: error.unwrap_or_default(),
            },
            other => TransformOutcome::Failed {
                message: unanswered(&self.name, budget, other),
            },
        }
    }

    async fn configure(
        &self,
        hook_name: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
        settings_version: u64,
        budget: Duration,
    ) -> Result<(), PolicyError> {
        let settings = serde_json::Value::Object(settings.clone()).to_string();
        self.calls
            .configure(hook_name, &settings, settings_version, budget)
            .await
            .map_err(PolicyError::from)
    }

    async fn describe(&self, budget: Duration) -> Option<serde_json::Value> {
        let bytes = self.calls.describe(budget).await?;
        serde_json::from_slice::<wire::DescribeReply>(&bytes)
            .ok()?
            .schema
    }

    async fn status(&self, budget: Duration) -> Option<HookStatus> {
        let bytes = self.calls.status(budget).await?;
        let envelope: wire::StatusEnvelope = serde_json::from_slice(&bytes).ok()?;
        envelope.status.map(Into::into)
    }

    async fn notify(&self, tap: Arc<NotifyFrame>, budget: Duration) {
        self.calls.notify(tap, budget).await;
    }
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "tests/statics_tests.rs"]
mod statics_tests;
