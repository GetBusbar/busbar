// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::hook::{
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_PRIORITIZE, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
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
    signals: Vec<busbar_contract::Signal>,
    child: Option<Arc<crate::hook_child::Grant>>,

    /// Each candidate set's static half, keyed by the set's [`identity`] and confirmed by
    /// [`CandidateStatics::matches`]; at most [`STATIC_HALVES`] sets are kept.
    statics: std::sync::Mutex<foldhash::HashMap<u64, Arc<CandidateStatics>>>,
}

const STATIC_HALVES: usize = 16;

/// A candidate set's identity within one generation: each candidate's index and where its model name
/// lives. Cheap to take per call; a collision (or a reused address after a reload) is caught by
/// `matches`, which compares the facts themselves.
fn identity(candidates: &[Candidate<'_>]) -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut h = foldhash::fast::FixedState::default().build_hasher();
    h.write_usize(candidates.len());
    for c in candidates {
        h.write_usize(c.idx);
        h.write_usize(c.model.as_ptr() as usize);
        h.write_usize(c.model.len());
    }
    h.finish()
}

impl HookPolicy {
    pub(crate) fn policy(
        calls: Arc<dyn HookCalls>,
        name: &str,
        signals: &[busbar_contract::Signal],
        child: Option<&crate::hook_child::Grant>,
    ) -> Arc<dyn RoutingPolicy> {
        // busbar:expect(bp::into_alloc, reason = "config: a hook policy is built once per generation")
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a hook policy is built once per generation"
        )]
        let policy = Arc::new(Self {
            calls,
            name: Arc::from(name),
            signals: signals.to_vec(),
            child: child.cloned().map(Arc::new),
            statics: std::sync::Mutex::default(),
        });
        policy
    }

    /// A built-in ranking strategy: the gate hook that declares the word `name`, asked for no
    /// signals and granted no child dispatch, answering only `decide`. It is content-blind
    /// ([`RoutingPolicy::content_blind`]); every other hook policy is not.
    pub(crate) fn ranking(calls: Arc<dyn HookCalls>, name: &str) -> Arc<dyn RoutingPolicy> {
        Arc::new(Ranking(Self {
            calls,
            name: Arc::from(name),
            signals: Vec::new(),
            child: None,
            statics: std::sync::Mutex::new(Vec::new()),
        }))
    }

    async fn decided(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        if crate::hook_child::recursive(&self.name) {
            return Ok(RoutingDecision::Abstain);
        }
        let statics = self.statics_for(candidates);
        let frame = DecideFrame::first(DecideView::build_with_signals(
            req,
            statics,
            candidates,
            ctx,
            &self.signals,
        ))
        .with_child(crate::hook_child::invocation(
            &self.name,
            self.child.as_ref(),
            budget,
        ));
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

    fn statics_for(&self, candidates: &[Candidate<'_>]) -> Arc<CandidateStatics> {
        let key = identity(candidates);
        let mut kept = self
            .statics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(found) = kept.get(&key).filter(|s| s.matches(candidates)) {
            return Arc::clone(found);
        }
        let built = CandidateStatics::build(candidates);
        if kept.len() >= STATIC_HALVES && !kept.contains_key(&key) {
            kept.clear();
        }
        kept.insert(key, Arc::clone(&built));
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
        Answered::TimedOut => {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a hook past its deadline is reported once, in words"
            )]
            let why = format!("hook plugin deadline ({budget:?}) exceeded");
            why
        }
        Answered::Broken(why) => why,
        Answered::Answer { error, .. } => {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a hook that could not answer is reported once, in words"
            )]
            let why = format!(
                "hook {name} could not answer: {}",
                error.unwrap_or_default()
            );
            why
        }
    }
}

/// The hook's reject message, sanitised and capped as 1.5.5 did, with a cut reported against
/// `hook`. `reject_of` caps it again; at most 300 chars already, that is the identity.
fn reported_reject(hook: &str, raw: &str) -> String {
    let (message, cut) = wire::sanitize_reject_message_counted(raw);
    if let Some(sanitised_chars) = cut {
        crate::hooks::text_cut::report(
            hook,
            wire::TextField::RejectMessage,
            wire::REJECT_MESSAGE_MAX_CHARS,
            1,
            sanitised_chars,
        );
    }
    message
}

fn lower_decide(
    hook: &str,
    out: &busbar_contract::abi::hook::DecideOut,
    frame: &DecideFrame,
    candidates: &[Candidate<'_>],
) -> RoutingDecision {
    decision(
        out.verbs,
        out.reject_status,
        || reported_reject(hook, &frame.reject_message(out.reject_message_written)),
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
        return RoutingDecision::Restrict {
            tags_any: super::trimmed_tags(restrict_tags()),
        };
    }
    if verbs & (VERB_PREFER | VERB_PRIORITIZE) == 0 {
        return RoutingDecision::Abstain;
    }
    match super::ranked(order(), candidates) {
        RoutingDecision::Prefer(set) if verbs & VERB_PRIORITIZE != 0 => {
            RoutingDecision::Prioritize(set)
        }
        decision => decision,
    }
}

fn lower_transform(
    hook: &str,
    out: &busbar_contract::abi::hook::TransformOut,
    frame: &DecideFrame,
) -> TransformOutcome {
    transformed(
        out.verbs,
        out.reject_status,
        || reported_reject(hook, &frame.reject_message(out.reject_message_written)),
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
        .and_then(wire::take_rewrite)
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
        if crate::hook_child::recursive(&self.name) {
            return Ok(RoutingDecision::Abstain);
        }
        let statics = self.statics_for(candidates);
        let frame = DecideFrame::first(DecideView::build_with_signals(
            req,
            statics,
            candidates,
            ctx,
            &self.signals,
        ))
        .with_child(crate::hook_child::invocation(
            &self.name,
            self.child.as_ref(),
            budget,
        ));
        match self.calls.decide(frame, budget).await {
            Answered::Answer {
                outcome: Outcome::Ready,
                out,
                frame,
                ..
            } => Ok(lower_decide(&self.name, &out, &frame, candidates)),

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
        let frame = DecideFrame::first(DecideView::build_with_signals(
            req,
            self.statics_for(&[]),
            &[],
            &ctx,
            &self.signals,
        ));
        match self.calls.transform(frame, budget).await {
            Answered::Answer {
                outcome: Outcome::Ready,
                out,
                frame,
                ..
            } => lower_transform(&self.name, &out, &frame),
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
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
        settings_version: u64,
        budget: Duration,
    ) -> Result<(), PolicyError> {
        self.calls
            .configure(hook_name, settings, settings_version, budget)
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
        self.calls
            .notify(tap.with_signals(&self.signals), budget)
            .await;
    }
}

/// [`HookPolicy::ranking`]: a pool's built-in ranking strategy. It is only ever asked to rank
/// (pool ordering or an `on_error` fallback link), so it answers `decide` and its name and keeps
/// every other call at the trait default.
struct Ranking(HookPolicy);

#[async_trait::async_trait]
impl RoutingPolicy for Ranking {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        self.0.decided(req, candidates, ctx, budget).await
    }

    fn name(&self) -> &str {
        &self.0.name
    }

    fn name_arc(&self) -> Arc<str> {
        Arc::clone(&self.0.name)
    }

    fn content_blind(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "tests/statics_tests.rs"]
mod statics_tests;
