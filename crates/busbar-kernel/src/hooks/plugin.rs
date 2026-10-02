// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK CHAIN'S CALLS ON THE ONE DISPATCHER (THE DESIGN §11.7: hooks on the memory ABI, 1.5.5
//! behaviour frozen): [`HookPolicy`], the routing seam's [`RoutingPolicy`] over one opened hook
//! instance's contract [`HookCalls`] (whichever door the instance came in by — the composition
//! root's `HookAxis` opened it). Each method builds the hook kind's fixed view
//! ([`DecideView`] / [`NotifyFrame`]) from the borrowed projections, makes the call bounded by the
//! hook's `timeout_ms`, and lowers the fixed answer back through the kernel's OWN 1.5.5 normalizing
//! ([`wire`]): reject > restrict > abstain > order, the reject-status clamp (400-499, else 403), the
//! reject-message sanitiser and 300-character cap, unknown candidate indices dropped, the rewrite
//! parsed fail-closed, the status metrics bounded. The plugin side lowered its own reply to the
//! fixed `out` (`abi::sdk::hook`); everything the 1.5.5 HOST did to a reply is done here.

use super::wire;
use busbar_contract::abi::hook::{
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView, NotifyFrame};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::hook_calls::{Answered, HookCalls};
use busbar_contract::hooks::{
    Candidate, HookStatus, PolicyError, PolicyResult, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
use std::sync::Arc;
use std::time::Duration;

/// ONE OPENED HOOK INSTANCE AS THE ROUTING SEAM CALLS IT.
pub(crate) struct HookPolicy {
    calls: Arc<dyn HookCalls>,
    /// The hook's registry name (metrics, `x-busbar-route`), interned once per distinct name.
    name: &'static str,
}

impl HookPolicy {
    /// The routing seam over `calls`, named `name` (the hook's registry name).
    pub(crate) fn new(calls: Arc<dyn HookCalls>, name: &str) -> Arc<dyn RoutingPolicy> {
        Arc::new(Self {
            calls,
            name: busbar_plugin_loader::intern_name(name),
        })
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

/// A reject's `(status, message)` as 1.5.5's host read it: a stated status clamped to 400-499
/// (else 403), an absent one 403; the message sanitised and capped.
fn reject_of(verbs: u32, status: u16, message: &str) -> (u16, String) {
    let status = if verbs & VERB_HAS_REJECT_STATUS != 0 {
        wire::clamp_reject_status(status)
    } else {
        wire::REJECT_STATUS_DEFAULT
    };
    (status, wire::sanitize_reject_message(message))
}

/// Why no answer could be had, as the caller's `on_error` reads it.
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

/// LOWER a READY `decide` answer: reject > restrict > abstain > order (1.5.5's `wire::normalize`).
fn lower_decide(
    out: &busbar_contract::abi::hook::DecideOut,
    frame: &DecideFrame,
    candidates: &[Candidate<'_>],
) -> RoutingDecision {
    let verbs = out.verbs;
    if verbs & VERB_REJECT != 0 {
        let message = frame.reject_message(out.reject_message_written);
        let (status, message) = reject_of(verbs, out.reject_status, &message);
        return RoutingDecision::Reject { status, message };
    }
    if verbs & VERB_RESTRICT != 0 {
        // Each tag trimmed, empties dropped; none left restricts to nothing (the gate's
        // `on_empty`), never allow-all.
        let tags_any = frame
            .restrict_tags(out.restrict_tags_written)
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
    RoutingDecision::from_ranked(frame.order(out.order_written), &valid)
}

/// LOWER a READY `transform` answer: reject > rewrite > abstain (1.5.5's `wire::transform_outcome`);
/// a rewrite that does not parse proceeds with the ORIGINAL body.
fn lower_transform(
    out: &busbar_contract::abi::hook::TransformOut,
    frame: &DecideFrame,
) -> TransformOutcome {
    let verbs = out.verbs;
    if verbs & VERB_REJECT != 0 {
        let message = frame.reject_message(out.reject_message_written);
        let (status, message) = reject_of(verbs, out.reject_status, &message);
        return TransformOutcome::Reject { status, message };
    }
    if verbs & VERB_REWRITE == 0 {
        return TransformOutcome::Abstain;
    }
    serde_json::from_slice::<serde_json::Value>(&frame.rewrite(out.rewrite_written))
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
        let frame = DecideFrame::first(DecideView::build(req, candidates, ctx));
        match self.calls.decide(frame, budget).await {
            Answered::Answer {
                outcome: Outcome::Ready,
                out,
                frame,
                ..
            } => Ok(lower_decide(&out, &frame, candidates)),
            // FAILED (the hook said it could not answer), a deadline, a broken contract: the
            // caller's `on_error` decides, never a silent abstain.
            other => Err(PolicyError::from(unanswered(self.name, budget, other))),
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn transform(&self, req: &RoutingRequest<'_>, budget: Duration) -> TransformOutcome {
        // A rewrite gate reads the prompt, not the candidate set.
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
                message: unanswered(self.name, budget, other),
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
