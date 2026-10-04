// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK STAGE ON THE DRIVER, against the contract-level plane double (`BUSBAR-1.6.0.md` Part 3,
//! section 12, "Hooks"; ARCHITECT K5): no hook bound projects nothing; a request-stage hook's
//! rewrite goes back to the plane (`ProjectIn::rewrite`), which applies it and answers the body the
//! kernel keeps and re-pushes on every attempt; a veto wears the hook's own status and words,
//! rendered by the plane (`REFUSAL_GATE`), before any attempt; a request the plane cannot project
//! is refused before any attempt. The 1.5.5 hook tests themselves run over the real llm plane in
//! the composition root's `hook_parity_driver` suite.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::caps::{Outcome, ReasonCode};
use busbar_contract::hooks::{
    BudgetBucketState, Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_kernel::config::PolicyOnError;
use busbar_kernel::hooks::{RequestedSignals, ResolvedPolicy};
use busbar_kernel::plane_driver::{BoundHooks, BufferCaps, CallerFacts, CallerKey, StageTaps};

use super::cases::{arrival, drive, Book, Caller, Far};
use super::common::TestUnits;
use super::{rig_with_hooks, Way};

/// A caller the hooks know nothing of.
struct Nobody;

impl CallerFacts for Nobody {
    fn key(&self, _: &str) -> Option<CallerKey> {
        None
    }
    fn in_groups(&self, _: Option<&str>, groups: &[String]) -> bool {
        groups.is_empty()
    }
    fn rate_headroom(&self, _: &str, _: &str) -> Option<f64> {
        None
    }
    fn budget(&self, _: &str) -> Vec<BudgetBucketState> {
        Vec::new()
    }
}

fn bound(
    rewrites: Vec<(Duration, Arc<dyn RoutingPolicy>)>,
    gates: Vec<(u16, ResolvedPolicy)>,
) -> BoundHooks {
    BoundHooks {
        rewrites,
        gates,
        pool_rewrites: Default::default(),
        pool_gates: Default::default(),
        pool_policies: Default::default(),
        taps: StageTaps::default(),
        requested: RequestedSignals::default(),
        next_request_id: Arc::new(|| 1),
        caller: Arc::new(Nobody),
        dialects: vec!["test-dialect".to_string()],
    }
}

/// The turns a gate was shown, per call.
type Seen = Arc<Mutex<Vec<Vec<(String, String)>>>>;

/// A gate that sees the prompt, records it, and decides `reject`.
struct Gate {
    seen: Seen,
    reject: Option<(u16, &'static str)>,
}

#[async_trait::async_trait]
impl RoutingPolicy for Gate {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        let turns = req
            .prompt
            .as_ref()
            .map(|p| {
                p.messages
                    .iter()
                    .map(|(r, t)| (r.to_string(), t.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        self.seen.lock().unwrap().push(turns);
        Ok(match self.reject {
            Some((status, message)) => RoutingDecision::Reject {
                status,
                message: message.to_string(),
            },
            None => RoutingDecision::Abstain,
        })
    }
    fn name(&self) -> &'static str {
        "gate"
    }
}

fn gate(reject: Option<(u16, &'static str)>) -> (Seen, ResolvedPolicy) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    (
        seen.clone(),
        ResolvedPolicy::Policy {
            policy: Arc::new(Gate { seen, reject }),
            on_error: PolicyOnError::default(),
            on_error_chain: Vec::new(),
            timeout: Duration::from_millis(500),
            send_prompt: true,
            send_user: false,
            on_empty: PolicyOnError::Reject,
        },
    )
}

/// A rewrite hook replacing the turns with one.
struct Rewriter;

#[async_trait::async_trait]
impl RoutingPolicy for Rewriter {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "rewriter"
    }
    async fn transform(&self, _: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        TransformOutcome::Rewrite(RewriteReply {
            messages: vec![serde_json::json!({"role": "user", "content": "COMPRESSED"})],
            tools: vec![],
        })
    }
}

#[tokio::test]
async fn no_hook_bound_projects_nothing() {
    let r = rig_with_hooks(Way::Double, BufferCaps::default(), Book::default(), None);
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    assert!(matches!(drive(&units).await, Outcome::Completed));
    assert!(
        r.projects().is_empty(),
        "a unit no hook binds crosses no `project`"
    );
}

#[tokio::test]
async fn a_rewrite_is_applied_by_the_plane_and_re_pushed_on_every_attempt() {
    let (seen, g) = gate(None);
    let hooks = bound(
        vec![(Duration::from_millis(500), Arc::new(Rewriter))],
        vec![(0, g)],
    );
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["overloaded", "ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    assert!(matches!(drive(&units).await, Outcome::Completed));
    let projects = r.projects();
    assert_eq!(
        projects.len(),
        2,
        "the first view, then the rewrite applied and re-projected"
    );
    assert!(
        projects[0].1.is_empty(),
        "the first `project` carries no rewrite"
    );
    assert!(
        !projects[1].1.is_empty(),
        "the second carries the hook's rewrite"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![vec![("user".to_string(), "COMPRESSED".to_string())]],
        "the gate after the rewrite sees the rewritten request"
    );
    let sent = far.sent();
    assert_eq!(
        sent.len(),
        2,
        "one failed-over attempt, then the served one"
    );
    for request in &sent {
        assert_eq!(
            request.body, b"user:COMPRESSED",
            "every attempt carries the body the rewrite left"
        );
    }
}

#[tokio::test]
async fn a_veto_is_rendered_by_the_plane_with_the_hooks_status_and_words_before_any_attempt() {
    let (_, g) = gate(Some((451, "blocked\r\nby policy")));
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(Vec::new(), vec![(0, g)])),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    let outcome = drive(&units).await;
    assert!(
        matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
        "{outcome:?}"
    );
    let rendered = units.take_rendered().expect("the plane rendered the veto");
    assert_eq!(rendered.status, 451);
    assert_eq!(
        rendered.body, b"refused:451:blockedby policy",
        "the hook's status and its sanitised words, in the plane's rendering"
    );
    assert!(far.sent().is_empty(), "no attempt was made");
}

#[tokio::test]
async fn a_request_the_plane_cannot_project_is_refused_before_any_attempt() {
    let (seen, g) = gate(None);
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(Vec::new(), vec![(0, g)])),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        arrival("/unprojectable", b"user:hello"),
        0,
    );
    let outcome = drive(&units).await;
    assert!(
        matches!(outcome, Outcome::Failed(_, ReasonCode::DecodeFailed)),
        "{outcome:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "no hook saw an unreadable request"
    );
    assert!(far.sent().is_empty(), "no attempt was made");
    let rendered = units
        .take_rendered()
        .expect("the plane rendered the refusal");
    assert_eq!(rendered.status, 400);
}
