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
    counted(rewrites, gates, Arc::new(|| 1))
}

/// [`bound`], the unit's correlation id off `next_request_id`.
fn counted(
    rewrites: Vec<(Duration, Arc<dyn RoutingPolicy>)>,
    gates: Vec<(u16, ResolvedPolicy)>,
    next_request_id: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> BoundHooks {
    BoundHooks {
        rewrites,
        gates,
        pool_rewrites: Default::default(),
        pool_gates: Default::default(),
        pool_policies: Default::default(),
        taps: StageTaps::default(),
        requested: RequestedSignals::default(),
        next_request_id,
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

// ── the request span's correlation id (ARCHITECT RULING D1 2026-10-06) ──────────────────────────

/// Every span opened under the capture: its name and each field as it was given or later recorded.
type Opened = Arc<Mutex<Vec<(tracing::span::Id, String, Vec<(String, String)>)>>>;

/// A layer keeping every span's name and fields, including those recorded after it opened.
#[derive(Clone, Default)]
struct SpanCapture(Opened);

struct Fields<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Vec::new();
        attrs.record(&mut Fields(&mut fields));
        let name = attrs.metadata().name().to_string();
        self.0.lock().unwrap().push((id.clone(), name, fields));
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut opened = self.0.lock().unwrap();
        if let Some((_, _, fields)) = opened.iter_mut().rev().find(|(i, _, _)| i == id) {
            values.record(&mut Fields(fields));
        }
    }
}

/// Drive one unit of `hooks` under a request span named `forward` (the span the composition root
/// opens around a unit), every span captured: the spans named `forward`, each with its fields, and
/// how many correlation ids the binder handed out.
async fn request_spans(gates: Vec<(u16, ResolvedPolicy)>) -> (Vec<Vec<(String, String)>>, u64) {
    use tracing::Instrument as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    let minted = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&minted);
    let next = Arc::new(move || 40 + counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1);
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(counted(Vec::new(), gates, next)),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let capture = SpanCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    let span = tracing::debug_span!("forward", request_id = tracing::field::Empty);
    let outcome = drive(&units).instrument(span).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    let forward = capture
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, name, _)| name == "forward")
        .map(|(_, _, fields)| fields.clone())
        .collect();
    (forward, minted.load(std::sync::atomic::Ordering::SeqCst))
}

/// A UNIT NO HOOK BINDS still carries a correlation id on its request span, one id off the
/// binder's counter, as 1.5.5 stamped one on every forwarded request (v1.5.5
/// `crates/busbar/src/proxy/engine/mod.rs:144`, recorded on its span at `:152`); and the kernel
/// opens no `forward` span of its own beside the request span. RED: the request span's
/// `request_id` stayed empty for a unit no hook binds.
#[tokio::test]
async fn a_unit_no_hook_binds_carries_one_correlation_id_on_its_request_span() {
    let (forward, minted) = request_spans(Vec::new()).await;
    assert_eq!(
        forward.len(),
        1,
        "the request span is the unit's one `forward` span: {forward:?}"
    );
    assert_eq!(minted, 1, "one id per unit");
    assert_eq!(
        forward[0],
        vec![("request_id".to_string(), "41".to_string())],
        "the request span carries the unit's id"
    );
}

/// A UNIT A HOOK BINDS carries on its request span the id its hooks were handed, minted once; and
/// the kernel opens no second `forward` span (the never-entered `debug_span!("forward")` the hook
/// stage opened before is deleted). RED: the id went on a second, never-entered `forward` span.
#[tokio::test]
async fn a_hooked_unit_carries_its_hooks_correlation_id_on_its_request_span() {
    let (_, g) = gate(None);
    let (forward, minted) = request_spans(vec![(0, g)]).await;
    assert_eq!(
        forward.len(),
        1,
        "the request span is the unit's one `forward` span: {forward:?}"
    );
    assert_eq!(minted, 1, "one id per unit, the one its hooks carry");
    assert_eq!(
        forward[0],
        vec![("request_id".to_string(), "41".to_string())],
        "the request span carries the id the hooks were handed"
    );
}
