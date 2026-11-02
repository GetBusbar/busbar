// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::caps::{Outcome, ReasonCode};
use busbar_contract::hooks::{
    BudgetBucketState, Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_kernel::config::PolicyOnError;
use busbar_kernel::hooks::{RequestedSignals, ResolvedPolicy};
use busbar_kernel::plane_driver::{
    BoundHooks, BufferCaps, CallerFacts, CallerKey, HookJournal, HooksRan, StageTaps,
};
use busbar_kernel_audit::{HookApplied, HookHead};

use super::cases::{arrival, drive, Book, Caller, Far};
use super::common::TestUnits;
use super::{rig_with_hooks, Way};

pub(crate) struct Nobody;

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
    fn hook_read(&self, _: &str, _: Option<&str>, _: &str, _: bool) {}
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

type Seen = Arc<Mutex<Vec<Vec<(String, String)>>>>;

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
    gate_granted(reject, true)
}

fn gate_granted(reject: Option<(u16, &'static str)>, send_prompt: bool) -> (Seen, ResolvedPolicy) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    (
        seen.clone(),
        ResolvedPolicy::Policy {
            policy: Arc::new(Gate { seen, reject }),
            on_error: PolicyOnError::default(),
            on_error_chain: Vec::new(),
            timeout: Duration::from_millis(500),
            send_prompt,
            send_user: false,
            on_empty: PolicyOnError::Reject,
        },
    )
}

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

struct LoadBearingDown;

#[async_trait::async_trait]
impl RoutingPolicy for LoadBearingDown {
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
        "load-bearing-down"
    }
    async fn transform(&self, _: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        TransformOutcome::Reject {
            status: busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
            message: busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string(),
        }
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

#[tokio::test]
async fn a_load_bearing_rewrite_that_cannot_answer_refuses_with_the_shared_503() {
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(
            vec![(Duration::from_millis(500), Arc::new(LoadBearingDown))],
            Vec::new(),
        )),
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
    assert_eq!(
        rendered.status,
        u32::from(busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS)
    );
    assert_eq!(
        rendered.body,
        format!(
            "refused:503:{}",
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE
        )
        .into_bytes(),
    );
    assert!(far.sent().is_empty(), "no attempt was made");
}

fn resolved_rewrite(on_error: &str) -> Vec<(Duration, Arc<dyn RoutingPolicy>)> {
    let env = busbar_kernel_testkit::test_support::test_hook_env(
        &["test-hook"],
        busbar_kernel_testkit::test_support::HookNeeds {
            prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
            user: busbar_contract::plugin_rows::NeedLevel::Ro,
        },
    );
    let hook: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "prompt": "rw",
        "on_error": on_error,
        "global": true,
        "timeout_ms": 5000,
    }))
    .expect("a prompt: rw gate");
    let hooks = std::collections::HashMap::from([("rw".to_string(), hook)]);
    let chain = busbar_kernel::hooks::resolve_rewrite_hooks(&hooks, &["rw".to_string()], &env, 0);
    assert_eq!(
        chain.len(),
        1,
        "the rw gate resolves into the rewrite chain"
    );
    chain
}

#[tokio::test]
async fn a_rewrite_the_plane_does_not_apply_is_refused_under_every_on_error() {
    for target in ["/refuses-rewrite", "/no-rewrite"] {
        for on_error in ["weighted", "first", "reject"] {
            let mut r = rig_with_hooks(
                Way::Double,
                BufferCaps::default(),
                Book::default(),
                Some(bound(resolved_rewrite(on_error), Vec::new())),
            );
            let reports = Arc::new(Reports::default());
            r.driver = r
                .driver
                .with_hook_journal(Arc::clone(&reports) as Arc<dyn HookJournal>);
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["ok"], &[b"done"]),
                Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival(target, b"user:hello"), 0);
            let outcome = drive(&units).await;
            let case = format!("{target} on_error: {on_error}");
            assert!(
                matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
                "{case}: {outcome:?}"
            );
            let projects = r.projects();
            assert_eq!(projects.len(), 2, "{case}: the view, then the rewrite");
            assert!(!projects[1].1.is_empty(), "{case}: the rewrite crossed");
            assert_eq!(
                units
                    .take_rendered()
                    .expect("the plane rendered the refusal")
                    .body,
                unapplied_rewrite_words(on_error),
                "{case}"
            );
            assert!(far.sent().is_empty(), "{case}: nothing was sent");
            assert_unapplied_on_record(&reports, &case);
        }
    }
}

fn unapplied_rewrite_words(on_error: &str) -> Vec<u8> {
    if on_error == "reject" {
        format!(
            "refused:{}:{}",
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE
        )
    } else {
        format!(
            "refused:{}:{}",
            busbar_contract::abi::plane::PROJECT_FAULT_STATUS,
            busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE
        )
    }
    .into_bytes()
}

fn assert_unapplied_on_record(reports: &Reports, case: &str) {
    let reports = reports.0.lock().unwrap().clone();
    assert_eq!(
        reports.len(),
        1,
        "{case}: one record for the unit: {reports:?}"
    );
    assert_eq!(
        reports[0]
            .hooks
            .iter()
            .map(|h| (h.head, h.failed))
            .collect::<Vec<_>>(),
        vec![(HookHead::Veto, true)],
        "{case}: the hook is on record as a failed veto: {reports:?}"
    );
}

struct GatedBinder {
    gates: Vec<(u16, ResolvedPolicy)>,
    rewrites: Vec<(Duration, Arc<dyn RoutingPolicy>)>,
}

impl busbar_kernel::plane_driver::HookBinder for GatedBinder {
    fn bind(
        &self,
        _bind: &busbar_kernel::plane_driver::Bind<'_>,
    ) -> Option<busbar_kernel::plane_driver::UnitHooks> {
        panic!("a gate-first plane binds no routed hooks")
    }

    fn order(&self) -> busbar_kernel::plane_driver::HookOrder {
        busbar_kernel::plane_driver::HookOrder::Gated
    }

    fn bind_gated(
        &self,
        _container: &str,
        _principal: Option<&str>,
    ) -> Option<busbar_kernel::plane_driver::GatedHooks> {
        Some(busbar_kernel::plane_driver::GatedHooks {
            request_id: 7,
            gates: self.gates.clone(),
            rewrites: self.rewrites.clone(),
            key: None,
            scan: None,
            reads: Arc::new(|_: &str, _: Option<&str>, _: &str, _: bool| {}),
        })
    }
}

#[tokio::test]
async fn a_gate_first_rewrite_the_plane_does_not_apply_is_refused_under_every_on_error() {
    for target in ["/refuses-rewrite", "/no-rewrite"] {
        for on_error in ["weighted", "first", "reject"] {
            let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
            let reports = Arc::new(Reports::default());
            let driver = r
                .driver
                .with_hooks(Arc::new(GatedBinder {
                    gates: Vec::new(),
                    rewrites: resolved_rewrite(on_error),
                }))
                .with_hook_journal(Arc::clone(&reports) as Arc<dyn HookJournal>);
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["ok"], &[b"done"]),
                Caller::default(),
            );
            let units = driver.unit(&steps, &far, &caller, arrival(target, b"user:hello"), 0);
            let outcome = drive(&units).await;
            let case = format!("{target} on_error: {on_error}");
            assert!(
                matches!(outcome, Outcome::Refused(_, ReasonCode::HookVeto)),
                "{case}: {outcome:?}"
            );
            let mut words = unapplied_rewrite_words(on_error);
            words.extend_from_slice(b":hook=rw");
            assert_eq!(
                units
                    .take_rendered()
                    .expect("the veto is rendered, named for the hook")
                    .body,
                words,
                "{case}"
            );
            assert!(far.sent().is_empty(), "{case}: nothing reached the far end");
            assert_unapplied_on_record(&reports, &case);
        }
    }
}

const NOT_APPLICABLE_WARN: &str = "rewrite not applicable to this request; forwarded unmodified";

fn capture_warnings() -> (
    busbar_kernel_testkit::test_support::warn_capture::WarnCapture,
    tracing::subscriber::DefaultGuard,
) {
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
    (cap, guard)
}

fn assert_passed_on_record(reports: &Reports, case: &str) {
    let reports = reports.0.lock().unwrap().clone();
    assert_eq!(
        reports.len(),
        1,
        "{case}: one record for the unit: {reports:?}"
    );
    assert_eq!(
        reports[0]
            .hooks
            .iter()
            .map(|h| (h.hook.as_str(), h.head, h.failed))
            .collect::<Vec<_>>(),
        vec![("rw", HookHead::Pass, false)],
        "{case}: the hook is on record as a pass: {reports:?}"
    );
}

#[tokio::test]
async fn a_rewrite_that_does_not_apply_to_the_unit_is_forwarded_unmodified_and_audited() {
    for on_error in ["weighted", "first", "reject"] {
        let (cap, _guard) = capture_warnings();
        let mut r = rig_with_hooks(
            Way::Double,
            BufferCaps::default(),
            Book::default(),
            Some(bound(resolved_rewrite(on_error), Vec::new())),
        );
        let reports = Arc::new(Reports::default());
        r.driver = r
            .driver
            .with_hook_journal(Arc::clone(&reports) as Arc<dyn HookJournal>);
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = r.driver.unit(
            &steps,
            &far,
            &caller,
            arrival("/rewrite-not-applicable", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        let case = format!("on_error: {on_error}");
        assert!(matches!(outcome, Outcome::Completed), "{case}: {outcome:?}");
        let projects = r.projects();
        assert_eq!(projects.len(), 2, "{case}: the view, then the rewrite");
        assert!(!projects[1].1.is_empty(), "{case}: the rewrite crossed");
        let sent = far.sent();
        assert_eq!(sent.len(), 1, "{case}: the unit went upstream once");
        assert_eq!(
            sent[0].body, b"user:hello",
            "{case}: the caller's own body, unmodified"
        );
        assert_passed_on_record(&reports, &case);
        let warned: Vec<String> = cap
            .messages()
            .into_iter()
            .filter(|m| m.contains(NOT_APPLICABLE_WARN))
            .collect();
        assert_eq!(warned.len(), 1, "{case}: one warning: {:?}", cap.messages());
        assert!(
            warned[0].contains("hook=rw") && warned[0].contains("pool="),
            "{case}: the warning names the hook and the entry: {warned:?}"
        );
    }
}

#[tokio::test]
async fn a_gate_first_rewrite_that_does_not_apply_to_the_unit_is_forwarded_unmodified_and_audited()
{
    for on_error in ["weighted", "first", "reject"] {
        let (cap, _guard) = capture_warnings();
        let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
        let reports = Arc::new(Reports::default());
        let driver = r
            .driver
            .with_hooks(Arc::new(GatedBinder {
                gates: Vec::new(),
                rewrites: resolved_rewrite(on_error),
            }))
            .with_hook_journal(Arc::clone(&reports) as Arc<dyn HookJournal>);
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = driver.unit(
            &steps,
            &far,
            &caller,
            arrival("/rewrite-not-applicable", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        let case = format!("gate-first on_error: {on_error}");
        assert!(matches!(outcome, Outcome::Completed), "{case}: {outcome:?}");
        let sent = far.sent();
        assert_eq!(sent.len(), 1, "{case}: the unit went upstream once");
        assert_eq!(
            sent[0].body, b"user:hello",
            "{case}: the caller's own body, unmodified"
        );
        assert_passed_on_record(&reports, &case);
        let warned: Vec<String> = cap
            .messages()
            .into_iter()
            .filter(|m| m.contains(NOT_APPLICABLE_WARN))
            .collect();
        assert_eq!(warned.len(), 1, "{case}: one warning: {:?}", cap.messages());
        assert!(
            warned[0].contains("hook=rw") && warned[0].contains("entry="),
            "{case}: the warning names the hook and the entry: {warned:?}"
        );
    }
}

#[tokio::test]
async fn a_faulted_rewrite_project_is_always_the_shared_500_under_every_on_error() {
    let words = format!(
        "refused:500:{}",
        busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE
    )
    .into_bytes();
    for on_error in ["weighted", "first", "reject"] {
        let r = rig_with_hooks(
            Way::Double,
            BufferCaps::default(),
            Book::default(),
            Some(bound(resolved_rewrite(on_error), Vec::new())),
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
            arrival("/faults-rewrite", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
            "on_error: {on_error}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the plane rendered the 500");
        assert_eq!(rendered.status, 500, "on_error: {on_error}");
        assert_eq!(rendered.body, words, "on_error: {on_error}");
        assert!(far.sent().is_empty(), "on_error: {on_error}: never dialled");
    }
}

#[tokio::test]
async fn a_gate_first_faulted_rewrite_project_is_always_the_shared_500() {
    let words = format!(
        "refused:500:{}",
        busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE
    )
    .into_bytes();
    for on_error in ["weighted", "first", "reject"] {
        let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
        let driver = r.driver.with_hooks(Arc::new(GatedBinder {
            gates: Vec::new(),
            rewrites: resolved_rewrite(on_error),
        }));
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = driver.unit(
            &steps,
            &far,
            &caller,
            arrival("/faults-rewrite", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Refused(_, ReasonCode::HookVeto)),
            "on_error: {on_error}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the 500 is rendered");
        assert_eq!(rendered.status, 500, "on_error: {on_error}");
        assert_eq!(rendered.body, words, "on_error: {on_error}");
        assert!(far.sent().is_empty(), "on_error: {on_error}: never dialled");
    }
}

struct CountingRewriter {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    answer: fn() -> TransformOutcome,
}

#[async_trait::async_trait]
impl RoutingPolicy for CountingRewriter {
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
        "counting-rewriter"
    }
    async fn transform(&self, _: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        (self.answer)()
    }
}

type Answers = [(&'static str, fn() -> TransformOutcome); 3];

const ANSWERS: Answers = [
    ("abstains", || TransformOutcome::Abstain),
    ("fails", || TransformOutcome::Failed {
        message: "down".to_string(),
    }),
    ("rejects", || TransformOutcome::Reject {
        status: 403,
        message: "no".to_string(),
    }),
];

type Counted = (
    Arc<std::sync::atomic::AtomicUsize>,
    Vec<(Duration, Arc<dyn RoutingPolicy>)>,
);

fn counting(answer: fn() -> TransformOutcome) -> Counted {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hook: Arc<dyn RoutingPolicy> = Arc::new(CountingRewriter {
        calls: calls.clone(),
        answer,
    });
    (calls, vec![(Duration::from_millis(500), hook)])
}

fn shared_500() -> Vec<u8> {
    format!(
        "refused:500:{}",
        busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE
    )
    .into_bytes()
}

#[tokio::test]
async fn an_unparseable_body_with_a_configured_rewrite_hook_is_the_shared_500_and_no_hook_runs() {
    for (how, answer) in ANSWERS {
        let (calls, chain) = counting(answer);
        let r = rig_with_hooks(
            Way::Double,
            BufferCaps::default(),
            Book::default(),
            Some(bound(chain, Vec::new())),
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
            arrival("/unparseable", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
            "{how}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the plane rendered the 500");
        assert_eq!(
            (rendered.status, rendered.body),
            (500, shared_500()),
            "{how}"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{how}: no hook ran"
        );
        assert!(far.sent().is_empty(), "{how}: never dialled");
    }
}

#[tokio::test]
async fn an_unparseable_body_with_a_pool_rewrite_is_the_shared_500() {
    for (how, answer) in ANSWERS {
        let (calls, chain) = counting(answer);
        let mut hooks = bound(Vec::new(), Vec::new());
        hooks.pool_rewrites.insert("pool-a".to_string(), chain);
        let r = rig_with_hooks(
            Way::Double,
            BufferCaps::default(),
            Book::default(),
            Some(hooks),
        );
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]).naming_its_pool(),
            Caller::default(),
        );
        let units = r.driver.unit(
            &steps,
            &far,
            &caller,
            arrival("/unparseable", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
            "{how}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the plane rendered the 500");
        assert_eq!(
            (rendered.status, rendered.body),
            (500, shared_500()),
            "{how}"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0, "{how}");
        assert!(far.sent().is_empty(), "{how}: never dialled");
    }
}

#[tokio::test]
async fn a_gate_first_unparseable_body_with_a_configured_rewrite_is_the_shared_500() {
    for (how, answer) in ANSWERS {
        let (calls, chain) = counting(answer);
        let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
        let driver = r.driver.with_hooks(Arc::new(GatedBinder {
            gates: Vec::new(),
            rewrites: chain,
        }));
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = driver.unit(
            &steps,
            &far,
            &caller,
            arrival("/unparseable", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Refused(_, ReasonCode::HookVeto)),
            "{how}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the 500 is rendered");
        assert_eq!(
            (rendered.status, rendered.body),
            (500, shared_500()),
            "{how}"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0, "{how}");
        assert!(far.sent().is_empty(), "{how}: never dialled");
    }
}

#[tokio::test]
async fn with_no_rewrite_configured_project_is_not_called_up_front() {
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(Vec::new(), Vec::new())),
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
        arrival("/unparseable", b"user:hello"),
        0,
    );
    let outcome = drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    assert!(r.projects().is_empty(), "project was never asked");
    assert_eq!(far.sent().len(), 1, "the body went through");
}

type Driven = (
    Outcome,
    Option<(u32, Vec<u8>)>,
    usize,
    Vec<(Vec<u8>, Vec<u8>)>,
);

async fn unparseable_under(hooks: BoundHooks) -> Driven {
    unparseable_over(hooks, Far::new(&["ok"], &[b"done"])).await
}

async fn unparseable_over(hooks: BoundHooks, far: Far) -> Driven {
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, caller) = (TestUnits::passing(), Caller::default());
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        arrival("/unparseable", b"user:hello"),
        0,
    );
    let outcome = drive(&units).await;
    let rendered = units
        .take_rendered()
        .map(|rendered| (rendered.status, rendered.body));
    (outcome, rendered, far.sent().len(), r.projects())
}

#[tokio::test]
async fn an_unparseable_body_with_only_a_gate_is_judged_as_a_null_body_and_served() {
    let (seen, g) = gate(None);
    let (outcome, rendered, sent, projects) =
        unparseable_under(bound(Vec::new(), vec![(0, g)])).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    assert_eq!(rendered, None, "nothing was refused");
    assert_eq!(sent, 1, "the body went through");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Vec::<(String, String)>::new()],
        "the gate judged once, over a Null body: no turns"
    );
    assert_eq!(projects.len(), 1, "one project, with no rewrite");
    assert!(
        projects[0].1.is_empty(),
        "the up-front project carries no rewrite"
    );

    let (_, g) = gate(Some((451, "blocked")));
    let (_, rendered, sent, _) = unparseable_under(bound(Vec::new(), vec![(0, g)])).await;
    assert_eq!(rendered, Some((451, b"refused:451:blocked".to_vec())));
    assert_eq!(sent, 0, "never dialled");
}

#[tokio::test]
async fn with_only_a_gate_a_parseable_body_is_judged_over_its_own_turns() {
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
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    let outcome = drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    assert_eq!(far.sent().len(), 1, "the body went through");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![vec![("user".to_string(), "hello".to_string())]],
        "the gate judged the request's own turn"
    );
}

#[tokio::test]
async fn an_unparseable_body_with_only_a_policy_is_judged_as_a_null_body_and_served() {
    let (seen, policy) = gate(None);
    let mut hooks = bound(Vec::new(), Vec::new());
    hooks.pool_policies.insert("pool-a".to_string(), policy);
    let far = Far::new(&["ok"], &[b"done"]).naming_its_pool();
    let (outcome, rendered, sent, _) = unparseable_over(hooks, far).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    assert_eq!(rendered, None, "nothing was refused");
    assert_eq!(sent, 1, "the body went through");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Vec::<(String, String)>::new()],
        "the policy judged once, over a Null body: no turns"
    );
}

#[tokio::test]
async fn a_gate_first_unparseable_body_with_only_gates_is_judged_and_served() {
    for (send_prompt, reject, want_sent, want_seen) in [
        (false, None, 1, 1),
        (true, None, 1, 0),
        (false, Some((451, "blocked")), 0, 1),
    ] {
        let (seen, g) = gate_granted(reject, send_prompt);
        let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
        let driver = r.driver.with_hooks(Arc::new(GatedBinder {
            rewrites: Vec::new(),
            gates: vec![(0, g)],
        }));
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = driver.unit(
            &steps,
            &far,
            &caller,
            arrival("/unparseable", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        let case = format!("send_prompt {send_prompt}, reject {reject:?}");
        assert_eq!(far.sent().len(), want_sent, "{case}: {outcome:?}");
        assert_eq!(seen.lock().unwrap().len(), want_seen, "{case}");
        match reject {
            None => assert!(matches!(outcome, Outcome::Completed), "{case}: {outcome:?}"),
            Some((status, _)) => {
                let rendered = units.take_rendered().expect("the veto is rendered");
                assert_eq!(rendered.status, u32::from(status), "{case}");
            }
        }
    }
}

#[tokio::test]
async fn every_fault_but_the_marked_unparseable_one_on_a_gate_only_route_is_refused_400() {
    for target in [
        "/panics",
        "/no-crossing",
        "/fault-unmarked",
        "/broken-answer",
    ] {
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
        let units = r
            .driver
            .unit(&steps, &far, &caller, arrival(target, b"user:hello"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Failed(_, ReasonCode::DecodeFailed)),
            "{target}: {outcome:?}"
        );
        assert_eq!(
            units.take_rendered().map(|r| r.status),
            Some(400),
            "{target}"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "{target}: no gate judged it"
        );
        assert!(far.sent().is_empty(), "{target}: never dialled");

        let (seen, g) = gate_granted(None, false);
        let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
        let driver = r.driver.with_hooks(Arc::new(GatedBinder {
            rewrites: Vec::new(),
            gates: vec![(0, g)],
        }));
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = driver.unit(&steps, &far, &caller, arrival(target, b"user:hello"), 0);
        let outcome = drive(&units).await;
        assert!(
            !matches!(outcome, Outcome::Completed),
            "{target}, gate-first: refused, {outcome:?}"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "{target}, gate-first: no gate judged it"
        );
        assert!(far.sent().is_empty(), "{target}, gate-first: never dialled");
    }
}

#[tokio::test]
async fn a_gate_first_unmarked_fault_with_a_configured_rewrite_is_the_shared_500() {
    for target in [
        "/panics",
        "/no-crossing",
        "/fault-unmarked",
        "/broken-answer",
    ] {
        let (calls, chain) = counting(|| TransformOutcome::Abstain);
        let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
        let driver = r.driver.with_hooks(Arc::new(GatedBinder {
            gates: Vec::new(),
            rewrites: chain,
        }));
        let (steps, far, caller) = (
            TestUnits::passing(),
            Far::new(&["ok"], &[b"done"]),
            Caller::default(),
        );
        let units = driver.unit(&steps, &far, &caller, arrival(target, b"user:hello"), 0);
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Refused(_, ReasonCode::HookVeto)),
            "{target}: {outcome:?}"
        );
        let rendered = units.take_rendered().expect("the 500 is rendered");
        assert_eq!(
            (rendered.status, rendered.body),
            (500, shared_500()),
            "{target}"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{target}: no hook ran"
        );
        assert!(far.sent().is_empty(), "{target}: never dialled");
    }
}

/// Every hook report the stage made, as the node would be handed it.
#[derive(Default)]
struct Reports(Mutex<Vec<HooksRan>>);

impl HookJournal for Reports {
    fn hooks_ran(&self, record: &HooksRan) {
        self.0.lock().unwrap().push(record.clone());
    }
}

fn ran(hook: &str, head: HookHead, failed: bool) -> HookApplied {
    HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    }
}

async fn reported(hooks: BoundHooks) -> Vec<HooksRan> {
    let mut r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let reports = Arc::new(Reports::default());
    r.driver = r
        .driver
        .with_hook_journal(Arc::clone(&reports) as Arc<dyn HookJournal>);
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    let _ = drive(&units).await;
    let out = reports.0.lock().unwrap().clone();
    out
}

#[tokio::test]
async fn the_stage_reports_each_hook_that_ran_in_order_with_its_head() {
    let (_, g) = gate(None);
    let reports = reported(bound(
        vec![(Duration::from_millis(500), Arc::new(Rewriter))],
        vec![(0, g)],
    ))
    .await;
    assert_eq!(
        reports,
        vec![HooksRan {
            unit: busbar_contract::UnitKey::new(7),
            hooks: vec![
                ran("rewriter", HookHead::Modify, false),
                ran("gate", HookHead::Pass, false),
            ],
        }],
    );
}

#[tokio::test]
async fn the_stage_reports_a_hook_that_failed_as_failed() {
    let reports = reported(bound(
        vec![(Duration::from_millis(500), Arc::new(LoadBearingDown))],
        Vec::new(),
    ))
    .await;
    assert_eq!(
        reports,
        vec![HooksRan {
            unit: busbar_contract::UnitKey::new(7),
            hooks: vec![ran("load-bearing-down", HookHead::Veto, true)],
        }],
    );
}
