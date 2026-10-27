// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK STAGE ON THE DRIVER, against the contract-level plane double (`BUSBAR-1.6.0.md` Part 3,
//! section 12, "Hooks"; ARCHITECT K5): no hook bound projects nothing; a request-stage hook's
//! rewrite goes back to the plane (`ProjectIn::rewrite`), which applies it and answers the body the
//! kernel keeps and re-pushes on every attempt; a veto wears the hook's own status and words,
//! rendered by the plane (`REFUSAL_GATE`), before any attempt; a request the plane cannot project
//! is refused before any attempt. The 1.5.5 hook tests themselves run over the real plane serving
//! the `pools` map in the composition root's `hook_parity_driver` suite.

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

/// A caller the hooks know nothing of.
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
    gate_granted(reject, true)
}

/// [`gate`], with or without the prompt granted.
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

/// A rewrite hook declared load-bearing whose call failed: what the resolver's `on_error: reject`
/// decorator hands every firing site (the shared refusal, minted as a transform reject).
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

/// RED (THE DESIGN §11.7, HOOK Q1, owner-signed 2026-10-02): a load-bearing rewrite that could not
/// answer refuses the routed request with the shared retryable 503 and its words, the refusal the
/// gate-first stage and every gate seat answer, never clamped to a 403.
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

// ── a rewrite the plane refuses to apply ────────────────────────────────────────────────────────

/// The `prompt: rw` gate `rw` with `on_error`, resolved through the kernel's own rewrite resolver
/// over the hook double (which answers every `transform` with a rewrite), so the chain entry is the
/// one a deployment's configuration produces, its `on_error` disposition and all.
fn resolved_rewrite(on_error: &str) -> Vec<(Duration, Arc<dyn RoutingPolicy>)> {
    let env = busbar_kernel::test_support::test_hook_env(
        &["test-hook"],
        busbar_kernel::test_support::HookNeeds {
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

/// RED (coordinator ruling, row 159): a plane that REFUSES to apply a request-stage hook's rewrite
/// (the rewrite names a model other than the routed one, say) has met that hook's failure, and the
/// hook's own `on_error` answers it, never a unit failure and never a silent provider switch:
/// - `on_error: weighted` (and `first`): the unit proceeds with the body and view it had before
///   that rewrite, as 1.5.5 relayed a rewrite it could not apply (the request unmodified);
/// - `on_error: reject`: the unit is refused with the shared retryable 503 and its words, the
///   refusal a failed call of that hook answers, before any attempt.
///
/// RED before: the refused re-projection stopped the unit as unreadable (`DecodeFailed`, 400)
/// whatever the hook's `on_error` said.
#[tokio::test]
async fn a_rewrite_the_plane_refuses_is_the_hooks_failure_answered_by_its_on_error() {
    for on_error in ["weighted", "first"] {
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
            arrival("/refuses-rewrite", b"user:hello"),
            0,
        );
        let outcome = drive(&units).await;
        assert!(
            matches!(outcome, Outcome::Completed),
            "on_error: {on_error}: {outcome:?}"
        );
        let projects = r.projects();
        assert_eq!(
            projects.len(),
            2,
            "on_error: {on_error}: the view, then the refused rewrite"
        );
        assert!(
            !projects[1].1.is_empty(),
            "on_error: {on_error}: the rewrite crossed"
        );
        let sent = far.sent();
        assert_eq!(sent.len(), 1, "on_error: {on_error}: one attempt");
        assert_eq!(
            sent[0].body, b"user:hello",
            "on_error: {on_error}: the request proceeds unmodified"
        );
    }

    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(resolved_rewrite("reject"), Vec::new())),
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
        arrival("/refuses-rewrite", b"user:hello"),
        0,
    );
    let outcome = drive(&units).await;
    assert!(
        matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
        "on_error: reject: {outcome:?}"
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

/// A gate-first binder attaching `gates` and `rewrites` to every entry.
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
        })
    }
}

/// RED, the gate-first twin: the entry's rewrite the plane refuses to apply is the rewriting
/// hook's failure. `on_error: weighted` serves the unit with its own body; `on_error: reject`
/// refuses it at the screen with the shared 503, named for the hook, nothing sent. RED before:
/// both were refused as unreadable.
#[tokio::test]
async fn a_gate_first_rewrite_the_plane_refuses_is_answered_by_the_hooks_on_error() {
    let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
    let driver = r.driver.with_hooks(Arc::new(GatedBinder {
        gates: Vec::new(),
        rewrites: resolved_rewrite("weighted"),
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
        arrival("/refuses-rewrite", b"user:hello"),
        0,
    );
    let outcome = drive(&units).await;
    assert!(
        !matches!(outcome, Outcome::Refused(..) | Outcome::Failed(..)),
        "on_error: weighted: {outcome:?}"
    );
    let sent = far.sent();
    assert!(
        !sent.is_empty(),
        "on_error: weighted: the far end was reached"
    );
    for request in &sent {
        assert_eq!(
            request.body, b"user:hello",
            "on_error: weighted: the request proceeds unmodified"
        );
    }

    let r = super::rig(Way::Double, BufferCaps::default(), Book::default());
    let driver = r.driver.with_hooks(Arc::new(GatedBinder {
        gates: Vec::new(),
        rewrites: resolved_rewrite("reject"),
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
        arrival("/refuses-rewrite", b"user:hello"),
        0,
    );
    let outcome = drive(&units).await;
    assert!(
        matches!(outcome, Outcome::Refused(_, ReasonCode::HookVeto)),
        "on_error: reject: {outcome:?}"
    );
    let rendered = units.take_rendered().expect("the veto is rendered");
    assert_eq!(
        rendered.status,
        u32::from(busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS)
    );
    assert!(far.sent().is_empty(), "nothing reached the far end");
}

/// RED (row 159, B1): a plane that answers FAULT to a `project` carrying a request-stage hook's
/// rewrite (a redaction it cannot apply) is answered with the shared 500 and its words under EVERY
/// `on_error`, never the hook's disposition, and the far end is never dialled.
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

/// The gate-first twin of the above: the entry's rewrite whose project FAULTs is the shared 500
/// under every `on_error`, nothing sent.
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

/// A rewrite hook that counts its invocations and abstains, fails or rejects as told: whichever it
/// does, it must never run over a body the plane could not parse.
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

/// How a configured rewrite hook may answer: abstain, fail, reject.
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

/// A counting rewrite chain: its invocation count, and the chain.
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

/// RED (v1.5.5 `proxy/engine/mod.rs:728`, `:749`): a rewrite hook CONFIGURED for the route has the
/// document materialized before any hook runs, so a body that will not parse is the shared 500 even
/// when the hook would have abstained, failed or rejected: the hook is never invoked and nothing is
/// dialled.
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

/// RED: the same for a rewrite the POOL configures, with no global rewrite hook. The far end names
/// its pool to the hooks, as the kernel's egress walk does: a pool's hooks bind only so.
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

/// The gate-first twin: the entry's configured rewrite hook, the first `project` FAULTs, no hook
/// runs, the shared 500, nothing dialled.
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

/// GREEN twin: no rewrite hook configured (nothing bound at all), so `project` is not called up
/// front and the body passes through to the far end.
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

/// What [`unparseable_under`] answers: the unit's outcome, the rendered refusal (status, body), the
/// attempts the far end received and every `project` crossing (body, rewrite).
type Driven = (
    Outcome,
    Option<(u32, Vec<u8>)>,
    usize,
    Vec<(Vec<u8>, Vec<u8>)>,
);

/// Drive one unit of `/unparseable` (the double answers FAULT to its every `project`) under
/// `hooks`: the outcome, what was rendered, and how many attempts reached the far end.
async fn unparseable_under(hooks: BoundHooks) -> Driven {
    unparseable_over(hooks, Far::new(&["ok"], &[b"done"])).await
}

/// [`unparseable_under`], over `far`.
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

/// RED (opus review B1; v1.5.5 `proxy/engine/mod.rs:957-961`): with a decision gate bound and no
/// rewrite configured (no hook, no pool rewrite), a body the plane cannot parse is no 500 and no
/// 400. 1.5.5 materialized the document for its gates and, when it would not parse, the gates
/// judged a Null body and the request proceeded: the gate judges the zeroed view (no turns) and
/// the unit is served. RED before: the FAULT was read as an unreadable request, 400 `DecodeFailed`.
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
    // The gate still judges: one that rejects refuses the unit with its own status and words.
    let (_, g) = gate(Some((451, "blocked")));
    let (_, rendered, sent, _) = unparseable_under(bound(Vec::new(), vec![(0, g)])).await;
    assert_eq!(rendered, Some((451, b"refused:451:blocked".to_vec())));
    assert_eq!(sent, 0, "never dialled");
}

/// GREEN twin: gates only, a body the plane parses. The up-front `project` answers the view and
/// the gate judges the request's own turns, the unit served.
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

/// RED (opus review B1; v1.5.5 `proxy/engine/mod.rs:1330`, the policy's document read `.ok()`):
/// the same with only a base routing policy bound for the pool: it judges the zeroed view and the
/// unit is served. RED before: 400 `DecodeFailed`.
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

/// RED, the gate-first twin (opus review B1): the entry has gates and no rewrite, and the first
/// `project` FAULTs. The gates judge a view with no body and the unit is served: a gate shown the
/// shape judges it (one that rejects refuses, with its status and words), and a gate granted the
/// content applies its `on_error` (here `weighted`, which proceeds), as it does for any body it
/// cannot read. RED before: refused as unreadable.
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

/// GUARD (lead rulings on #1500; dev answers these 400 too): only the plane's own FAULT marked
/// `PROJECT_FAULT_UNPARSEABLE` takes
/// the Null-view path. Every other FAULT on a gate-only route is a broken plane and fails closed,
/// unreadable (400), before any gate judges it and before any attempt: a slot that panicked (its
/// door writes nothing but the outcome), a frame refused before the crossing or a quarantined
/// instance (the `out` as the host lent it), a FAULT the plane answered without the mark, and a
/// READY answer the host's kind check refused (a FAULT the host minted, the mark's bit among the
/// plane's own view flags even). The same at a gate-first screen.
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

/// RED (opus review of #1500): at a gate-first screen the first `project` is made before the entry
/// is bound, so it cannot know a rewrite is configured. An UNMARKED FAULT there (a panicking slot, no
/// crossing, a FAULT without the mark, a READY answer the host's check refused) over an entry that
/// carries a rewrite is the shared 500, no hook invoked and nothing dialled, as dev answered it and
/// as the routed path does. RED before: 400, the unit read as unreadable without the rewrite looked at.
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

/// One hook that ran, keyed `hook`.
fn ran(hook: &str, head: HookHead, failed: bool) -> HookApplied {
    HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    }
}

/// Drive one unit through `hooks` with the stage reporting to a [`Reports`], and hand back what it
/// reported.
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

/// THE STAGE REPORTS EACH HOOK THAT RAN (audit root#3; THE DESIGN §1: the record's "controls (...
/// hooks applied)"): once for the unit, under its key, in the order the hooks ran, each by its key
/// with its decision head. The rewrite changed the request; the gate after it let it through.
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

/// A HOOK THAT FAILED IS REPORTED FAILED, never dropped: the load-bearing rewrite that could not
/// answer stopped the unit, and the report names it as the veto it became, failed.
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
