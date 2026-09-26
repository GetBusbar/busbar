//! Tests for the "decision observability" signal catalog substrate:
//! `busbar_contract::signal::Signal`/`SignalValue`/`SignalBag`, the `RequestedSignals` declared-signal gate
//! (`busbar_kernel::hooks::requested_signals`/`RequestedSignals::wants`), and the two health signals
//! wired into `decide_policy_order`'s candidate loop (`CandidateBreakerState`/`CandidateErrorRate`).
//! Proves: a declared signal is computed + projected; an undeclared signal is absent AND never
//! computed; the default (nothing declared) path never allocates the signal bag past its inline
//! capacity; breaker_state/error_rate project real store state correctly. The pre-existing hook/tap
//! tests (`hook_seam_tests.rs`, `hooks/tests/tests.rs`, `hooks/wire.rs`'s inline tests) are asserted
//! unchanged elsewhere — this file only covers the NEW substrate.

use super::*;
use crate::engine::WeightedLane;
use crate::test_support::{LaneSpec, TestApp};
use busbar_contract::hooks::{Candidate, PolicyResult, RoutingContext, RoutingPolicy};
use busbar_contract::signal::{Signal, SignalValue};
use busbar_kernel::hooks::ResolvedPolicy;
use std::sync::Mutex as StdMutex;

/// A no-op policy that just records the candidate projections it was handed, then Abstains.
struct CapturingCandidatesPolicy {
    seen: std::sync::Arc<StdMutex<Option<Vec<busbar_contract::signal::SignalBag>>>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for CapturingCandidatesPolicy {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        *self.seen.lock().unwrap() = Some(candidates.iter().map(|c| c.signals.clone()).collect());
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "capture-candidates"
    }
}

/// A minimal `HookCfg` whose only interesting field is `signals:` — registered in the app's
/// `hooks:` registry (never wired as the pool's actual policy) purely to populate
/// `App::requested_signals` via `hooks::requested_signals`'s union-across-every-hook walk, exactly
/// as an operator's real `signals:` declaration would.
fn declaring_hook(signals: Vec<Signal>) -> busbar_kernel::config::hooks::HookCfg {
    busbar_kernel::config::hooks::HookCfg {
        kind: busbar_kernel::config::hooks::HookKind::Tap,
        plugin: "test-hook".to_string(),
        timeout_ms: busbar_kernel::config::hooks::DEFAULT_POLICY_TIMEOUT_MS,
        on_error: "weighted".to_string(),
        prompt: busbar_kernel::config::hooks::PromptAccess::No,
        user: busbar_kernel::config::hooks::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals,
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// Build a one-lane TestApp (optionally with a `signals:`-declaring hook registered) and run
/// `decide_policy_order` once, returning the per-candidate signal bags the policy observed.
async fn run_with_declared(signals: Vec<Signal>) -> Vec<busbar_contract::signal::SignalBag> {
    let mut builder = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://localhost",
        ))
        .pool("p", &[(0, 1)]);
    if !signals.is_empty() {
        builder = builder.hook("declarer", declaring_hook(signals));
    }
    let app = builder.build();
    let (_host, _rt) = crate::engine::test_host_rt(&app);
    run_decide(&app).await
}

/// Run `decide_policy_order` once against an ALREADY-BUILT one-lane app, returning the
/// per-candidate signal bags the policy observed. Split out of [`run_with_declared`] so a caller can
/// hand in any already-built snapshot rather than only the one the `TestApp` fixture produces.
async fn run_decide<A: busbar_kernel::test_support::BuiltAppSeam + ?Sized>(
    app: &std::sync::Arc<A>,
) -> Vec<busbar_contract::signal::SignalBag> {
    let (host, rt) = crate::engine::test_host_rt(app);
    let seen = std::sync::Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: std::sync::Arc::new(CapturingCandidatesPolicy { seen: seen.clone() }),
        on_error: busbar_kernel::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_kernel::config::PolicyOnError::Reject,
    };
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    let rc = RequestCtx::new(60, 1);
    let v = serde_json::json!({"model": "m0", "messages": [{"role": "user", "content": "hi"}]});
    let _out = decide_policy_order(
        &host,
        &rt,
        &resolved,
        &cands,
        &rc,
        &v,
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_contract::operation::OpVerb::CHAT,
        false,
        None,
        None,
    )
    .await;
    let out = seen
        .lock()
        .unwrap()
        .clone()
        .expect("policy must have been called");
    out
}

/// A declared signal (`CandidateBreakerState`) is computed and projects into the candidate's bag —
/// a fresh lane's breaker starts Closed, so the projected value is the `"closed"` label.
#[tokio::test]
async fn declared_signal_is_computed_and_projected() {
    crate::testkit::install_test_seams();
    let bags = run_with_declared(vec![Signal::CandidateBreakerState]).await;
    assert_eq!(bags.len(), 1);
    match bags[0].get(Signal::CandidateBreakerState) {
        Some(SignalValue::Str(s)) => assert_eq!(s.as_ref(), "closed"),
        other => panic!("expected CandidateBreakerState = Str(\"closed\"), got {other:?}"),
    }
    // Only the declared signal is present — CandidateErrorRate was never asked for.
    assert!(bags[0].get(Signal::CandidateErrorRate).is_none());
}

// The admin runtime-register path's `signals:` recompute (`build_with_hook`/`build_without_hook`
// opening then closing `App::requested_signals`) is proven in `busbar-admin`'s
// `hook_derived_fields_follow_the_registry`, which asserts the same
// `requested_signals.wants(CandidateBreakerState)` / `is_empty()` contract directly on the admin
// snapshots. Composed with `declared_signal_is_computed_and_projected` below (which proves the
// engine projects any signal a correct `requested_signals` mask requests), that is the full
// end-to-end guard — and it keeps this plane crate off a `busbar-admin` edge it must not name. The
// duplicate that lived here (calling `busbar_kernel::admin::v1::service::build_with_hook`) was removed
// when the admin service was extracted to `busbar-admin`.

/// An UNDECLARED signal is absent from the projected bag (never computed) — the exact "declared
/// signal in, everything else out" contract.
#[tokio::test]
async fn undeclared_signal_is_absent() {
    crate::testkit::install_test_seams();
    let bags = run_with_declared(vec![Signal::CandidateBreakerState]).await;
    assert!(
        bags[0].get(Signal::CandidateErrorRate).is_none(),
        "CandidateErrorRate was not declared by any hook; it must not appear"
    );
}

/// The DEFAULT path — no hook anywhere declares a `signals:` entry — computes nothing extra: the
/// candidate's bag is empty AND never spills its inline `SmallVec` capacity onto the heap. This is
/// the "zero cost when undeclared" guarantee's proof: `RequestedSignals` is the all-zero bitmask,
/// `requested.is_empty()` short-circuits `decide_policy_order`'s candidate-signal block entirely, so
/// `SignalBag::push` is never called.
#[tokio::test]
async fn default_path_allocates_no_signals_container() {
    crate::testkit::install_test_seams();
    let bags = run_with_declared(Vec::new()).await;
    assert_eq!(bags.len(), 1);
    assert!(bags[0].is_empty(), "no hook declared any signal");
    assert!(
        !bags[0].spilled(),
        "an empty (or ≤4-entry) SignalBag must never spill onto the heap"
    );
}

/// `CandidateBreakerState` tracks the REAL breaker FSM state: forcing the (pool, lane) cell Open
/// (the same test primitive the pre-existing breaker regression tests use) flips the projected
/// label from `"closed"` to `"open"`.
#[tokio::test]
async fn breaker_state_projects_open_after_a_trip() {
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .hook(
            "declarer",
            declaring_hook(vec![Signal::CandidateBreakerState]),
        )
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    // Force the ROUTING POOL cell (not the lane-default cell) Open with a cooldown far in the
    // future, so the projected state reads "open" (not an already-expired-back-to-recoverable one).
    app.store
        .force_open_in("p", 0, busbar_kernel::store::now() + 3600);

    let seen = std::sync::Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: std::sync::Arc::new(CapturingCandidatesPolicy { seen: seen.clone() }),
        on_error: busbar_kernel::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_kernel::config::PolicyOnError::Reject,
    };
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    let rc = RequestCtx::new(60, 1);
    let v = serde_json::json!({"model": "m0", "messages": [{"role": "user", "content": "hi"}]});
    let _ = decide_policy_order(
        &host,
        &rt,
        &resolved,
        &cands,
        &rc,
        &v,
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_contract::operation::OpVerb::CHAT,
        false,
        None,
        None,
    )
    .await;
    let bags = seen
        .lock()
        .unwrap()
        .clone()
        .expect("policy must have been called");
    match bags[0].get(Signal::CandidateBreakerState) {
        Some(SignalValue::Str(s)) => assert_eq!(s.as_ref(), "open"),
        other => panic!("expected CandidateBreakerState = Str(\"open\"), got {other:?}"),
    }
}

/// `CandidateErrorRate` projects the breaker's own sliding outcome-window error rate: recording a
/// mix of successes/failures against the (pool, lane) cell, then declaring the signal, yields the
/// exact fraction — a PURE projection of state the breaker already tracks (no new collection).
#[tokio::test]
async fn error_rate_projects_the_outcome_window_fraction() {
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .hook("declarer", declaring_hook(vec![Signal::CandidateErrorRate]))
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let cfg = busbar_kernel::store::BreakerCfg::default();
    // 1 error + 3 successes = 25% error rate, well under the default trip threshold (so the
    // breaker itself stays Closed — this test is purely about the PROJECTED rate).
    app.store.record_transient_in("p", 0, "test", &cfg, None);
    app.store.record_success_in("p", 0);
    app.store.record_success_in("p", 0);
    app.store.record_success_in("p", 0);

    let seen = std::sync::Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: std::sync::Arc::new(CapturingCandidatesPolicy { seen: seen.clone() }),
        on_error: busbar_kernel::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_kernel::config::PolicyOnError::Reject,
    };
    let cands = vec![WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    let rc = RequestCtx::new(60, 1);
    let v = serde_json::json!({"model": "m0", "messages": [{"role": "user", "content": "hi"}]});
    let _ = decide_policy_order(
        &host,
        &rt,
        &resolved,
        &cands,
        &rc,
        &v,
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_contract::operation::OpVerb::CHAT,
        false,
        None,
        None,
    )
    .await;
    let bags = seen
        .lock()
        .unwrap()
        .clone()
        .expect("policy must have been called");
    match bags[0].get(Signal::CandidateErrorRate) {
        Some(SignalValue::F64(rate)) => assert!(
            (*rate - 0.25).abs() < 1e-9,
            "expected 1/4 = 0.25 error rate, got {rate}"
        ),
        other => panic!("expected CandidateErrorRate = F64(0.25), got {other:?}"),
    }
}
