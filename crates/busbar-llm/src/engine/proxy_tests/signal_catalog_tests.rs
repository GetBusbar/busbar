//! Tests for the "decision observability" signal catalog substrate:
//! `busbar_api::Signal`/`SignalValue`/`SignalBag`, the `RequestedSignals` declared-signal gate
//! (`busbar_core::hooks::requested_signals`/`RequestedSignals::wants`), and the two health signals
//! wired into `decide_policy_order`'s candidate loop (`CandidateBreakerState`/`CandidateErrorRate`).
//! Proves: a declared signal is computed + projected; an undeclared signal is absent AND never
//! computed; the default (nothing declared) path never allocates the signal bag past its inline
//! capacity; breaker_state/error_rate project real store state correctly. The pre-existing hook/tap
//! tests (`hook_seam_tests.rs`, `hooks/tests/tests.rs`, `hooks/wire.rs`'s inline tests) are asserted
//! unchanged elsewhere — this file only covers the NEW substrate.

use super::*;
use crate::engine::WeightedLane;
use crate::test_support::{LaneSpec, TestApp};
use busbar_api::{Signal, SignalValue};
use busbar_core::hooks::{Candidate, PolicyResult, ResolvedPolicy, RoutingContext, RoutingPolicy};
use std::sync::Mutex as StdMutex;

/// A no-op policy that just records the candidate projections it was handed, then Abstains.
struct CapturingCandidatesPolicy {
    seen: std::sync::Arc<StdMutex<Option<Vec<busbar_api::SignalBag>>>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for CapturingCandidatesPolicy {
    async fn decide(
        &self,
        _req: &busbar_core::hooks::RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        *self.seen.lock().unwrap() = Some(candidates.iter().map(|c| c.signals.clone()).collect());
        Ok(busbar_core::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "capture-candidates"
    }
}

/// A minimal `HookCfg` whose only interesting field is `signals:` — registered in the app's
/// `hooks:` registry (never wired as the pool's actual policy) purely to populate
/// `App::requested_signals` via `hooks::requested_signals`'s union-across-every-hook walk, exactly
/// as an operator's real `signals:` declaration would.
fn declaring_hook(signals: Vec<Signal>) -> busbar_core::config::HookCfg {
    busbar_core::config::HookCfg {
        kind: busbar_core::config::HookKind::Tap,
        plugin: "test-hook".to_string(),
        timeout_ms: busbar_core::config::DEFAULT_POLICY_TIMEOUT_MS,
        on_error: "weighted".to_string(),
        prompt: busbar_core::config::PromptAccess::No,
        user: busbar_core::config::UserAccess::No,
        priority: 0,
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
async fn run_with_declared(signals: Vec<Signal>) -> Vec<busbar_api::SignalBag> {
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
    run_decide(&app).await
}

/// Run `decide_policy_order` once against an ALREADY-BUILT one-lane app, returning the
/// per-candidate signal bags the policy observed. Split out of [`run_with_declared`] so a test can
/// hand in a snapshot produced by the ADMIN builders rather than by the `TestApp` fixture.
async fn run_decide(app: &std::sync::Arc<busbar_core::state::App>) -> Vec<busbar_api::SignalBag> {
    let seen = std::sync::Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: std::sync::Arc::new(CapturingCandidatesPolicy { seen: seen.clone() }),
        on_error: busbar_core::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_core::config::PolicyOnError::Reject,
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
        app,
        &resolved,
        &cands,
        &rc,
        &v,
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_core::operation::Operation::CHAT,
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

/// A hook registered THROUGH THE ADMIN API (`POST /api/v1/admin/hooks`'s pure core,
/// `service::build_with_hook`) must have its `signals:` declaration take effect on the very next
/// request — exactly as a hook declared in `config.yaml` does. `HookCfg::signals`'s own contract
/// says declaring a signal is "necessary AND sufficient for it to start being computed +
/// projected; nothing else is required", and the runtime-register path is a config apply like any
/// other.
///
/// Without the recompute this is a FAIL-OPEN of the same shape as the `reresolve_plane_gates` and
/// `tools.hooks:` defects: the operator gets `200 OK`, the hook fires, and every candidate payload
/// it is handed silently lacks the signal it declared — until the process restarts and `main.rs`
/// rebuilds the mask from the persisted overlay.
#[tokio::test]
async fn admin_registered_hook_signals_take_effect_on_the_next_request() {
    crate::testkit::install_test_seams();
    // PANIC, never skip: a rig that skips when the cdylib is missing reports green over the exact
    // code it was written to cover. `cargo build -p busbar-hook-test-plugin` (or a `--workspace`
    // build) is a precondition of this test, not an option.
    let env = crate::test_support::test_hook_env(&["test-hook"], Default::default()).expect(
        "the hook-test plugin cdylib must be built for this test (cargo build -p \
         busbar-hook-test-plugin); refusing to skip the admin-register signal coverage",
    );
    let app = TestApp::new()
        .hook_env(env)
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://localhost",
        ))
        .pool("p", &[(0, 1)])
        .build();
    // Nothing declared at boot: the baseline the operator is about to change.
    assert!(
        run_decide(&app).await[0]
            .get(Signal::CandidateBreakerState)
            .is_none(),
        "no hook declared a signal at boot; the bag must start empty"
    );

    let registered = busbar_core::admin::v1::service::build_with_hook(
        &app,
        "declarer",
        declaring_hook(vec![Signal::CandidateBreakerState]),
    )
    .expect("registering a signal-declaring hook must succeed");

    let bags = run_decide(&std::sync::Arc::new(registered.clone())).await;
    match bags[0].get(Signal::CandidateBreakerState) {
        Some(SignalValue::Str(s)) => assert_eq!(s.as_ref(), "closed"),
        other => panic!(
            "a hook registered through the admin API declared \
             `signals: [candidate.breaker_state]`, so the very next request's candidate bag must \
             carry it; got {other:?}. `App::requested_signals` was not recomputed from the \
             rewritten `hook_registry`."
        ),
    }

    // ...and the mask closes again when the last declaring hook is deleted, so the engine stops
    // computing a signal nobody asked for.
    let deleted = busbar_core::admin::v1::service::build_without_hook(&registered, "declarer")
        .expect("deleting the hook must succeed");
    assert!(
        deleted.requested_signals.is_empty(),
        "deleting the last signal-declaring hook must close the compute gate again"
    );
}

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
    // Force the ROUTING POOL cell (not the lane-default cell) Open with a cooldown far in the
    // future, so the projected state reads "open" (not an already-expired-back-to-recoverable one).
    app.store
        .force_open_in("p", 0, busbar_core::store::now() + 3600);

    let seen = std::sync::Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: std::sync::Arc::new(CapturingCandidatesPolicy { seen: seen.clone() }),
        on_error: busbar_core::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_core::config::PolicyOnError::Reject,
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
        &app,
        &resolved,
        &cands,
        &rc,
        &v,
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_core::operation::Operation::CHAT,
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
    let cfg = busbar_core::store::BreakerCfg::default();
    // 1 error + 3 successes = 25% error rate, well under the default trip threshold (so the
    // breaker itself stays Closed — this test is purely about the PROJECTED rate).
    app.store.record_transient_in("p", 0, "test", &cfg, None);
    app.store.record_success_in("p", 0);
    app.store.record_success_in("p", 0);
    app.store.record_success_in("p", 0);

    let seen = std::sync::Arc::new(StdMutex::new(None));
    let resolved = ResolvedPolicy::Policy {
        policy: std::sync::Arc::new(CapturingCandidatesPolicy { seen: seen.clone() }),
        on_error: busbar_core::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_core::config::PolicyOnError::Reject,
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
        &app,
        &resolved,
        &cands,
        &rc,
        &v,
        &[],
        crate::engine::APPLICATION_JSON,
        "p",
        "anthropic",
        busbar_core::operation::Operation::CHAT,
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
