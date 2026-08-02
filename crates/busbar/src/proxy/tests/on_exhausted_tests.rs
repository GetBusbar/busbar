use crate::config;

#[test]
fn test_config_parsing_status_503() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("reject").unwrap();
    assert!(matches!(cfg.to_runtime(), config::OnExhausted::Status503));
}

#[test]
fn test_config_parsing_least_bad() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("least_bad").unwrap();
    assert!(matches!(cfg.to_runtime(), config::OnExhausted::LeastBad));
}

#[test]
fn test_config_parsing_fallback_pool() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("{ fallback_pool: drain }").unwrap();
    if let config::OnExhausted::FallbackPool(name) = cfg.to_runtime() {
        assert_eq!(name, "drain");
    } else {
        panic!("Expected FallbackPool variant");
    }
}

#[test]
fn test_config_parsing_unknown_fails() {
    let result: Result<config::OnExhaustedCfg, _> = serde_yaml::from_str("invalid");
    assert!(result.is_err(), "Unknown action should fail parsing");
}

#[test]
fn test_config_parsing_bare_fallback_pool_fails() {
    // The old colon form `fallback_pool:drain` is no longer a bare keyword; only the
    // structured `{ fallback_pool: name }` map is accepted.
    let result: Result<config::OnExhaustedCfg, _> = serde_yaml::from_str("'fallback_pool:drain'");
    assert!(result.is_err(), "Colon-form keyword should fail parsing");
}

// ── least_bad routing ────────────────────────────────────────────────────────────────────────────
// `least_bad` is licensed to override ONE thing: the circuit breaker, an inference busbar drew from
// observed failures. It is not licensed to override operator declarations — a `failover.exclusions`
// blocklist, a `dead` mark, or an exhausted `max_requests` budget. These assert that boundary.

use crate::proxy::forward_with_pool;
use crate::state::{now, WeightedLane};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::json;
use std::sync::Arc;

async fn ok_server_for(model: &'static str) -> MockServer {
    let state = Arc::new(MockServerState::new());
    for _ in 0..4 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "role": "assistant",
                "content": [{"type": "text", "text": "hi"}],
                "model": model,
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    MockServer::new(state).await
}

fn lane(idx: usize) -> WeightedLane {
    WeightedLane {
        reasoning: None,
        idx,
        weight: 1,
        attempt_timeout_ms: None,
    }
}

fn chat_body(pool: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"model": pool, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    .unwrap()
}

fn pool_runtime_with_exclusions(excl: Option<Vec<String>>) -> crate::state::PoolRuntime {
    crate::state::PoolRuntime {
        members: Default::default(),
        failover: Some(crate::config::FailoverCfg {
            timeout_secs: 120,
            exclusions: excl,
            max_hops: 3,
        }),
        affinity: None,
        breaker: None,
        policy: None,
        gates: Vec::new(),
        rewrite_hooks: Vec::new(),
    }
}

/// `least_bad` must not reach for a member the operator blocklisted. `docs/failover.md` promises an
/// excluded member "can never" be landed on and that automatic selection "never spends on it" — the
/// whole point being that it is the expensive last resort a human invokes deliberately. Reaching
/// for it precisely when everything else is on fire inverts that.
#[tokio::test]
async fn least_bad_never_reaches_an_excluded_member() {
    crate::metrics::init();
    let server_a = ok_server_for("alpha").await;
    let server_b = ok_server_for("beta").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "alpha",
                crate::proto::Protocol::anthropic(),
                &server_a.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "beta",
                crate::proto::Protocol::anthropic(),
                &server_b.base_url(),
            )
            .provider("p"),
        )
        .pool("pe", &[(0, 1), (1, 1)])
        .pool_runtime(
            "pe",
            pool_runtime_with_exclusions(Some(vec!["beta".into()])),
        )
        .on_exhausted("pe", crate::config::OnExhausted::LeastBad)
        .build();

    // alpha is the only eligible member and its breaker is Open → the pool is exhausted.
    app.store.force_open_in("pe", 0, now() + 300);

    let resp = forward_with_pool(
        app.clone(),
        vec![lane(0), lane(1)],
        chat_body("pe").into(),
        None,
        "pe",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        0,
        "the excluded member must not serve the degraded dispatch"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        1,
        "least_bad must degrade onto the eligible Open member, not the blocklisted healthy one"
    );
    server_a.shutdown().await;
    server_b.shutdown().await;
}

/// Deadness lives outside the breaker cell, so a dead lane reports a cooldown of 0 and would sort
/// FIRST — beating a lane that genuinely recovers in seconds. `least_bad` must rank only among
/// lanes that could actually serve.
#[tokio::test]
async fn least_bad_ranks_only_admissible_lanes() {
    crate::metrics::init();
    let server_dead = ok_server_for("gone").await;
    let server_soon = ok_server_for("soon").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gone",
                crate::proto::Protocol::anthropic(),
                &server_dead.base_url(),
            )
            .provider("p")
            .dead("administratively down"),
        )
        .lane(
            LaneSpec::new(
                "soon",
                crate::proto::Protocol::anthropic(),
                &server_soon.base_url(),
            )
            .provider("p"),
        )
        .pool("pl", &[(0, 1), (1, 1)])
        .pool_runtime("pl", pool_runtime_with_exclusions(None))
        .on_exhausted("pl", crate::config::OnExhausted::LeastBad)
        .build();

    app.store.force_open_in("pl", 1, now() + 5);

    let resp = forward_with_pool(
        app.clone(),
        vec![lane(0), lane(1)],
        chat_body("pl").into(),
        None,
        "pl",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "the recovering lane must serve"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        0,
        "the dead lane must not be ranked, let alone dispatched to"
    );
    server_dead.shutdown().await;
    server_soon.shutdown().await;
}

/// Regression fence for the naive fix. Filtering `least_bad` on `request_ctx.excluded` looks
/// equivalent but is not: that set also accumulates every lane the request already TRIED, so in the
/// dominant exhaustion case it holds every member and `least_bad` silently degenerates to `reject`.
#[tokio::test]
async fn least_bad_still_serves_the_only_member_after_it_was_tried() {
    crate::metrics::init();
    let server = ok_server_for("solo").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "solo",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("p"),
        )
        .pool("ps", &[(0, 1)])
        .pool_runtime("ps", pool_runtime_with_exclusions(None))
        .on_exhausted("ps", crate::config::OnExhausted::LeastBad)
        .build();

    app.store.force_open_in("ps", 0, now() + 30);

    let resp = forward_with_pool(
        app.clone(),
        vec![lane(0)],
        chat_body("ps").into(),
        None,
        "ps",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "least_bad must still override the Open breaker for a non-excluded member"
    );
    server.shutdown().await;
}

/// `failover.exclusions` is a PER-POOL member blocklist, and a fallback pool is an independent
/// membership. Its own blocklist was never consulted, so a member the operator blocklisted there
/// could still be reached by spilling into the pool — the one path exclusions exist to prevent.
#[tokio::test]
async fn a_fallback_pool_applies_its_own_exclusions() {
    crate::metrics::init();
    let server_primary = ok_server_for("primary").await;
    let server_ok = ok_server_for("spare").await;
    let server_blocked = ok_server_for("blocked").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                &server_primary.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "spare",
                crate::proto::Protocol::anthropic(),
                &server_ok.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "blocked",
                crate::proto::Protocol::anthropic(),
                &server_blocked.base_url(),
            )
            .provider("p"),
        )
        .pool("pf", &[(0, 1)])
        .pool_runtime("pf", pool_runtime_with_exclusions(None))
        .on_exhausted(
            "pf",
            crate::config::OnExhausted::FallbackPool("spill".into()),
        )
        .fallback_pool("spill", &[(1, 1), (2, 1)])
        .pool_runtime(
            "spill",
            pool_runtime_with_exclusions(Some(vec!["blocked".into()])),
        )
        .build();

    // Exhaust the primary so the request spills.
    app.store.force_open_in("pf", 0, now() + 300);

    for _ in 0..4 {
        let resp = forward_with_pool(
            app.clone(),
            vec![lane(0)],
            chat_body("pf").into(),
            None,
            "pf",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    assert_eq!(
        app.store.snapshot(2, now()).ok,
        0,
        "a member blocklisted by the FALLBACK pool must never serve a spilled request"
    );
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        4,
        "the eligible fallback member serves every spilled request"
    );
    server_primary.shutdown().await;
    server_ok.shutdown().await;
    server_blocked.shutdown().await;
}

// ── AT-CAPACITY exhaustion (Bug 1) ─────────────────────────────────────────────────────────────
//
// The documented contract: "When all candidates are unavailable, tripped, excluded, or at-capacity,
// the pool is exhausted." Before the fix, a member at its `max_concurrent` limit was NOT treated as
// an exhaustion condition — `pick_among` PARKED on the lane semaphore until the failover deadline
// instead of returning `None`, so `on_exhausted` never fired: `fallback_pool` never spilled and
// `reject` never shed. Requests serialized behind the saturated lane, latency grew with burst depth.
//
// TEST DESIGN (deterministic; no real-clock race). A lane is saturated by handing it a shared
// 1-permit semaphore whose ONE permit the test already holds ([`saturated`]) — so the lane's
// `try_acquire` fails for the whole test with no in-flight upstream request to time. Each request is
// then wrapped in a SHORT test-side `timeout` ([`SHED_BUDGET`]) while the pool's failover deadline is
// set LONG ([`long_failover`], 300s). On the UNFIXED code the request parks ~300s on the saturated
// semaphore, so the 4s wrapper fires and the `.expect` panics — this is the RED signal, and it is
// exactly what makes every at-capacity test below fail if the one-line `select.rs` fix is reverted
// (the tautology-check the task requires). On the FIXED code the request sheds/spills immediately,
// completing far inside the wrapper, and the assertion on the OBSERVABLE outcome (503 + Retry-After,
// or which member served) holds.

use std::time::Duration;

/// A failover budget long enough that, on the unfixed code, an at-capacity park cannot masquerade as
/// a fast shed: the buggy park runs to this deadline (300s), well past [`SHED_BUDGET`].
fn long_failover() -> crate::config::FailoverCfg {
    crate::config::FailoverCfg {
        timeout_secs: 300,
        exclusions: None,
        max_hops: 3,
    }
}

/// The test-side "shed, do not queue" budget. The fix completes in microseconds; the bug parks to the
/// 300s failover deadline. 4s is comfortably between the two, so this is not a flaky timing race — it
/// is a binary "did the request queue to the deadline or not".
const SHED_BUDGET: Duration = Duration::from_secs(4);

/// A shared 1-permit semaphore whose single permit is ALREADY HELD by the returned guard. A lane
/// built with this semaphore (`.max(1).sem(sem)`) is at-capacity for as long as the guard is alive:
/// its `try_acquire` always fails. Deterministic saturation with no slow upstream to time.
fn saturated() -> (
    std::sync::Arc<tokio::sync::Semaphore>,
    tokio::sync::OwnedSemaphorePermit,
) {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let held = sem
        .clone()
        .try_acquire_owned()
        .expect("fresh 1-permit semaphore has its permit available");
    (sem, held)
}

/// A saturated-lane `LaneSpec`: bounded (`max_concurrent: 1`) and wired to the shared, already-held
/// semaphore, so the lane is permanently at-capacity. The `base_url` is never dialed (no request is
/// ever dispatched to a saturated lane), so a dead address is fine.
fn saturated_lane(model: &str, sem: &std::sync::Arc<tokio::sync::Semaphore>) -> LaneSpec {
    LaneSpec::new(
        model,
        crate::proto::Protocol::anthropic(),
        "http://127.0.0.1:1",
    )
    .provider("p")
    .max(1)
    .sem(sem.clone())
}

/// Read the `Retry-After` header (whole seconds) off a response, if present.
fn retry_after(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Drive one request through `forward_with_pool` under the shed budget. On the fixed code this
/// returns immediately; on the unfixed code the inner future parks to the failover deadline and this
/// `.expect` panics (RED) — the shed-not-queued assertion.
async fn drive_shed(
    app: std::sync::Arc<crate::state::App>,
    cands: Vec<WeightedLane>,
    pool: &str,
) -> axum::response::Response {
    tokio::time::timeout(
        SHED_BUDGET,
        forward_with_pool(
            app,
            cands,
            chat_body(pool).into(),
            None,
            pool,
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        ),
    )
    .await
    .expect(
        "at-capacity request must shed/spill immediately — it queued to the failover deadline \
         instead (Bug 1: the select.rs at-capacity park). This fails if the one-line fix is reverted.",
    )
}

/// D — `on_exhausted: reject` (Status503) on a saturated pool must SHED with 503 + `Retry-After`,
/// not queue behind the busy member to the deadline. RED before the fix (parks to 300s).
#[tokio::test]
async fn at_capacity_reject_sheds_503_not_queued() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Status503)
        .build();

    let resp = drive_shed(app, vec![lane(0)], "p").await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "a saturated `reject` pool must shed with 503"
    );
    assert!(
        retry_after(&resp).is_some(),
        "the shed 503 must carry a Retry-After header for rate-aware clients"
    );
}

/// D/default — a pool with NO `on_exhausted` config defaults to reject semantics (Status503): a
/// saturated pool sheds 503 + Retry-After, not queue. RED before the fix.
#[tokio::test]
async fn at_capacity_default_no_on_exhausted_sheds_503() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        // No `.on_exhausted(...)` → default OnExhausted::Status503.
        .build();

    let resp = drive_shed(app, vec![lane(0)], "p").await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "default exhaustion is reject/503"
    );
    assert!(
        retry_after(&resp).is_some(),
        "default 503 carries Retry-After"
    );
}

/// A — saturation with `fallback_pool` must SPILL to the fallback pool's fast member, NOT serialize
/// on the saturated primary. The primary member must serve ZERO requests (it never dispatches while
/// at-capacity). RED before the fix (the request parks on the primary and never reaches the spill).
#[tokio::test]
async fn at_capacity_fallback_spills_to_fast_member() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("slow", &sem)) // idx 0 — saturated primary
        .lane(
            LaneSpec::new(
                "fast",
                crate::proto::Protocol::anthropic(),
                &fast.base_url(),
            )
            .provider("p"),
        ) // idx 1 — fast overflow
        .pool("primary", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("overflow".into()),
        )
        .fallback_pool("overflow", &[(1, 1)])
        .build();

    let resp = drive_shed(app.clone(), vec![lane(0)], "primary").await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "a saturated primary must spill to the fast overflow pool and be served"
    );
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        1,
        "the fast overflow member serves the spilled request"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        0,
        "the saturated primary must NOT serialize the request (it was never dispatched)"
    );
    fast.shutdown().await;
}

/// The `least_bad` last-resort path, when the ONLY member is at-capacity (breaker-healthy but its
/// permit is held), must SHED with 503 rather than queue: `least_bad` overrides the breaker, not a
/// concurrency limit. RED before the fix (parks in `pick_among` before ever reaching `least_bad`).
#[tokio::test]
async fn at_capacity_least_bad_sheds_when_saturated() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::LeastBad)
        .build();

    let resp = drive_shed(app, vec![lane(0)], "p").await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "least_bad cannot dispatch onto an at-capacity member (no permit) → it must shed 503"
    );
    assert!(retry_after(&resp).is_some());
}

/// E / F — a bounded pool under a concurrent BURST must not serialize: with the single primary member
/// at capacity, N concurrent requests all SPILL to the fast overflow pool in parallel (the fast pool
/// serves all N; the saturated primary serves none). This is the "queue appears unbounded" report
/// scenario turned into a permanent guard. RED before the fix (all N park behind the one busy slot).
#[tokio::test]
async fn at_capacity_bounded_burst_all_spill_not_serialized() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await; // pushes 4 canned OKs
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("slow", &sem)) // idx 0 — one bounded, saturated slot
        .lane(
            LaneSpec::new(
                "fast",
                crate::proto::Protocol::anthropic(),
                &fast.base_url(),
            )
            .provider("p")
            .max(20),
        ) // idx 1 — roomy overflow
        .pool("primary", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("overflow".into()),
        )
        .fallback_pool("overflow", &[(1, 1)])
        .build();

    let n = 4usize;
    let futs = (0..n).map(|_| drive_shed(app.clone(), vec![lane(0)], "primary"));
    let results = futures::future::join_all(futs).await;

    for resp in &results {
        assert_eq!(
            resp.status().as_u16(),
            200,
            "every request in the burst must be served by the overflow pool, not queued"
        );
    }
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        n as u64,
        "all {n} burst requests spilled to the fast overflow member in parallel"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        0,
        "the single saturated slot served none of them (no serialization)"
    );
    fast.shutdown().await;
}

/// F (localization) — a pool with TWO members BOTH at `max_concurrent: 1` and BOTH busy: the request
/// that arrives when EVERY member is at capacity must exhaust → spill, not queue. This pins the
/// defect to the pool-exhaustion check (not per-member capacity accounting). RED before the fix.
#[tokio::test]
async fn at_capacity_all_members_busy_two_member_pool_spills() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let (sem_a, _held_a) = saturated();
    let (sem_b, _held_b) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("slowA", &sem_a)) // idx 0
        .lane(saturated_lane("slowB", &sem_b)) // idx 1
        .lane(
            LaneSpec::new(
                "fast",
                crate::proto::Protocol::anthropic(),
                &fast.base_url(),
            )
            .provider("p"),
        ) // idx 2
        .pool("primary", &[(0, 1), (1, 1)])
        .failover(long_failover())
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("overflow".into()),
        )
        .fallback_pool("overflow", &[(2, 1)])
        .build();

    let resp = drive_shed(app.clone(), vec![lane(0), lane(1)], "primary").await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "with every member at capacity the pool is exhausted and must spill"
    );
    assert_eq!(app.store.snapshot(2, now()).ok, 1, "overflow served it");
    assert_eq!(app.store.snapshot(0, now()).ok, 0);
    assert_eq!(app.store.snapshot(1, now()).ok, 0);
    fast.shutdown().await;
}

/// Combination — one member at-capacity + one member breaker-Open (tripped). Every candidate is
/// unavailable, so the pool is exhausted → reject/503. RED before the fix (parks on the at-capacity
/// member). Also proves the fix composes with the existing breaker-Open exclusion path.
#[tokio::test]
async fn at_capacity_plus_tripped_member_rejects_503() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem)) // idx 0 — at capacity
        .lane(
            LaneSpec::new(
                "tripped",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("p"),
        ) // idx 1 — will be forced Open
        .pool("p", &[(0, 1), (1, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Status503)
        .build();

    // Trip member 1's breaker (Open, not yet expired) so it is never admissible.
    app.store.force_open_in("p", 1, now() + 300);

    let resp = drive_shed(app, vec![lane(0), lane(1)], "p").await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "at-capacity + tripped = fully exhausted → shed 503"
    );
    assert!(retry_after(&resp).is_some());
}

/// A fallback CHAIN A→B→C: primary A at-capacity spills to B, B at-capacity spills to C, C (fast)
/// serves. Proves the at-capacity exhaustion signal propagates through multi-level chains. RED
/// before the fix (parks on A).
#[tokio::test]
async fn at_capacity_fallback_chain_spills_through_to_third_pool() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let (sem_a, _held_a) = saturated();
    let (sem_b, _held_b) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("a", &sem_a)) // idx 0 — pool A
        .lane(saturated_lane("b", &sem_b)) // idx 1 — pool B
        .lane(
            LaneSpec::new("c", crate::proto::Protocol::anthropic(), &fast.base_url()).provider("p"),
        ) // idx 2 — pool C (fast)
        .pool("pa", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("pa", crate::config::OnExhausted::FallbackPool("pb".into()))
        .fallback_pool("pb", &[(1, 1)])
        .on_exhausted("pb", crate::config::OnExhausted::FallbackPool("pc".into()))
        .fallback_pool("pc", &[(2, 1)])
        .build();

    let resp = drive_shed(app.clone(), vec![lane(0)], "pa").await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "A→B→C: the at-capacity signal must cascade through the whole chain to the fast pool"
    );
    assert_eq!(app.store.snapshot(2, now()).ok, 1, "pool C served it");
    assert_eq!(app.store.snapshot(0, now()).ok, 0);
    assert_eq!(app.store.snapshot(1, now()).ok, 0);
    fast.shutdown().await;
}

/// A self-referential fallback (a pool whose `on_exhausted` names itself) on an at-capacity pool must
/// terminate at the visited-pool loop guard with 503 — never recurse or park. RED before the fix.
#[tokio::test]
async fn at_capacity_self_referential_fallback_stays_503() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem))
        .pool("loop", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted(
            "loop",
            crate::config::OnExhausted::FallbackPool("loop".into()),
        )
        .fallback_pool("loop", &[(0, 1)])
        .build();

    let resp = drive_shed(app, vec![lane(0)], "loop").await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "a self-referential fallback must stop at the loop guard with 503, not recurse/park"
    );
}

/// A fallback pool that is ITSELF at-capacity (no further `on_exhausted`) cascades to 503 — the spill
/// target being exhausted too must still terminate in a shed, not a queue. RED before the fix.
#[tokio::test]
async fn at_capacity_fallback_to_also_exhausted_pool_cascades_to_503() {
    crate::metrics::init();
    let (sem_a, _held_a) = saturated();
    let (sem_b, _held_b) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("primary", &sem_a)) // idx 0
        .lane(saturated_lane("overflow", &sem_b)) // idx 1 — also saturated
        .pool("primary", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("overflow".into()),
        )
        .fallback_pool("overflow", &[(1, 1)])
        // No on_exhausted for "overflow" → default Status503 when it too is exhausted.
        .build();

    let resp = drive_shed(app, vec![lane(0)], "primary").await;

    assert_eq!(
        resp.status().as_u16(),
        503,
        "spilling into an also-at-capacity pool must cascade to a 503 shed"
    );
    assert!(retry_after(&resp).is_some());
}

// ── Green regression guards (pass BOTH before and after the fix) ────────────────────────────────

/// C-analogue regression guard: a NON-at-capacity exhaustion (a member with its breaker forced Open)
/// still falls back correctly. This is the control the bug report used to isolate the defect to the
/// at-capacity condition; it must stay green across the fix, proving the fix did not disturb the
/// already-working tripped/unreachable exhaustion → fallback path. (Passes on unfixed code too.)
#[tokio::test]
async fn tripped_member_still_falls_back_to_overflow() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("p"),
        ) // idx 0
        .lane(
            LaneSpec::new(
                "fast",
                crate::proto::Protocol::anthropic(),
                &fast.base_url(),
            )
            .provider("p"),
        ) // idx 1
        .pool("primary", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted(
            "primary",
            crate::config::OnExhausted::FallbackPool("overflow".into()),
        )
        .fallback_pool("overflow", &[(1, 1)])
        .build();

    // Primary member is tripped (Open) — the already-working exhaustion condition.
    app.store.force_open_in("primary", 0, now() + 300);

    let resp = drive_shed(app.clone(), vec![lane(0)], "primary").await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "a tripped primary must fall back to the overflow pool (unchanged by the fix)"
    );
    assert_eq!(app.store.snapshot(1, now()).ok, 1, "overflow served it");
    fast.shutdown().await;
}

// ── least_bad must skip a SATURATED soonest member (Finding 2) ──────────────────────────────────

/// `least_bad` ranks Open members by soonest cooldown and dispatches to the "least bad" one. If that
/// soonest member is AT-CAPACITY (no free permit) but a slightly-worse sibling has a free permit,
/// `least_bad` must degrade onto the SIBLING — not return a hard 503. It exists to provide a degraded
/// response when everything is tripped; refusing because the single best member happens to be busy
/// defeats its purpose. Before the Finding-2 fix, `handle_least_bad` did one `try_acquire` on the
/// soonest member and 503'd on failure, so this returned 503; after, it falls to the free sibling.
#[tokio::test]
async fn least_bad_skips_saturated_soonest_and_serves_free_sibling() {
    crate::metrics::init();
    let sibling = ok_server_for("sibling").await;
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("soonest", &sem)) // idx 0 — soonest cooldown, but saturated
        .lane(
            LaneSpec::new(
                "sibling",
                crate::proto::Protocol::anthropic(),
                &sibling.base_url(),
            )
            .provider("p"),
        ) // idx 1 — worse cooldown, but a free permit
        .pool("p", &[(0, 1), (1, 1)])
        .pool_runtime("p", pool_runtime_with_exclusions(None))
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::LeastBad)
        .build();

    // Both Open → pool exhausted → least_bad. idx 0 has the SOONER cooldown (it would be picked
    // first) but is saturated; idx 1 cools down later but has a free permit.
    app.store.force_open_in("p", 0, now() + 5);
    app.store.force_open_in("p", 1, now() + 20);

    let resp = drive_shed(app.clone(), vec![lane(0), lane(1)], "p").await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "least_bad must fall past the saturated soonest member to a free sibling, not 503"
    );
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        1,
        "the free sibling served the degraded dispatch"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        0,
        "the saturated soonest member could not be dispatched to"
    );
    sibling.shutdown().await;
}

// ── Retry-After reflects the real backpressure axis (Finding 3) ─────────────────────────────────

/// Parse the numeric `Retry-After` seconds off a response.
fn retry_after_secs(resp: &axum::response::Response) -> u64 {
    retry_after(resp)
        .expect("a shed 503 must carry Retry-After")
        .parse()
        .expect("Retry-After is whole seconds")
}

/// When exhaustion is a genuine breaker COOLDOWN, Retry-After reflects the soonest cooldown — even
/// when an at-capacity-but-Closed sibling (whose cooldown reads 0) is also in the candidate set. The
/// old `find_soonest_cooldown` took the MIN including that 0 and collapsed Retry-After to 1, badly
/// under-serving backoff; the fix ignores at-capacity-Closed members' 0 when a real cooldown exists.
#[tokio::test]
async fn retry_after_reflects_cooldown_when_a_member_is_tripped() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem)) // idx 0 — at capacity, Closed (cooldown reads 0)
        .lane(
            LaneSpec::new(
                "tripped",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("p"),
        ) // idx 1 — tripped
        .pool("p", &[(0, 1), (1, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Status503)
        .build();

    app.store.force_open_in("p", 1, now() + 40);

    let resp = drive_shed(app, vec![lane(0), lane(1)], "p").await;

    assert_eq!(resp.status().as_u16(), 503);
    let ra = retry_after_secs(&resp);
    assert!(
        ra > 2 && ra <= 40,
        "Retry-After must track the genuine ~40s cooldown, not collapse to 1 because a saturated \
         sibling reports cooldown 0; got {ra}"
    );
}

/// When exhaustion is PURE saturation (every member at-capacity, breakers Closed → cooldown 0),
/// Retry-After must still be a sensible floor (> 1), signaling "a permit will free shortly", rather
/// than the misleading `Retry-After: 1` the old code always produced under load.
#[tokio::test]
async fn retry_after_has_saturation_floor_when_purely_at_capacity() {
    crate::metrics::init();
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Status503)
        .build();

    let resp = drive_shed(app, vec![lane(0)], "p").await;

    assert_eq!(resp.status().as_u16(), 503);
    assert!(
        retry_after_secs(&resp) > 1,
        "a purely at-capacity shed must not always advertise Retry-After: 1"
    );
}
