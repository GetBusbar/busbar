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
fn test_config_parsing_queue() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("{ queue: { max_ms: 250 } }").unwrap();
    assert!(matches!(
        cfg.to_runtime(),
        config::OnExhausted::Queue { max_ms: 250 }
    ));
}

#[test]
fn test_config_parsing_both_fallback_and_queue_conflicts() {
    // A mapping carrying BOTH keys is an explicit "exactly one of" error, never a force-fit.
    let result: Result<config::OnExhaustedCfg, _> =
        serde_yaml::from_str("{ fallback_pool: cold, queue: { max_ms: 250 } }");
    let err = format!(
        "{}",
        result.expect_err("both keys present must be an error")
    );
    assert!(
        err.contains("exactly one of"),
        "must reject both fallback_pool and queue; got: {err}"
    );
}

#[test]
fn test_config_parsing_queue_unknown_inner_key_fails() {
    // `deny_unknown_fields` on the inner body: a typo'd `max_millis` must fail, not be ignored.
    let result: Result<config::OnExhaustedCfg, _> =
        serde_yaml::from_str("{ queue: { max_millis: 250 } }");
    assert!(
        result.is_err(),
        "an unknown queue inner key must fail parsing"
    );
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
use crate::store::BreakerState;
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
        upstream_credentials: None,
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
            LaneSpec::new("alpha", crate::proto::PROTO_ANTHROPIC, &server_a.base_url())
                .provider("p"),
        )
        .lane(
            LaneSpec::new("beta", crate::proto::PROTO_ANTHROPIC, &server_b.base_url())
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
        &app,
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
                crate::proto::PROTO_ANTHROPIC,
                &server_dead.base_url(),
            )
            .provider("p")
            .dead("administratively down"),
        )
        .lane(
            LaneSpec::new(
                "soon",
                crate::proto::PROTO_ANTHROPIC,
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
        &app,
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

/// Regression fence for a tempting wrong fix. Filtering `least_bad` on `request_ctx.excluded` looks
/// equivalent but is not: that set also accumulates every lane the request already TRIED, so in the
/// dominant exhaustion case it holds every member and `least_bad` silently degenerates to `reject`.
#[tokio::test]
async fn least_bad_still_serves_the_only_member_after_it_was_tried() {
    crate::metrics::init();
    let server = ok_server_for("solo").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new("solo", crate::proto::PROTO_ANTHROPIC, &server.base_url()).provider("p"),
        )
        .pool("ps", &[(0, 1)])
        .pool_runtime("ps", pool_runtime_with_exclusions(None))
        .on_exhausted("ps", crate::config::OnExhausted::LeastBad)
        .build();

    app.store.force_open_in("ps", 0, now() + 30);

    let resp = forward_with_pool(
        &app,
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
                crate::proto::PROTO_ANTHROPIC,
                &server_primary.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "spare",
                crate::proto::PROTO_ANTHROPIC,
                &server_ok.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "blocked",
                crate::proto::PROTO_ANTHROPIC,
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
            &app,
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

// ── AT-CAPACITY exhaustion ─────────────────────────────────────────────────────────────────────
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
// set LONG ([`long_failover`], 300s). A regression that parks runs ~300s on the saturated
// semaphore, so the 4s wrapper fires and the `.expect` panics — that panic is the failure signal,
// and it is what makes every at-capacity test below fail if the `select.rs` guard regresses.
// Correct behaviour sheds/spills immediately, completing far inside the wrapper, and the assertion
// on the OBSERVABLE outcome (503 + Retry-After, or which member served) holds.

use std::time::Duration;

/// A failover budget long enough that an at-capacity park cannot masquerade as a fast shed: a park
/// runs to this deadline (300s), well past [`SHED_BUDGET`].
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
    LaneSpec::new(model, crate::proto::PROTO_ANTHROPIC, "http://127.0.0.1:1")
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

/// Drive one request through `forward_with_pool` under the shed budget. A correct shed returns
/// immediately; a queue-instead-of-shed regression parks the inner future to the failover deadline
/// and this `.expect` panics — the shed-not-queued assertion.
async fn drive_shed(
    app: std::sync::Arc<crate::state::App>,
    cands: Vec<WeightedLane>,
    pool: &str,
) -> axum::response::Response {
    tokio::time::timeout(
        SHED_BUDGET,
        forward_with_pool(
            &app,
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
         instead (the select.rs at-capacity park).",
    )
}

/// `on_exhausted: reject` (Status503) on a saturated pool must SHED with 503 + `Retry-After`,
/// not queue behind the busy member to the deadline (which would park to 300s).
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

/// A pool with NO `on_exhausted` config defaults to reject semantics (Status503): a
/// saturated pool sheds 503 + Retry-After, not queue.
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

/// Saturation with `fallback_pool` must SPILL to the fallback pool's fast member, NOT serialize
/// on the saturated primary. The primary member must serve ZERO requests (it never dispatches while
/// at-capacity); parking on the primary would never reach the spill.
#[tokio::test]
async fn at_capacity_fallback_spills_to_fast_member() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("slow", &sem)) // idx 0 — saturated primary
        .lane(LaneSpec::new("fast", crate::proto::PROTO_ANTHROPIC, &fast.base_url()).provider("p")) // idx 1 — fast overflow
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
/// concurrency limit; parking in `pick_among` would never reach `least_bad`.
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

/// A bounded pool under a concurrent BURST must not serialize: with the single primary member
/// at capacity, N concurrent requests all SPILL to the fast overflow pool in parallel (the fast pool
/// serves all N; the saturated primary serves none). This is the "queue appears unbounded" report
/// scenario turned into a permanent guard; otherwise all N park behind the one busy slot.
#[tokio::test]
async fn at_capacity_bounded_burst_all_spill_not_serialized() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await; // pushes 4 canned OKs
    let (sem, _held) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("slow", &sem)) // idx 0 — one bounded, saturated slot
        .lane(
            LaneSpec::new("fast", crate::proto::PROTO_ANTHROPIC, &fast.base_url())
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

/// A pool with TWO members BOTH at `max_concurrent: 1` and BOTH busy: the request
/// that arrives when EVERY member is at capacity must exhaust → spill, not queue. This pins the
/// defect to the pool-exhaustion check, not per-member capacity accounting.
#[tokio::test]
async fn at_capacity_all_members_busy_two_member_pool_spills() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let (sem_a, _held_a) = saturated();
    let (sem_b, _held_b) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("slowA", &sem_a)) // idx 0
        .lane(saturated_lane("slowB", &sem_b)) // idx 1
        .lane(LaneSpec::new("fast", crate::proto::PROTO_ANTHROPIC, &fast.base_url()).provider("p")) // idx 2
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
/// unavailable, so the pool is exhausted → reject/503 (parking on the at-capacity
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
                crate::proto::PROTO_ANTHROPIC,
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
/// serves. Proves the at-capacity exhaustion signal propagates through multi-level chains rather
/// than parking on A.
#[tokio::test]
async fn at_capacity_fallback_chain_spills_through_to_third_pool() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let (sem_a, _held_a) = saturated();
    let (sem_b, _held_b) = saturated();
    let app = TestApp::new()
        .lane(saturated_lane("a", &sem_a)) // idx 0 — pool A
        .lane(saturated_lane("b", &sem_b)) // idx 1 — pool B
        .lane(LaneSpec::new("c", crate::proto::PROTO_ANTHROPIC, &fast.base_url()).provider("p")) // idx 2 — pool C (fast)
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
/// terminate at the visited-pool loop guard with 503 — never recurse or park.
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
/// target being exhausted too must still terminate in a shed, not a queue.
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

// ── Regression guards that hold in every configuration ──────────────────────────────────────────

/// Regression guard: a NON-at-capacity exhaustion (a member with its breaker forced Open)
/// still falls back correctly. This is the control that isolates the defect to the at-capacity
/// condition: it must stay green either way, proving the at-capacity guard did not disturb the
/// already-working tripped/unreachable exhaustion → fallback path.
#[tokio::test]
async fn tripped_member_still_falls_back_to_overflow() {
    crate::metrics::init();
    let fast = ok_server_for("fast").await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::PROTO_ANTHROPIC,
                "http://127.0.0.1:1",
            )
            .provider("p"),
        ) // idx 0
        .lane(LaneSpec::new("fast", crate::proto::PROTO_ANTHROPIC, &fast.base_url()).provider("p")) // idx 1
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

// ── least_bad must skip a SATURATED soonest member ──────────────────────────────────────────────

/// `least_bad` ranks Open members by soonest cooldown and dispatches to the "least bad" one. If that
/// soonest member is AT-CAPACITY (no free permit) but a slightly-worse sibling has a free permit,
/// `least_bad` must degrade onto the SIBLING — not return a hard 503. It exists to provide a degraded
/// response when everything is tripped; refusing because the single best member happens to be busy
/// defeats its purpose. A `handle_least_bad` that does one `try_acquire` on the
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
                crate::proto::PROTO_ANTHROPIC,
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

// ── Retry-After reflects the real backpressure axis ─────────────────────────────────────────────

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
                crate::proto::PROTO_ANTHROPIC,
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

/// An EMPTY/unknown candidate set — reachable via a fallback loop A→B→A or an
/// unconfigured `fallback_pool` target, both of which call `handle_status_503` with `&[]` — must
/// advertise the honest ≥2s floor (`AT_CAPACITY_RETRY_AFTER_SECS`), never the deceptive bare `1`
/// ("retry immediately, just re-collide"), which is why the `None` arm floors instead of returning 1.
#[test]
fn retry_after_empty_candidate_set_uses_floor_not_one() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, "http://127.0.0.1:1").provider("p"))
        .pool("p", &[(0, 1)])
        .build();
    // Directly exercise the shed with an EMPTY candidate slice (the fallback-loop / unconfigured-target
    // shape) — no genuine cooldown, nothing at-capacity in `&[]`.
    let resp = crate::proxy::engine::handle_status_503(&app, &[], now(), "p", "anthropic");
    assert_eq!(resp.status().as_u16(), 503);
    let ra = retry_after_secs(&resp);
    assert!(
        ra >= 2,
        "an empty candidate set must get the >=2s honest floor, never the deceptive 1; got {ra}"
    );
}

// ── on_exhausted: queue{max_ms} ─────────────────────────────────────────────────────────────────
// The queue waits BOUNDED on the AtCapacity candidates' OWN FIFO semaphores — a permit freed on
// a busy lane wakes exactly one waiter with the stored permit (no lost wakeup, no thundering herd) —
// then re-checks the breaker on the won lane before dispatch. Every test saturates a REAL semaphore.

/// A lane wired to a REAL mock server AND a shared 1-permit semaphore: at-capacity while the test
/// holds the permit, dispatchable once the test frees it (so the queue can actually serve on it).
fn busy_real_lane(model: &str, base_url: &str, sem: &Arc<tokio::sync::Semaphore>) -> LaneSpec {
    LaneSpec::new(model, crate::proto::PROTO_ANTHROPIC, base_url)
        .provider("p")
        .max(1)
        .sem(sem.clone())
}

/// Spawn one request through the real dispatch path with `'static` literals so it can run detached
/// while the test frees a permit / trips a breaker underneath it.
fn spawn_request(
    app: std::sync::Arc<crate::state::App>,
) -> tokio::task::JoinHandle<axum::response::Response> {
    tokio::spawn(async move {
        forward_with_pool(
            &app,
            vec![lane(0)],
            chat_body("p").into(),
            None,
            "p",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        )
        .await
    })
}

/// Poll-until-parked: wait (bounded) for the pool's queue depth to reach `min_depth`, re-asserting on
/// a tight interval rather than sleeping a fixed wall-clock time. Replaces flaky fixed-sleep syncs
/// under CI scheduler pressure — it only proceeds once the spawned request(s) have actually reached
/// the queue park point. Panics if the depth is not reached within the bound.
async fn wait_until_queued(app: &std::sync::Arc<crate::state::App>, pool: &str, min_depth: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while app.queued_depth.depth(pool) < min_depth {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for queue depth >= {min_depth} on pool {pool} (got {})",
            app.queued_depth.depth(pool)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// queue DISPATCHES when a permit frees before the deadline: the request parks on the saturated
/// lane's semaphore, and once the held permit is released the queued waiter acquires it, passes the
/// (Closed) breaker, and is served by THAT freed lane (200). Without the queue arm this would be an
/// immediate 503.
#[tokio::test]
async fn queue_dispatches_when_permit_frees_before_deadline() {
    crate::metrics::init();
    let svc = ok_server_for("svc").await;
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let held = sem.clone().try_acquire_owned().unwrap();
    let app = TestApp::new()
        .lane(busy_real_lane("svc", &svc.base_url(), &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 5000 })
        .build();

    let req = spawn_request(app.clone());
    // Poll until the request has actually PARKED in the queue (not a fixed sleep — flaky under CI load).
    wait_until_queued(&app, "p", 1).await;
    assert!(
        app.queued_depth.depth("p") >= 1,
        "the request must be parked in the queue (busbar_pool_queued source > 0 during the wait)"
    );
    // Free the permit — the queued waiter acquires it and dispatches on the freed lane.
    drop(held);

    let resp = tokio::time::timeout(Duration::from_secs(5), req)
        .await
        .expect("queue must dispatch within the wait window, never hang")
        .expect("request task panicked");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a permit freed before the deadline must let the queued request dispatch"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        1,
        "the freed lane served the queued request"
    );
    assert_eq!(
        app.queued_depth.depth("p"),
        0,
        "the park depth returns to 0 after dispatch (RAII guard dropped)"
    );
    svc.shutdown().await;
}

/// A queued dispatch that WON a single-flight recovery probe, then has its
/// future DROPPED mid-upstream-await (client disconnect), must RELEASE the probe via the RAII
/// `ProbeGuard` — the cell must not be left wedged HalfOpen (which would bench the lane until the
/// out-of-band prober rescues it). Deterministic via `MockResponse::Gated` (a `Notify`, not a sleep).
/// Without the forward_once ProbeGuard: the explicit `release_probe_in` sites are code AFTER the
/// dropped await, so none run on drop and the cell stays HalfOpen.
#[tokio::test]
async fn queue_dropped_dispatch_future_releases_probe() {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    // A non-2xx gated body: forward_once reads it via `read_capped_body(...).await` (parking WITH the
    // permit AND the won probe held) before recording any outcome — the exact mid-dispatch await the
    // dropped-future guard must cover.
    state.push(MockResponse::Gated {
        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        body: json!({"error": {"message": "boom"}}),
        started: started.clone(),
        release: release.clone(),
    });
    let server = MockServer::new(state.clone()).await;

    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let held = sem.clone().try_acquire_owned().unwrap();
    let app = TestApp::new()
        .lane(busy_real_lane("svc", &server.base_url(), &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 30_000 })
        .build();
    // Make the member EXPIRED-OPEN so that when the freed permit is won the queue's `try_admit_breaker`
    // WINS a single-flight recovery probe (cell → HalfOpen) — the state that wedges without a guard.
    app.store.force_open_in("p", 0, 0);

    let req = spawn_request(app.clone());
    wait_until_queued(&app, "p", 1).await;

    // Free the permit → the queued waiter wins the probe (HalfOpen) and dispatches; it parks in the
    // gated upstream body read.
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .expect("the queued dispatch must reach the upstream body read");
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::HalfOpen),
        "precondition: the queued dispatch won the recovery probe (cell HalfOpen)"
    );

    // DROP the dispatch future mid-await (client disconnect): abort the task and observe cancellation.
    req.abort();
    let _ = req.await;

    // The ProbeGuard's Drop must have released the probe (owner-checked HalfOpen→Open) — the cell must
    // NOT be stuck HalfOpen. Poll briefly for the drop to take effect.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while matches!(app.store.breaker_state_in("p", 0), BreakerState::HalfOpen) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dropped forward_once future left the cell stuck HalfOpen — the probe leaked"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        matches!(
            app.store.breaker_state_in("p", 0),
            BreakerState::Open { .. }
        ),
        "a dropped forward_once future must release the probe (HalfOpen→Open), not bench the lane"
    );

    release.notify_waiters();
    server.shutdown().await;
}

/// Peer-probe revert: `handle_least_bad` OWNS NO PROBE — it dispatches via
/// `try_acquire` and wins nothing. So if a least_bad dispatch's `forward_once` future is DROPPED
/// mid-upstream-await (client disconnect), it must NEVER revert a single-flight probe a CONCURRENT PEER
/// legitimately won on the SAME cell. Passing the cell's CURRENT epoch to an ARMED `ProbeGuard`
/// on this path; because `release_probe_owned_in` matches by epoch EQUALITY (not "did THIS dispatch win
/// it"), a HalfOpen cell whose live probe belongs to peer A would be REVERTED (HalfOpen→Open, probe
/// cleared) on B's drop — letting a THIRD request win a SECOND concurrent probe, breaking single-flight.
/// The fix makes `forward_once`'s `probe_epoch` an `Option<u64>` and has least_bad pass `None`, so NO
/// guard is built on this path and a dropped least_bad future can revert nothing.
///
/// The least_bad `forward_once` arg must stay `None`: `Some(app.store.probe_epoch_in(pool,
/// soonest_idx))` would arm a guard capturing peer A's live epoch, so B's drop reverts A's probe —
/// the cell goes Open and a fresh `try_admit` wins a NEW probe. With `None` the cell is untouched.
#[tokio::test]
async fn least_bad_dropped_dispatch_never_reverts_a_peers_probe() {
    crate::metrics::init();
    // A gated non-2xx body: least_bad's `forward_once` parks reading it (BEFORE recording any breaker
    // outcome) — the exact mid-dispatch await a dropped future must not turn into a peer-probe revert.
    let state = Arc::new(MockServerState::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    state.push(MockResponse::Gated {
        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        body: json!({"error": {"message": "boom"}}),
        started: started.clone(),
        release: release.clone(),
    });
    let server = MockServer::new(state.clone()).await;

    // One lane, capacity 2: peer A holds one permit + the probe, least_bad's request B needs the other.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("svc", crate::proto::PROTO_ANTHROPIC, &server.base_url())
                .provider("p")
                .max(2),
        )
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::LeastBad)
        .build();

    // Make lane 0 EXPIRED-Open so a single-flight recovery probe can be won on its pool cell.
    app.store.force_open_in("p", 0, 0);

    // PEER A wins the recovery probe (cell → HalfOpen, probe_in_flight=true, epoch E1) and is "in
    // flight": keep the `Admit` alive so A still owns the probe (and one permit) for the whole test.
    let admit_a = app
        .store
        .try_admit("p", 0, now())
        .unwrap_or_else(|_| panic!("peer A must win the recovery probe"));
    // Peer A won a REAL probe (the cell was expired-Open), so `probe_epoch` is `Some(epoch)`.
    let e1 = admit_a
        .probe_epoch
        .expect("peer A won a single-flight probe on the expired-Open cell");
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::HalfOpen),
        "precondition: peer A won the probe (cell HalfOpen)"
    );

    // Request B: lane 0 is HalfOpen + probe_in_flight, so `pick_among` excludes it (ProbeInFlight) and
    // the pool EXHAUSTS → `handle_least_bad` fires and dispatches B onto the same Open member (it sorts
    // first: cooldown 0). B parks in the gated upstream body read BEFORE recording any outcome.
    let b = spawn_request(app.clone());
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .expect("least_bad must dispatch B to the upstream body read");

    // DROP B mid-await (client disconnect): abort the task and let cancellation run its Drop chain.
    b.abort();
    let _ = b.await;
    // Give B's Drop chain a moment to settle before observing the cell.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // THE INVARIANT: B owned NO probe, so its dropped future must have left peer A's LIVE probe intact.
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::HalfOpen),
        "peer A's probe was REVERTED by B's dropped least_bad future — the cell must still be HalfOpen"
    );
    assert_eq!(
        app.store.probe_epoch_in("p", 0),
        e1,
        "peer A's probe epoch must be unchanged (never reverted by B's dropped future)"
    );
    // Single-flight preserved: A's probe is still live, so NO third caller can win a SECOND concurrent
    // probe. On the buggy (armed-guard) path B's drop reverted A's probe → the cell went Open → this
    // `try_admit` would WIN a fresh probe (Ok), breaking single-flight.
    assert!(
        matches!(
            app.store.try_admit("p", 0, now()),
            Err(crate::store::Unavailable::ProbeInFlight)
        ),
        "a third caller must NOT win a second concurrent probe — peer A's probe is still in flight"
    );

    drop(admit_a);
    release.notify_waiters();
    server.shutdown().await;
}

/// The design's claimed no-thundering-herd property: with 2+ requests parked on a 1-permit saturated
/// lane, freeing ONE permit lets EXACTLY ONE waiter dispatch — the survivor stays parked (the single
/// tokio permit can never be handed to two dispatchers, so max_concurrent is never exceeded). Made
/// observable with a gated non-2xx: while the winner holds the one permit inside its body read, the
/// loser is provably still parked; releasing the winner then lets the loser dispatch and serve 200.
#[tokio::test]
async fn queue_two_waiters_one_freed_permit_wakes_exactly_one() {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    // Responses pop from the END: push the plain OK FIRST (served SECOND, to the loser once it wins the
    // freed permit) and the gated 500 LAST (served FIRST, to the winner — it holds the one permit while
    // parked in the gated body read).
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "model": "svc",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    state.push(MockResponse::Gated {
        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        body: json!({"error": {"message": "hold the permit"}}),
        started: started.clone(),
        release: release.clone(),
    });
    let server = MockServer::new(state.clone()).await;

    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let held = sem.clone().try_acquire_owned().unwrap();
    let app = TestApp::new()
        .lane(busy_real_lane("svc", &server.base_url(), &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 30_000 })
        .build();

    // TWO concurrent waiters on the single-permit saturated lane.
    let a = spawn_request(app.clone());
    let b = spawn_request(app.clone());
    wait_until_queued(&app, "p", 2).await;

    // Free EXACTLY ONE permit.
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .expect("exactly one waiter must win the freed permit and dispatch");

    // The winner holds the ONE permit inside its gated body read → no permit remains, and the loser is
    // provably STILL PARKED (not finished). If freeing one permit had woken both (a herd), the second
    // could not have acquired a permit anyway (tokio hands one permit to one waiter) — this locks that.
    assert_eq!(
        sem.available_permits(),
        0,
        "the single freed permit is held by the one winner — none left for a second dispatcher"
    );
    assert!(
        !a.is_finished() && !b.is_finished(),
        "while the winner holds the only permit, the surviving waiter must still be parked (no herd)"
    );

    // Release the winner → its permit frees → the loser wins it and serves the OK (200).
    release.notify_waiters();
    let r1 = tokio::time::timeout(Duration::from_secs(5), a)
        .await
        .expect("waiter A completes")
        .expect("task A ok");
    let r2 = tokio::time::timeout(Duration::from_secs(5), b)
        .await
        .expect("waiter B completes")
        .expect("task B ok");

    // The winner saw the gated 500; the survivor then dispatched serially through the ONE permit and
    // resolved (200 if the breaker held, or 503 if the winner's 500 benched the lane — both are valid
    // SERIAL outcomes; the no-herd/no-double-dispatch core is already proven by the mid-flight
    // permit==0 + both-parked assertions above). The load-bearing fact: exactly one 500, and both
    // resolved without a hang or a double-serve.
    let mut statuses = [r1.status().as_u16(), r2.status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(
        statuses[0], 500,
        "exactly one waiter (the permit winner) saw the gated 500; got {statuses:?}"
    );
    assert!(
        statuses[1] == 200 || statuses[1] == 503,
        "the survivor serializes through the one freed permit to a valid outcome; got {statuses:?}"
    );
    assert_eq!(
        app.queued_depth.depth("p"),
        0,
        "park depth returns to 0 after both waiters resolve"
    );
    server.shutdown().await;
}

/// queue TIMES OUT → 503 + Retry-After when no permit ever frees within `max_ms`. The wait is bounded
/// by `max_ms` (300ms), NOT the long failover budget — it must actually wait ~max_ms (not shed
/// immediately) and shed well before the budget, rather than shedding immediately with no wait.
#[tokio::test]
async fn queue_times_out_to_503_when_capacity_never_frees() {
    crate::metrics::init();
    let (sem, _held) = saturated(); // permit held for the whole test → never frees
    let app = TestApp::new()
        .lane(saturated_lane("busy", &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 300 })
        .build();

    let start = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(4),
        forward_with_pool(
            &app,
            vec![lane(0)],
            chat_body("p").into(),
            None,
            "p",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        ),
    )
    .await
    .expect("the queue wait must be bounded by max_ms and never hang");
    let elapsed = start.elapsed();

    assert_eq!(
        resp.status().as_u16(),
        503,
        "a queue that never gets a permit must fall through to 503"
    );
    assert!(
        retry_after(&resp).is_some(),
        "the timed-out queue 503 must carry Retry-After"
    );
    assert!(
        elapsed >= Duration::from_millis(250),
        "it must actually WAIT ~max_ms before shedding, not shed immediately; waited {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the wait is bounded by max_ms (300ms), not the 300s failover budget; waited {elapsed:?}"
    );
    assert_eq!(
        app.queued_depth.depth("p"),
        0,
        "depth returns to 0 after the timeout"
    );
}

/// queue SKIPS the wait and rejects IMMEDIATELY when NO candidate is `AtCapacity` (all breaker-Open /
/// dead): queuing cannot free a permit on a pool that is DOWN, not busy, so waiting `max_ms` would be
/// pointless. Proven by the reject completing far inside `max_ms`.
#[tokio::test]
async fn queue_skips_wait_and_rejects_when_no_candidate_at_capacity() {
    crate::metrics::init();
    let app = TestApp::new()
        .lane(
            LaneSpec::new("down", crate::proto::PROTO_ANTHROPIC, "http://127.0.0.1:1")
                .provider("p"),
        )
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 3000 })
        .build();
    // Breaker Open (not expired) → the sole exclusion reason is BreakerOpen, never AtCapacity.
    app.store.force_open_in("p", 0, now() + 300);

    let start = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(2),
        forward_with_pool(
            &app,
            vec![lane(0)],
            chat_body("p").into(),
            None,
            "p",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        ),
    )
    .await
    .expect("must not hang");
    let elapsed = start.elapsed();

    assert_eq!(
        resp.status().as_u16(),
        503,
        "a breaker-Open (not at-capacity) pool cannot be helped by queuing → reject"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "queuing cannot help a down pool → skip the 3000ms wait and reject now; took {elapsed:?}"
    );
}

/// No lost wakeup: a permit freed in the SMALL window around when the waiter parks is STORED by the
/// FIFO semaphore and still acquired — so with a SHORT `max_ms` (400ms) the request still DISPATCHES
/// (200) rather than missing the wake and timing out to 503. This is exactly the failure a per-pool
/// `Notify` would exhibit (a wake fired before `notified()` registered is lost); the semaphore-acquire
/// design makes it pass.
#[tokio::test]
async fn queue_no_lost_wakeup_when_permit_freed_in_the_window() {
    crate::metrics::init();
    let svc = ok_server_for("svc").await;
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let held = sem.clone().try_acquire_owned().unwrap();
    let app = TestApp::new()
        .lane(busy_real_lane("svc", &svc.base_url(), &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        // SHORT bound: if the freed-permit wake were lost, this would time out to 503 within 400ms.
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 400 })
        .build();

    let req = spawn_request(app.clone());
    // Free the permit in the tight window right around when the waiter is registering its acquire.
    tokio::time::sleep(Duration::from_millis(5)).await;
    drop(held);

    let resp = tokio::time::timeout(Duration::from_secs(2), req)
        .await
        .expect("must not hang")
        .expect("task panicked");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a permit freed in the window must not be lost — the stored permit dispatches the request"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        1,
        "the freed lane served it"
    );
    svc.shutdown().await;
}

/// Won-permit-but-breaker-now-Open: the waiter acquires a freed permit but the lane's breaker TRIPPED
/// Open while it was queued. The breaker re-check on the won lane must REFUSE — the request must never
/// dispatch onto the Open lane, and (single candidate) falls through to 503. Proves the breaker
/// composition on the won lane.
#[tokio::test]
async fn queue_won_permit_but_breaker_now_open_never_dispatches() {
    crate::metrics::init();
    let svc = ok_server_for("svc").await; // wired, but must NEVER be dispatched to
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let held = sem.clone().try_acquire_owned().unwrap();
    let app = TestApp::new()
        .lane(busy_real_lane("svc", &svc.base_url(), &sem))
        .pool("p", &[(0, 1)])
        .failover(long_failover())
        .on_exhausted("p", crate::config::OnExhausted::Queue { max_ms: 2000 })
        .build();

    let req = spawn_request(app.clone());
    // Poll until the request has actually PARKED in the queue (deterministic; not a fixed sleep that is
    // flaky under CI load), matching the sibling queue tests.
    wait_until_queued(&app, "p", 1).await;
    // Trip the breaker Open WHILE queued, THEN free the permit: the waiter wins capacity but the
    // breaker re-check must refuse and never dispatch onto the now-Open lane.
    app.store.force_open_in("p", 0, now() + 300);
    drop(held);

    let resp = tokio::time::timeout(Duration::from_secs(3), req)
        .await
        .expect("must not hang")
        .expect("task panicked");
    assert_eq!(
        resp.status().as_u16(),
        503,
        "a lane whose breaker opened while queued must not be dispatched to → 503"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        0,
        "the now-Open lane served nothing (never dispatched onto)"
    );
    svc.shutdown().await;
}
