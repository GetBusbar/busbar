// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Property-based invariant for the lane-availability refactor (design §6, R4) + the failover budget
//! contract (§5, R6).
//!
//! A `proptest` generator builds a WORLD — a primary pool (1–5 members) and, for the `fallback_pool`
//! policy, a fallback pool (1–4 members); each member is bounded(cap 1–8) | unbounded | saturated,
//! with an initial breaker of Closed | Open{active} | Open{expired} | HalfOpen, an ∞|exhausted budget,
//! and a dead flag — under one of the four `on_exhausted` policies (reject | least_bad | fallback_pool
//! | queue{max_ms}). Causes (saturate permits, trip breakers, exhaust budget, kill lanes) and their
//! combinations are generated per member. One request is then driven through the REAL
//! `forward_with_pool` selection + `on_exhausted` dispatch against a mock provider.
//!
//! ## The STRENGTHENED invariant (R4 — disposition-matches-policy, not a pure latency bound)
//!
//! At DECISION time an ELIGIBLE primary lane is `classify(primary, lane) == Ok` — admissible (not
//! dead / in budget), the breaker would admit, AND a free permit exists — exactly the predicate
//! `try_admit` succeeds on for a single (uncontended) request. Per case we assert the request EITHER
//!   (a) dispatches on an ELIGIBLE lane (served by the primary pool), OR
//!   (b) is disposed of PER POLICY:
//!       * `reject`        → 503 + `Retry-After` ≥ the at-capacity floor (2s) / the real cooldown,
//!       * `least_bad`     → dispatched to a free admissible sibling (NOT 503 when one exists),
//!       * `fallback_pool` → SERVED BY THE FALLBACK POOL (primary serves ZERO) when the fallback has
//!                           an eligible member, else 503 — the discriminating Bug-1 assertion,
//!       * `queue{max_ms}` → waited ≤ max_ms then 503 (permits are held for the whole case, so none
//!                           ever frees);
//! and in ALL cases the wall clock from ingress to disposition stays within the failover budget, and
//! a 503 is NEVER returned while an eligible lane existed at decision time.
//!
//! A pure latency bound is NOT sufficient — the disposition is asserted. The Bug-1 witness
//! (breaker-healthy primary + at-capacity + fallback_pool ⇒ MUST spill, never park-then-serve-primary)
//! is dominated by [`assert_served_by_fallback_not_primary`], whose TEETH are proven by
//! [`invariant_rejects_park_then_serve_primary_witness`].

use crate::config::{FailoverCfg, OnExhausted};
use crate::proxy::forward_with_pool;
use crate::state::{now, WeightedLane};
use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Fixtures ─────────────────────────────────────────────────────────────────────────────────────

/// Failover budget (whole seconds) for every generated world. Small enough that the budget bound is
/// MEANINGFUL (a park to the deadline would blow it), large enough to comfortably serve an instant
/// mock. The queue `max_ms` is generated ≤ 50ms, far below this.
const FAILOVER_SECS: u64 = 2;

/// Test-level slack ε for the ingress→disposition budget bound. Tighter than the in-code
/// `debug_assert` ε (which guards against SECONDS-scale regressions) — this is the real, meaningful
/// bound the property test enforces: disposition within `FAILOVER_SECS + ε`.
const TEST_BUDGET_EPS: Duration = Duration::from_millis(1500);

fn wlane(idx: usize) -> WeightedLane {
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

/// Numeric `Retry-After` seconds off a response, if present.
fn retry_after_secs(resp: &axum::response::Response) -> Option<u64> {
    resp.headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

// ── Generated world ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Breaker {
    /// Healthy, ready to admit.
    Closed,
    /// Open with a cooldown well in the FUTURE — genuinely unavailable for the whole request.
    OpenActive,
    /// Open with an EXPIRED cooldown — probe-winnable, so ELIGIBLE if it also has a free permit.
    OpenExpired,
    /// A single-flight recovery probe is in flight (HalfOpen) — not admissible until it resolves.
    HalfOpen,
}

#[derive(Debug, Clone, Copy)]
enum Cap {
    /// `max_concurrent` omitted (realized as `MAX_PERMITS`) — never at capacity.
    Unbounded,
    /// Bounded with a free permit (cap 1–8).
    BoundedFree(usize),
    /// Bounded `max_concurrent: 1` whose only permit the test HOLDS for the whole case → permanently
    /// at capacity (the deterministic saturation of the Bug-1 suite).
    Saturated,
}

#[derive(Debug, Clone, Copy)]
struct Member {
    dead: bool,
    budget_out: bool,
    breaker: Breaker,
    cap: Cap,
}

#[derive(Debug, Clone, Copy)]
enum Policy {
    Reject,
    LeastBad,
    Fallback,
    Queue(u64),
}

#[derive(Debug, Clone)]
struct World {
    primary: Vec<Member>,
    fallback: Vec<Member>,
    policy: Policy,
}

fn breaker_strat() -> impl Strategy<Value = Breaker> {
    prop_oneof![
        Just(Breaker::Closed),
        Just(Breaker::OpenActive),
        Just(Breaker::OpenExpired),
        Just(Breaker::HalfOpen),
    ]
}

fn cap_strat() -> impl Strategy<Value = Cap> {
    prop_oneof![
        Just(Cap::Unbounded),
        (1usize..=8).prop_map(Cap::BoundedFree),
        Just(Cap::Saturated),
    ]
}

fn member_strat() -> impl Strategy<Value = Member> {
    (any::<bool>(), any::<bool>(), breaker_strat(), cap_strat()).prop_map(
        |(dead, budget_out, breaker, cap)| Member {
            dead,
            budget_out,
            breaker,
            cap,
        },
    )
}

fn policy_strat() -> impl Strategy<Value = Policy> {
    prop_oneof![
        Just(Policy::Reject),
        Just(Policy::LeastBad),
        Just(Policy::Fallback),
        (5u64..=50).prop_map(Policy::Queue),
    ]
}

fn world_strat() -> impl Strategy<Value = World> {
    (
        prop::collection::vec(member_strat(), 1..=5),
        prop::collection::vec(member_strat(), 1..=4),
        policy_strat(),
    )
        .prop_map(|(primary, fallback, policy)| World {
            primary,
            fallback,
            policy,
        })
}

// ── Shared disposition assertions (also the TEETH surface) ───────────────────────────────────────

/// `reject` disposition: a 503 whose `Retry-After` reflects the ACTUAL backpressure axis. `soonest` is
/// the min genuine future cooldown across ADMISSIBLE members (None if none); `any_at_cap` is whether
/// any candidate is at its concurrency limit. Mirrors `walk::retry_after_secs` exactly, with ±1s
/// tolerance on the time-dependent cooldown branch (a second may tick between decision and shed).
fn assert_disposition_reject(ra: u64, soonest: Option<u64>, any_at_cap: bool) {
    assert!(ra >= 1, "Retry-After must be a sane floor (>= 1); got {ra}");
    match soonest {
        // Pure saturation — jitter-free constant floor. This is the Bug-1 Finding-3 guard: an
        // at-capacity shed must NOT advertise the misleading `Retry-After: 1`.
        None if any_at_cap => assert!(
            ra >= 2,
            "a purely at-capacity 503 must floor Retry-After at >= 2 (never 1); got {ra}"
        ),
        // A genuine breaker cooldown drives the hint.
        Some(s) => assert!(
            ra + 1 >= s && ra <= s + 1,
            "Retry-After {ra} must track the ~{s}s genuine cooldown (±1s)"
        ),
        // No cooldown, nothing at capacity (e.g. every member dead/budget-exhausted) — the bare floor.
        None => {}
    }
}

/// THE discriminating Bug-1 assertion, factored out so its TEETH can be proven directly
/// ([`invariant_rejects_park_then_serve_primary_witness`]). Under `fallback_pool` with an eligible
/// fallback, the request MUST SPILL: served with 200 by the FALLBACK pool, with the at-capacity/parked
/// primary serving ZERO. A park-then-dispatch-before-deadline impl (which serves the PRIMARY once its
/// permit frees) yields `primary_ok == 1, fallback_ok == 0` and MUST fail here — a pure latency bound
/// would let it pass.
fn assert_served_by_fallback_not_primary(status: u16, primary_ok: u64, fallback_ok: u64) {
    assert_eq!(
        status, 200,
        "fallback_pool with an eligible fallback must SERVE (spill), not shed"
    );
    assert_eq!(
        primary_ok, 0,
        "Bug-1: the at-capacity primary must serve ZERO — the request must SPILL to the fallback, \
         never park-then-serve the primary"
    );
    assert_eq!(
        fallback_ok, 1,
        "the eligible fallback pool must serve exactly the one spilled request"
    );
}

// ── The property test ────────────────────────────────────────────────────────────────────────────

/// Which disposition branch `run_world` actually drove for a case — returned so a targeted test can
/// PROVE the harness plumbing reaches a specific assertion (e.g. `FallbackSpill` ⇒ the fb_elig branch's
/// [`assert_served_by_fallback_not_primary`] actually ran), closing the "does the generator/harness
/// reach it, or only the hand-fed witness?" gap.
#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    PrimaryServed,
    Reject,
    LeastBadServed,
    LeastBadShed,
    FallbackSpill,
    FallbackCascade,
    QueueShed,
}

/// Drive one request through the REAL selection + dispatch for `world` and assert the strengthened
/// invariant. Panics on violation (proptest treats the panic as a failing case and shrinks). Returns
/// the [`Disposition`] branch taken so a targeted test can assert the harness reached it.
async fn run_world(world: World) -> Disposition {
    crate::metrics::init();

    // One mock provider that answers every request with a default 200 (an empty queue pops nothing and
    // falls back to the default OK), so any number of healthy lanes / retries are served.
    let server = MockServer::new(Arc::new(MockServerState::new())).await;
    let url = server.base_url();

    let p = world.primary.len();
    let total = p + world.fallback.len();
    let is_fallback = matches!(world.policy, Policy::Fallback);

    // Held permits keep the `Saturated` lanes permanently at capacity for the case's lifetime.
    let mut held_permits: Vec<tokio::sync::OwnedSemaphorePermit> = Vec::new();

    let mut builder = TestApp::new();
    let all: Vec<Member> = world
        .primary
        .iter()
        .chain(world.fallback.iter())
        .copied()
        .collect();
    for (i, m) in all.iter().enumerate() {
        let model = format!("m{i}");
        let mut spec =
            LaneSpec::new(&model, crate::proto::Protocol::anthropic(), &url).provider("p");
        match m.cap {
            Cap::Unbounded => spec = spec.max(tokio::sync::Semaphore::MAX_PERMITS),
            Cap::BoundedFree(c) => spec = spec.max(c),
            Cap::Saturated => {
                let sem = Arc::new(tokio::sync::Semaphore::new(1));
                held_permits.push(sem.clone().try_acquire_owned().unwrap());
                spec = spec.max(1).sem(sem);
            }
        }
        if m.dead {
            spec = spec.dead("test-dead");
        }
        if m.budget_out {
            spec = spec.budget(0);
        }
        builder = builder.lane(spec);
    }

    let primary_members: Vec<(usize, u32)> = (0..p).map(|i| (i, 1)).collect();
    builder = builder
        .pool("primary", &primary_members)
        .failover(FailoverCfg {
            timeout_secs: FAILOVER_SECS,
            exclusions: None,
            max_hops: 3,
        });
    builder = match world.policy {
        Policy::Reject => builder.on_exhausted("primary", OnExhausted::Status503),
        Policy::LeastBad => builder.on_exhausted("primary", OnExhausted::LeastBad),
        Policy::Queue(ms) => builder.on_exhausted("primary", OnExhausted::Queue { max_ms: ms }),
        Policy::Fallback => {
            let fb_members: Vec<(usize, u32)> = (p..total).map(|i| (i, 1)).collect();
            builder
                .on_exhausted("primary", OnExhausted::FallbackPool("fallback".into()))
                .fallback_pool("fallback", &fb_members)
        }
    };
    let app = builder.build();

    // Apply the generated breaker states. `force_open_in` seeds Open (future = active, past = expired);
    // an expired-Open cell driven once through `acquire_for_dispatch_in` wins its single-flight probe
    // and is left HalfOpen (probe in flight) — a real ProbeInFlight state, un-settable otherwise.
    let t = now();
    let apply = |pool: &str, idx: usize, b: Breaker| match b {
        Breaker::Closed => {}
        Breaker::OpenActive => app.store.force_open_in(pool, idx, t + 30),
        Breaker::OpenExpired => app.store.force_open_in(pool, idx, t.saturating_sub(1)),
        Breaker::HalfOpen => {
            app.store.force_open_in(pool, idx, t.saturating_sub(1));
            let _ = app.store.acquire_for_dispatch_in(pool, idx, t);
        }
    };
    for (i, m) in world.primary.iter().enumerate() {
        apply("primary", i, m.breaker);
    }
    if is_fallback {
        for (j, m) in world.fallback.iter().enumerate() {
            apply("fallback", p + j, m.breaker);
        }
    }

    // ── Oracle: compute the decision-time predicates from the SAME store primitives the code uses. ──
    let t2 = now();
    let elig_primary: Vec<usize> = (0..p)
        .filter(|&i| app.store.classify("primary", i, t2).is_ok())
        .collect();
    // reject Retry-After axes (mirror `walk::retry_after_secs`).
    let soonest = (0..p)
        .filter(|&i| app.store.lane_admissible(i))
        .map(|i| app.store.cooldown_remaining_in("primary", i, t2))
        .filter(|&r| r > 0)
        .min();
    let any_at_cap = (0..p).any(|i| app.store.available_permits(i) == 0);
    // least_bad serves iff SOME admissible member has a free permit (breaker is bypassed).
    let ls_serve =
        (0..p).any(|i| app.store.lane_admissible(i) && app.store.available_permits(i) > 0);
    // fallback serves iff SOME fallback member is eligible.
    let fb_elig = is_fallback && (p..total).any(|i| app.store.classify("fallback", i, t2).is_ok());

    // ── Drive the request through the real path. ──
    let cands: Vec<WeightedLane> = (0..p).map(wlane).collect();
    let start = Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        forward_with_pool(
            app.clone(),
            cands,
            chat_body("primary").into(),
            None,
            "primary",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        ),
    )
    .await
    .expect("the request must never hang past the hard cap — the failover budget bounds it");
    let elapsed = start.elapsed();
    let status = resp.status().as_u16();

    let t3 = now();
    let primary_ok: u64 = (0..p).map(|i| app.store.snapshot(i, t3).ok).sum();
    let fallback_ok: u64 = (p..total).map(|i| app.store.snapshot(i, t3).ok).sum();

    // ── Budget contract (§5/R6): ingress→disposition ≤ failover.timeout + ε, ALWAYS. ──
    assert!(
        elapsed <= Duration::from_secs(FAILOVER_SECS) + TEST_BUDGET_EPS,
        "ingress→disposition {elapsed:?} exceeded the failover budget ({FAILOVER_SECS}s) + ε; \
         policy={:?}",
        world.policy
    );

    // ── The strengthened, disposition-matches-policy invariant (R4). ──
    let disposition = if !elig_primary.is_empty() {
        // (a) An eligible primary lane existed → it MUST dispatch there, never shed, never spill.
        assert_eq!(
            status, 200,
            "an eligible primary lane existed ({elig_primary:?}) but the request did not dispatch \
             200 — a 503/spill while an eligible lane exists is forbidden; policy={:?}",
            world.policy
        );
        assert_eq!(
            primary_ok, 1,
            "exactly one eligible primary lane must serve the request"
        );
        assert_eq!(
            fallback_ok, 0,
            "the fallback pool must not be touched while the primary can serve"
        );
        Disposition::PrimaryServed
    } else {
        // (b) Primary exhausted → disposition PER POLICY.
        match world.policy {
            Policy::Reject => {
                assert_eq!(status, 503, "exhausted `reject` pool must shed 503");
                let ra = retry_after_secs(&resp).expect("a reject 503 must carry Retry-After");
                assert_disposition_reject(ra, soonest, any_at_cap);
                Disposition::Reject
            }
            Policy::LeastBad => {
                if ls_serve {
                    assert_eq!(
                        status, 200,
                        "least_bad must degrade onto a free admissible sibling, not 503"
                    );
                    assert_eq!(primary_ok, 1, "least_bad served exactly one primary member");
                    assert_eq!(fallback_ok, 0, "least_bad never spills to a fallback pool");
                    Disposition::LeastBadServed
                } else {
                    assert_eq!(
                        status, 503,
                        "least_bad with no free admissible member must shed 503"
                    );
                    assert!(
                        retry_after_secs(&resp).is_some(),
                        "a least_bad 503 must carry Retry-After"
                    );
                    Disposition::LeastBadShed
                }
            }
            Policy::Fallback => {
                if fb_elig {
                    assert_served_by_fallback_not_primary(status, primary_ok, fallback_ok);
                    Disposition::FallbackSpill
                } else {
                    assert_eq!(
                        status, 503,
                        "fallback_pool whose fallback is also exhausted must cascade to 503"
                    );
                    assert_eq!(primary_ok, 0, "the parked primary must serve nothing");
                    assert!(
                        retry_after_secs(&resp).is_some(),
                        "the cascaded 503 must carry Retry-After"
                    );
                    Disposition::FallbackCascade
                }
            }
            Policy::Queue(max_ms) => {
                // Every saturating permit is held for the whole case, so no permit ever frees: the
                // queue either skips the wait (no AtCapacity candidate) or waits ≤ max_ms then sheds —
                // either way a bounded 503, NEVER a park to the failover deadline.
                assert_eq!(
                    status, 503,
                    "queue under sustained saturation must fall through to 503, never dispatch"
                );
                assert!(
                    retry_after_secs(&resp).is_some(),
                    "a timed-out queue 503 must carry Retry-After"
                );
                assert!(
                    elapsed <= Duration::from_millis(max_ms) + TEST_BUDGET_EPS,
                    "queue waited {elapsed:?}, exceeding max_ms {max_ms} + ε — it must be bounded by \
                     max_ms, not the failover budget"
                );
                Disposition::QueueShed
            }
        }
    };

    server.shutdown().await;
    drop(held_permits);
    disposition
}

proptest! {
    // CI-friendly: 128 cases over small topologies; the per-case hard cap (5s) and shrink bound keep
    // wall time reasonable. No per-case proptest `timeout` (would need the fork feature) — the inner
    // `tokio::time::timeout` is the hang guard.
    #![proptest_config(ProptestConfig { cases: 128, max_shrink_iters: 256, ..ProptestConfig::default() })]

    #[test]
    fn strengthened_lane_availability_invariant(world in world_strat()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run_world(world));
    }
}

// ── Teeth: the invariant CATCHES the park-then-dispatch (Bug-1) failure ───────────────────────────

/// Proof that [`assert_served_by_fallback_not_primary`] — the discriminating fallback disposition the
/// property test enforces — has TEETH: it REJECTS the exact park-then-dispatch-before-deadline outcome
/// (a breaker-healthy at-capacity primary that PARKS and then serves the PRIMARY once its permit frees,
/// `primary_ok=1, fallback_ok=0`) even though that outcome satisfies any pure latency bound (it
/// returns 200 fast). A broken impl that produced it would fail the property test here; the correct
/// SPILL outcome passes.
#[test]
fn invariant_rejects_park_then_serve_primary_witness() {
    // Silence the default panic printer for the deliberately-panicking witness below.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    // BROKEN park-then-serve-primary witness: 200, but served by the parked PRIMARY, fallback untouched.
    let broken = std::panic::catch_unwind(|| {
        assert_served_by_fallback_not_primary(200, /*primary_ok*/ 1, /*fallback_ok*/ 0);
    });
    std::panic::set_hook(prev);
    assert!(
        broken.is_err(),
        "the invariant FAILED to catch park-then-serve-primary — it lacks teeth and does not \
         dominate Bug-1"
    );

    // The CORRECT spill outcome passes the very same assertion.
    assert_served_by_fallback_not_primary(200, /*primary_ok*/ 0, /*fallback_ok*/ 1);
}

/// HARNESS teeth, via a TARGETED (hand-constructed) shape — NOT the proptest generator. The witness
/// above proves the assertion FUNCTION rejects a bad triple, but not that `run_world`'s
/// Policy::Fallback / fb_elig plumbing actually REACHES it on a real dispatch. This drives one `World`
/// shaped exactly for the fb_elig branch — a breaker-healthy but SATURATED primary (so `elig_primary`
/// is empty and the Bug-1 park-then-serve temptation is live) with an eligible (Closed, free) fallback
/// — through the REAL `run_world` harness, and asserts it took the `FallbackSpill` branch. That branch
/// is where `assert_served_by_fallback_not_primary` runs, so a wiring bug that short-circuited before
/// it (a shadowed `if`, an early return) would make this return something other than `FallbackSpill`
/// and fail here.
///
/// Scope honesty: this shape is HAND-BUILT, not drawn from `world_strat()`. The generator's coverage of
/// this exact branch is exercised by the main `strengthened_lane_availability_invariant` proptest, which
/// runs `run_world` over 128 generated worlds and whose `world_strat()` can produce this
/// healthy-saturated-primary + eligible-fallback shape — there, reaching the branch runs the same
/// in-`run_world` `assert_served_by_fallback_not_primary`. So this test's job is narrow and named for it:
/// prove the fb_elig branch is REACHABLE on the real dispatch path for a concrete targeted shape.
#[tokio::test]
async fn run_world_reaches_fallback_spill_assertion_on_targeted_shape() {
    let world = World {
        primary: vec![Member {
            dead: false,
            budget_out: false,
            breaker: Breaker::Closed,
            cap: Cap::Saturated, // healthy but at capacity → not eligible → the spill trigger
        }],
        fallback: vec![Member {
            dead: false,
            budget_out: false,
            breaker: Breaker::Closed,
            cap: Cap::Unbounded, // eligible fallback → fb_elig == true
        }],
        policy: Policy::Fallback,
    };
    assert_eq!(
        run_world(world).await,
        Disposition::FallbackSpill,
        "run_world must actually REACH and pass the fb_elig assert_served_by_fallback_not_primary \
         branch on this generated fallback shape — not skip it"
    );
}

/// The concrete Bug-1 witness on the REAL dispatch path, tied to the shared discriminating assertion:
/// a breaker-HEALTHY (Closed) but AT-CAPACITY primary under `fallback_pool` MUST spill to the eligible
/// fallback (served by the fallback, primary serves zero) — never park-then-serve the primary.
#[tokio::test]
async fn bug1_witness_fallback_spills_served_by_fallback_not_primary() {
    crate::metrics::init();
    let server = MockServer::new(Arc::new(MockServerState::new())).await;
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let _held = sem.clone().try_acquire_owned().unwrap(); // primary permanently at capacity

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("p")
            .max(1)
            .sem(sem.clone()),
        ) // idx 0 — breaker-healthy but saturated
        .lane(
            LaneSpec::new(
                "spare",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("p"),
        ) // idx 1 — eligible fallback
        .pool("primary", &[(0, 1)])
        .failover(FailoverCfg {
            timeout_secs: FAILOVER_SECS,
            exclusions: None,
            max_hops: 3,
        })
        .on_exhausted("primary", OnExhausted::FallbackPool("overflow".into()))
        .fallback_pool("overflow", &[(1, 1)])
        .build();

    let resp = forward_with_pool(
        app.clone(),
        vec![wlane(0)],
        chat_body("primary").into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    let primary_ok = app.store.snapshot(0, now()).ok;
    let fallback_ok = app.store.snapshot(1, now()).ok;
    assert_served_by_fallback_not_primary(resp.status().as_u16(), primary_ok, fallback_ok);
    server.shutdown().await;
}

// ── Budget contract holds under full saturation for EVERY policy (§5/R6) ──────────────────────────

/// The failover budget bound holds under FULL saturation for every `on_exhausted` policy: with the
/// primary member(s) permanently at capacity, ingress→disposition stays within `FAILOVER_SECS + ε`
/// and the request sheds 503 rather than parking to the (long-relative) deadline. This is the
/// wall-clock companion to the in-dispatcher `debug_assert_within_budget` (which is ALSO live during
/// this test).
#[tokio::test]
async fn budget_contract_holds_under_full_saturation_for_every_policy() {
    crate::metrics::init();

    for policy in [
        OnExhausted::Status503,
        OnExhausted::LeastBad,
        OnExhausted::Queue { max_ms: 50 },
        OnExhausted::FallbackPool("overflow".into()),
    ] {
        let server = MockServer::new(Arc::new(MockServerState::new())).await;
        let sem_a = Arc::new(tokio::sync::Semaphore::new(1));
        let _held_a = sem_a.clone().try_acquire_owned().unwrap();
        let sem_b = Arc::new(tokio::sync::Semaphore::new(1));
        let _held_b = sem_b.clone().try_acquire_owned().unwrap();

        let is_fallback = matches!(policy, OnExhausted::FallbackPool(_));
        let mut builder = TestApp::new()
            .lane(
                LaneSpec::new(
                    "busy",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("p")
                .max(1)
                .sem(sem_a.clone()),
            )
            .lane(
                LaneSpec::new(
                    "overflow",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("p")
                .max(1)
                .sem(sem_b.clone()),
            )
            .pool("primary", &[(0, 1)])
            .failover(FailoverCfg {
                timeout_secs: FAILOVER_SECS,
                exclusions: None,
                max_hops: 3,
            })
            .on_exhausted("primary", policy.clone());
        if is_fallback {
            // The fallback is ALSO saturated → the spill cascades to 503, still within budget.
            builder = builder.fallback_pool("overflow", &[(1, 1)]);
        }
        let app = builder.build();

        let start = Instant::now();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            forward_with_pool(
                app.clone(),
                vec![wlane(0)],
                chat_body("primary").into(),
                None,
                "primary",
                None,
                "anthropic",
                crate::handlers::CHAT,
                None,
            ),
        )
        .await
        .expect("saturated dispatch must never hang past the budget");
        let elapsed = start.elapsed();

        assert_eq!(
            resp.status().as_u16(),
            503,
            "a fully-saturated pool must shed 503 under {policy:?}"
        );
        assert!(
            elapsed <= Duration::from_secs(FAILOVER_SECS) + TEST_BUDGET_EPS,
            "ingress→disposition {elapsed:?} exceeded the failover budget for {policy:?}"
        );
        server.shutdown().await;
    }
}
