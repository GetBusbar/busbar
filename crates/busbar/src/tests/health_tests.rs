// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/health.rs`.

use super::*;
use crate::config::{HealthCfg, HealthMode};
use crate::proto::Protocol;
use crate::store::BreakerState;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use axum::http::StatusCode;
use std::sync::Arc;

fn health_active() -> HealthCfg {
    HealthCfg {
        mode: HealthMode::Active,
        interval_secs: Some(30),
        timeout_secs: Some(5),
    }
}

/// Stand up a mock upstream that returns `resp`, build a one-lane App (anthropic, in pool `p`)
/// pointed at it, run a single probe, and hand back the App so the test can inspect the breaker.
async fn probe_once(resp: MockResponse) -> (Arc<crate::state::App>, MockServer) {
    let state = Arc::new(MockServerState::new());
    state.push(resp);
    let server = MockServer::new(state).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();
    probe_lane(&app, 0, Duration::from_secs(5)).await;
    (app, server)
}

/// An active health probe must send the SAME native-SDK fingerprint
/// headers organic traffic sends — `User-Agent` and `Accept` — or a backend could fingerprint
/// and special-case busbar's probes (defeating indistinguishability). reqwest emits no default
/// User-Agent, so its absence on the probe was a tell.
#[tokio::test]
async fn test_probe_sends_native_user_agent_and_accept_headers() {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: serde_json::json!({"ok": true}),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();
    probe_lane(&app, 0, Duration::from_secs(5)).await;
    // The probe carries the protocol's native-SDK User-Agent and Accept (non-streaming), exactly
    // as the organic forward path does (egress_user_agent / egress_accept).
    assert_eq!(
        state.get_last_request_header("user-agent").as_deref(),
        Some(crate::proxy::egress_user_agent("anthropic")),
        "probe must send the native User-Agent organic traffic sends"
    );
    assert_eq!(
        state.get_last_request_header("accept").as_deref(),
        Some(crate::proxy::egress_accept("anthropic", false)),
        "probe must send the native Accept organic traffic sends"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn test_probe_auth_failure_is_hard_down_not_transient() {
    // Regression: a 401 probe must classify as HardDown (auth) and PARK the lane dead in the
    // default cell AND the per-pool cell — not be mis-recorded as a recoverable transient that
    // oscillates between cooldown and re-probe forever.
    let (app, server) = probe_once(MockResponse::Auth {
        status: StatusCode::UNAUTHORIZED,
    })
    .await;

    assert!(
        matches!(app.store.breaker_state(0), BreakerState::Open { .. }),
        "401 probe must trip the default cell Open (hard-down), got {:?}",
        app.store.breaker_state(0)
    );
    assert!(
        app.store.cooldown_remaining_in("p", 0, now()) > 60,
        "401 probe must arm the long sticky hard-down cooldown on the per-pool cell, not a \
             short transient cooldown"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn test_probe_server_error_is_transient_not_hard_down() {
    // A single 503 probe is a transient failure: it must NOT immediately Open the default cell
    // with the multi-minute sticky hard-down cooldown (one sub-threshold transient stays Closed
    // under the default error-rate breaker).
    let (app, server) = probe_once(MockResponse::ServerError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: serde_json::json!({"error": "upstream down"}),
    })
    .await;

    assert!(
        matches!(app.store.breaker_state(0), BreakerState::Closed),
        "a single 503 probe must record a transient (no immediate hard-down trip), got {:?}",
        app.store.breaker_state(0)
    );
    server.shutdown().await;
}

#[tokio::test]
async fn test_probe_client_fault_does_not_penalize_lane() {
    // A 400 (client fault — the probe request shape, not the lane) must record NOTHING: the lane
    // stays Closed with no cooldown, so a healthy lane is never benched over a probe-construction
    // issue.
    let (app, server) = probe_once(MockResponse::ServerError {
        status: StatusCode::BAD_REQUEST,
        body: serde_json::json!({"error": "bad request"}),
    })
    .await;

    assert!(
        matches!(app.store.breaker_state(0), BreakerState::Closed),
        "a 400 probe (client fault) must not trip the breaker, got {:?}",
        app.store.breaker_state(0)
    );
    assert_eq!(
        app.store.cooldown_remaining_in("p", 0, now()),
        0,
        "a 400 probe (client fault) must not arm any cooldown"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn test_probe_skips_lane_without_key() {
    // No api_key → no probe (can't authenticate; a guaranteed 401 would only thrash the breaker).
    // The lane must stay Closed even though no upstream is reachable.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), "http://127.0.0.1:1")
                .api_key("")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();
    probe_lane(&app, 0, Duration::from_secs(1)).await;
    assert!(matches!(app.store.breaker_state(0), BreakerState::Closed));
}

/// A 2xx probe must record a SUCCESS into
/// every cell's sliding error-rate window, not just a failed probe recording a FAILURE. With the
/// old failure-only accounting, a lane whose probes intermittently fail presented a window holding
/// ONLY failures, so the error-rate breaker (errors / total) read ~100% and tripped a recoverable
/// lane. Here we drive 7 successful probes then 5 failing (503) probes against a default error-rate
/// breaker (min_requests=5, threshold=0.5): the failures alone would breach (5/5 = 1.0 >= 0.5 →
/// Open), but the recorded successes dilute the window to 5/12 ≈ 0.42 < 0.5, so BOTH the default
/// cell and the per-pool cell stay Closed. Against the pre-fix code (no success recorded) the 5th
/// failure trips the default cell Open — this test fails there and passes after.
#[tokio::test]
async fn test_probe_success_recorded_so_intermittent_failures_dont_trip() {
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();

    // 7 successful probes: each must push a SUCCESS into both the default and the per-pool cell's
    // window (the per-pool cell is lazily created Closed on the first success record).
    for _ in 0..7 {
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({ "ok": true }),
        });
        probe_lane(&app, 0, Duration::from_secs(5)).await;
    }
    // 5 failing (503 transient) probes. The failure path records into the SAME cells. Even at the
    // 5th failure the windows hold 7 successes + 5 errors → 5/12 < 0.5 → no trip.
    for _ in 0..5 {
        state.push(MockResponse::ServerError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: serde_json::json!({ "error": "upstream down" }),
        });
        probe_lane(&app, 0, Duration::from_secs(5)).await;
    }

    assert!(
        matches!(app.store.breaker_state(0), BreakerState::Closed),
        "recorded probe successes must dilute the error-rate window so 5 of 12 outcomes stays \
             below the 0.5 trip threshold; default cell should remain Closed, got {:?}",
        app.store.breaker_state(0)
    );
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::Closed),
        "the per-pool cell organic traffic routes against must likewise stay Closed once probe \
             successes are recorded into its window, got {:?}",
        app.store.breaker_state_in("p", 0)
    );
    server.shutdown().await;
}

/// A 2xx probe on an already-Closed, never-tripped lane must still push
/// a success outcome into the lane's window (the success half of symmetric accounting) — it is NOT
/// silently dropped just because the lane needed no recovery. We assert observably: after one
/// success probe followed by 4 failing probes, the default cell holds 1 success + 4 errors = 5
/// outcomes at 4/5 = 0.8 >= 0.5 and trips Open; if the success had NOT been recorded the window
/// would hold only 4 errors (4 < min_requests=5) and stay Closed. So an Open default cell here
/// proves the healthy-lane success was recorded.
#[tokio::test]
async fn test_probe_success_recorded_even_on_healthy_lane() {
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();

    // One success on a healthy (Closed, untripped) lane — recovery is a no-op, but the success
    // must still be recorded into the window.
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: serde_json::json!({ "ok": true }),
    });
    probe_lane(&app, 0, Duration::from_secs(5)).await;
    // 4 failing probes. With the success recorded the window is 1 success + 4 errors = 5 outcomes
    // (>= min_requests) at 4/5 = 0.8 >= 0.5 → trips Open. Without the success it would be 4 errors
    // only (< min_requests) → stays Closed.
    for _ in 0..4 {
        state.push(MockResponse::ServerError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: serde_json::json!({ "error": "upstream down" }),
        });
        probe_lane(&app, 0, Duration::from_secs(5)).await;
    }

    assert!(
            matches!(app.store.breaker_state(0), BreakerState::Open { .. }),
            "the healthy-lane probe success must be recorded so the window reaches min_requests (1 \
             success + 4 errors = 5 at 0.8 error rate) and trips Open; a Closed cell here would mean \
             the success was dropped, got {:?}",
            app.store.breaker_state(0)
        );
    server.shutdown().await;
}

/// A single SUCCESSFUL probe bumps the lane-global `ok` stat EXACTLY
/// ONCE — not once per cell. The lane sits in THREE pools, so the pre-fix code (which recorded the
/// success via a per-cell `record_success_in` loop over the default cell plus every pool) bumped
/// `LaneState.ok` 4 times per 2xx probe (1 default + 3 pools), inflating the public `/stats` `ok`
/// metric by (N+1). The SYMMETRIC failure path was already decoupled (one `err` bump
/// per probe) but the success path still multi-counted. After the fix `ok` rises by exactly 1 per
/// successful probe, mirroring how `record_probe_failure_all_cells` bumps `err` once. We drive 2
/// probes and assert `ok == 2` (the pre-fix code would read 8).
#[tokio::test]
async fn test_probe_success_bumps_lane_ok_once_not_per_cell() {
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(health_active()),
        )
        // Same lane fronted by three distinct pools — the per-cell success loop would bump the
        // lane-global `ok` (1 default + 3 pools) = 4 times per probe under the old code.
        .pool("a", &[(0, 1)])
        .pool("b", &[(0, 1)])
        .pool("c", &[(0, 1)])
        .build();

    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({ "ok": true }),
        });
        probe_lane(&app, 0, Duration::from_secs(5)).await;
    }

    assert_eq!(
            app.store.snapshot(0, now()).ok,
            2,
            "a successful probe must bump the lane-global `ok` exactly once (mirroring the single \
             `err` bump on the failure path); a lane in 3 pools probed twice must read ok == 2, not \
             ok == 8 (the pre-fix per-cell multi-count of 4 per probe)"
        );
    server.shutdown().await;
}

/// REGRESSION: active health probes must use `upstream_model` on the wire so they exercise the
/// same model actual traffic hits. Without this a lane with `upstream_model` reports healthy
/// against the config key while real requests fail against the upstream model ID.
#[tokio::test]
async fn test_probe_uses_upstream_model_override() {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: serde_json::json!({"ok": true}),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("config-key", Protocol::bedrock(), &server.base_url())
                .api_key("sk-test")
                .upstream_model("anthropic.claude-3-5-sonnet-20241022-v2:0")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();
    probe_lane(&app, 0, Duration::from_secs(5)).await;

    // Path must carry the upstream model ID (with SigV4-safe percent encoding for reserved `:`).
    let path = state
        .get_last_request_path()
        .expect("probe must reach upstream");
    assert!(
        path.contains("anthropic.claude-3-5-sonnet-20241022-v2%3A0"),
        "probe path must encode upstream_model, got {path}"
    );

    // Body is empty for Bedrock (model lives in URL), but for body-model protocols probe_body
    // also passes upstream_model — indistinguishability from organic traffic requires the same
    // wire name everywhere.
}

/// `spawn_probers` must capture a `Weak<App>`, never a strong `Arc`, so a
/// config reload's old prober generation exits (and the old snapshot frees) instead of leaking one
/// task-set per reload forever. Deterministic: the closure holds only a `Weak` regardless of task
/// scheduling, so dropping the last strong ref must make `upgrade()` fail immediately.
#[tokio::test]
async fn test_spawn_probers_retains_no_strong_app_ref() {
    let app = TestApp::new()
        .lane(
            LaneSpec::new("claude", Protocol::anthropic(), "http://127.0.0.1:1")
                .api_key("k")
                .health(health_active()),
        )
        .pool("p", &[(0, 1)])
        .build();
    let weak = Arc::downgrade(&app);
    spawn_probers(&app);
    drop(app);
    assert!(
            weak.upgrade().is_none(),
            "spawn_probers must retain only a Weak<App>; a strong ref would leak the snapshot across reloads"
        );
}

/// The active probe MUST sign the canonical URI from
/// the SAME path encoding it transmits on the wire. `probe_lane` derives both the SigV4
/// `canonical_uri` and the wire URL from `crate::proxy::sign_and_wire_path(&url_path)` (the
/// identical primitive the organic forward path uses), so for a Bedrock-style path whose modelId
/// carries a reserved `:` the signed/sent path is byte-identical and `%3A`-encoded — eliminating
/// the `SignatureDoesNotMatch` 403 that would otherwise park every Bedrock lane dead. This guards
/// the contract at the health layer (the helper itself is covered by the proxy engine reserved-char
/// test) so a future refactor of the probe can't reintroduce a raw-send divergence.
#[test]
fn test_probe_signs_and_sends_same_encoded_path_for_reserved_chars() {
    let url_path = "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse";
    let wire_path = crate::proxy::sign_and_wire_path(url_path);
    let canonical_uri = wire_path
        .split('?')
        .next()
        .unwrap_or(&wire_path)
        .to_string();

    assert!(
        wire_path.contains("%3A"),
        "Bedrock modelId ':' must be percent-encoded on the wire path: {wire_path}"
    );
    assert!(
        !wire_path.contains(":0/converse"),
        "the raw ':' must NOT survive on the wire path (would diverge from the signed URI): \
             {wire_path}"
    );
    assert_eq!(
        canonical_uri, wire_path,
        "with no query string the signed canonical URI must equal the transmitted wire path \
             (signed == sent), the exact invariant that prevents SignatureDoesNotMatch"
    );
}
/// `AppHandle::swap` re-spawns the probers on EVERY config mutation, and each fresh generation
/// used to start a brand-new interval whose first tick is one full period out. A swap cadence
/// faster than the probe interval — an onboarding wave auto-provisioning a group per new
/// subject, or a script applying settings in a loop — therefore replaced every generation before
/// it could probe ONCE, and health probing went silently dark while logging it was enabled.
///
/// The property that fixes it: a swap must NOT move the lane's probe deadline. Asserted on the
/// schedule directly rather than by waiting for a probe — a probe needs real socket I/O, which
/// under a paused clock completes at the runtime's discretion, so asserting on it measures the
/// test harness rather than the fix.
#[tokio::test]
async fn a_swap_does_not_push_the_probe_deadline_out() {
    let server = MockServer::new(Arc::new(MockServerState::new())).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("l", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(HealthCfg {
                    mode: HealthMode::Active,
                    interval_secs: Some(10),
                    timeout_secs: Some(5),
                }),
        )
        .pool("p", &[(0, 1)])
        .build();

    spawn_probers(&app);
    let first = app.probe_schedule.deadlines[0].load(std::sync::atomic::Ordering::Relaxed);
    assert_ne!(
        first,
        super::UNSCHEDULED,
        "the first spawn schedules the lane"
    );

    // Further generations, as a swap burst would produce. Real time must advance between them:
    // a deadline RECOMPUTED from "now" only differs from an inherited one once the clock has
    // moved, so without this the assertion cannot tell the two apart.
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(6));
        spawn_probers(&app);
        assert_eq!(
            app.probe_schedule.deadlines[0].load(std::sync::atomic::Ordering::Relaxed),
            first,
            "a re-spawn must inherit the existing deadline, never restart the interval"
        );
    }

    // And every one of those generations is accounted for, so the stale ones exit rather than
    // probing alongside the live one.
    assert_eq!(
        app.probe_schedule
            .generation
            .load(std::sync::atomic::Ordering::Relaxed),
        6,
        "each spawn takes its own generation"
    );
    server.shutdown().await;
}

/// A SHORTENED `interval_secs` takes effect on an inherited schedule within one new
/// interval, rather than waiting out the old (far longer) one. Targets the `fetch_min` clamp
/// specifically — deadlines are offsets from each schedule's OWN `origin`, so a numeric
/// comparison only discriminates when both spawns share one `Arc` (the state `App::clone`
/// produces), which this test establishes by construction rather than assuming.
#[tokio::test]
async fn a_shortened_interval_takes_effect_on_the_inherited_schedule() {
    let server = MockServer::new(Arc::new(MockServerState::new())).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new("l", Protocol::anthropic(), &server.base_url())
                .api_key("sk-test")
                .health(HealthCfg {
                    mode: HealthMode::Active,
                    interval_secs: Some(3600),
                    timeout_secs: Some(5),
                }),
        )
        .pool("p", &[(0, 1)])
        .build();

    spawn_probers(&app);
    let far = app.probe_schedule.deadlines[0].load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        far >= 3_600_000 && far != super::UNSCHEDULED,
        "first spawn schedules a ~3600s-out deadline, got {far}"
    );

    // Build the second generation as `App::clone` would (config apply / reload) — the `Arc`,
    // and therefore `origin`, is SHARED, which is the precondition the numeric assertion below
    // depends on.
    let mut a2 = (*app).clone();
    a2.lanes[0].health = Some(HealthCfg {
        mode: HealthMode::Active,
        interval_secs: Some(10),
        timeout_secs: Some(5),
    });
    let app2 = Arc::new(a2);
    spawn_probers(&app2);

    assert!(
        app.probe_schedule.deadlines[0].load(std::sync::atomic::Ordering::Relaxed) <= 11_000,
        "a shortened interval must clamp the inherited deadline"
    );
    assert_eq!(
        app.probe_schedule
            .generation
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    server.shutdown().await;
}

/// The tick-side owner-checked write. A late-arriving prober's post-tick write must
/// NOT revert a newer generation's spawn-time clamp — the deeper reason `advance_owned_deadline`
/// is `compare_exchange`, keyed on the value THIS prober last observed itself owning, rather than
/// an unconditional `store`. Plain synchronous unit test: no runtime, no clock, nothing for a
/// scheduler to race.
#[test]
fn a_late_tick_write_does_not_revert_a_newer_generations_clamp() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let slot = AtomicU64::new(3_600_000); // gen 1 owns this deadline
    let owned = 3_600_000;
    // A newer generation's spawn-time fetch_min lands a SHORTER deadline while gen 1 is mid-tick.
    slot.fetch_min(10_000, Ordering::Relaxed);
    // Gen 1's post-tick write now arrives, late, carrying the value it computed from its OWN
    // interval — must NOT clobber the newer generation's clamp.
    let got = advance_owned_deadline(&slot, owned, 3_610_000);
    assert_eq!(
        slot.load(Ordering::Relaxed),
        10_000,
        "the newer generation's clamp must survive"
    );
    assert_eq!(
        got, 10_000,
        "and the late prober must adopt it, not its own stale value"
    );
}
