use busbar_core::store::LaneRuntime as _;
use super::{forward_with_pool, KIND_INVALID_REQUEST};
use busbar_core::store::{now as store_now, BreakerState};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;

/// On the degraded FallbackPool path, `forward_once` must record breaker outcomes
/// against the ROUTING POOL cell — NOT the default `""` cell. The fallback caller selects the
/// member via the pool cell and CAS-wins a single-flight HalfOpen probe on it; recording on `""`
/// left the pool cell wedged HalfOpen + `probe_in_flight` forever, benching the lane.
///
/// Case A — a fallback 2xx must CLOSE the POOL cell. The fb pool cell starts expired-Open (→
/// HalfOpen on dispatch); a served 200 must drive it HalfOpen→Closed (and leave the default cell
/// untouched, proving the recording targeted the pool cell, not `""`).
#[tokio::test]
async fn test_forward_once_fallback_2xx_closes_pool_cell_not_default() {
    crate::testkit::install_test_seams();
    // Fallback-pool member's upstream serves a clean 200.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    // Lane 0 = primary pool member, marked dead so the primary pool is EXHAUSTED → FallbackPool.
    // Lane 1 = the fallback-pool member that actually serves.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("primary", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            busbar_core::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    // Drive the "fb" pool cell for lane 1 into expired-Open (cooldown_until in the PAST), so the
    // FallbackPool dispatch's `acquire_for_dispatch_in` transitions it Open→HalfOpen and CAS-wins
    // the recovery probe — the precise state a leaked probe wedges.
    app.store.force_open_in("fb", 1, t0.saturating_sub(10));
    assert!(
        matches!(
            app.store.breaker_state_in("fb", 1),
            BreakerState::Open { .. }
        ),
        "precondition: fb pool cell is expired-Open"
    );

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "FallbackPool must serve the 2xx"
    );
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The POOL cell must now be CLOSED (HalfOpen probe succeeded). Before the fix the success was
    // recorded on the "" cell, so the pool cell stayed HalfOpen forever.
    assert!(
        matches!(app.store.breaker_state_in("fb", 1), BreakerState::Closed),
        "fb POOL cell must close on a 2xx served via forward_once; got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // And the recording must NOT have touched the default "" cell (it was never tripped here).
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (recording targeted the pool cell, not \"\")"
    );
    server.shutdown().await;
}

/// Case B — a fallback transport error must OPEN the POOL cell. The fb pool cell
/// starts expired-Open (→ HalfOpen on dispatch); a pre-response transport error (unreachable
/// member) must reopen the POOL cell (HalfOpen→Open), re-arming its cooldown — not the default
/// `""` cell. Before the fix the reopen hit `""`, leaving the pool cell wedged HalfOpen forever.
#[tokio::test]
async fn test_forward_once_fallback_transport_error_opens_pool_cell() {
    crate::testkit::install_test_seams();
    let t0 = store_now();
    // Lane 0 = dead primary (exhausts the primary pool). Lane 1 = fallback member pointed at an
    // unreachable address so the upstream call fails pre-response (transport error).
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto_codec::PROTO_ANTHROPIC,
                "http://127.0.0.1:1",
            )
            .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1", // connect-refused → forward_once Err(transport) arm
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            busbar_core::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    app.store.force_open_in("fb", 1, t0.saturating_sub(10));

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    // The fb member is unreachable and the chain exhausts → a 5xx/503 to the client; the precise
    // status is not the assertion — the breaker state of the POOL cell is.
    let _ = response.status();
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The POOL cell must be OPEN (the failed half-open probe reopened it with a fresh cooldown).
    assert!(
        matches!(
            app.store.breaker_state_in("fb", 1),
            BreakerState::Open { .. }
        ),
        "fb POOL cell must reopen on a transport error via forward_once; got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // The default "" cell must be untouched (still Closed) — the recording targeted the pool cell.
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (transport-error recording targeted the pool cell)"
    );
}

/// A fallback-pool member that returns a genuine upstream-fault NON-2xx (5xx)
/// must leave its POOL cell USABLE, not wedged HalfOpen, AND must penalize the breaker. On the
/// degraded (`forward_once`) same-protocol non-2xx branch a 5xx classifies as
/// `Disposition::TransientUpstream`, so it records a transient failure BEFORE releasing the
/// single-flight HalfOpen probe the fallback dispatch CAS-won on the pool cell — bumping the
/// cooldown via exponential backoff, exactly like the MAIN forward path's non-2xx branch. The
/// probe is still released (HalfOpen→Open, flag cleared) so the cell is not wedged, but its
/// cooldown is now in the FUTURE (backoff), so an immediate re-probe is refused.
///
/// Discriminator: after the 5xx, the pool cell must be back to `Open` (NOT wedged `HalfOpen`) AND
/// its cooldown must be extended by backoff (no immediate re-probe), yet re-acquirable once the
/// backoff elapses. This is the "a 503 MUST trip the breaker" half of the PX1 pair.
#[tokio::test]
async fn test_forward_once_fallback_5xx_fault_trips_and_releases_probe() {
    crate::testkit::install_test_seams();
    // The fallback member's upstream serves a 503 (a genuine upstream fault the degraded path
    // classifies as TransientUpstream → records a breaker penalty, then relays verbatim).
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::ServerError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: json!({ "type": "error", "error": { "type": "overloaded_error", "message": "upstream overloaded" } }),
        });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    let app = TestApp::new()
        .lane(
            LaneSpec::new("primary", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            busbar_core::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    // Drive the "fb" pool cell into expired-Open so the FallbackPool dispatch CAS-wins the
    // single-flight HalfOpen recovery probe — the precise state the leak wedges.
    app.store.force_open_in("fb", 1, t0.saturating_sub(10));

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    // The verbatim non-2xx is relayed to the client (the status is not the point — the cell is).
    assert_eq!(
        response.status().as_u16(),
        503,
        "FallbackPool must relay the upstream 5xx verbatim"
    );
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The probe must have been RELEASED: the pool cell is Open again (not wedged HalfOpen).
    assert!(
        !matches!(app.store.breaker_state_in("fb", 1), BreakerState::HalfOpen),
        "fb POOL cell must NOT be wedged HalfOpen after a non-2xx (probe leak); got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // Cooldown-backoff fix: a non-2xx on a HalfOpen probe now RECORDS a transient failure (before
    // releasing the probe), which bumps the cooldown via exponential backoff — exactly like the
    // MAIN forward path's non-2xx branch. So the cell is Open but with a FUTURE cooldown: an
    // immediate re-acquire is refused (no base-interval re-probe with zero backoff anymore).
    // Before this fix the cooldown stayed expired and this returned true.
    assert!(
        !app.store.acquire_for_dispatch_in("fb", 1, store_now()),
        "fb POOL cell cooldown must be extended by backoff after a non-2xx probe failure \
             (no immediate re-probe)"
    );
    // Once the backoff cooldown elapses, the Open cell re-admits exactly one probe again — the
    // slot is not permanently benched, just backed off. A far-future instant clears the cooldown.
    assert!(
        app.store
            .acquire_for_dispatch_in("fb", 1, store_now().saturating_add(86_400)),
        "fb POOL cell must be re-acquirable once the backoff cooldown elapses"
    );
    // The default "" cell is never touched by the degraded path's recordings.
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (degraded path targets the pool cell only)"
    );
    server.shutdown().await;
}

/// PX1 (availability): a fallback-pool member that returns a deterministic CLIENT-error 4xx
/// (400/404/422 — the caller's own bad input, NOT an upstream fault) must NOT penalize the
/// breaker. The degraded (`forward_once`) same-protocol non-2xx branch previously called
/// `record_transient_in` UNCONDITIONALLY on any non-2xx, so a healthy upstream answering a 400
/// counted as a transient upstream FAILURE: it bumped the pool cell's cooldown (exponential
/// backoff) and, at threshold, tripped the circuit breaker against a HEALTHY upstream — a
/// self-inflicted availability outage. The fix classifies the disposition first (mirroring the
/// main forward path: `breaker::classify` over the normalized signal) and only feeds a genuine
/// `TransientUpstream` fault to the breaker; a `ClientFault` 4xx is relayed verbatim with NO
/// breaker penalty, the still-armed probe_guard alone releasing the won HalfOpen probe.
///
/// Discriminator: after the 400, the pool cell must be `Open` with its ORIGINAL (expired) cooldown
/// intact, so an IMMEDIATE re-acquire succeeds — proving no transient/backoff was recorded. Against
/// the old unconditional-`record_transient_in` code the 400 bumped the cooldown into the future and
/// this immediate re-acquire returned false (the regression signature).
#[tokio::test]
async fn test_forward_once_fallback_client_4xx_does_not_trip_breaker() {
    crate::testkit::install_test_seams();
    // The fallback member's upstream serves a 400 (Anthropic invalid_request_error) — a client
    // fault the breaker model treats as a healthy, deterministic response, NOT an upstream fault.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::ServerError {
        status: StatusCode::BAD_REQUEST,
        body: json!({ "type": "error", "error": { "type": KIND_INVALID_REQUEST, "message": "bad" } }),
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    let app = TestApp::new()
        .lane(
            LaneSpec::new("primary", crate::proto_codec::PROTO_ANTHROPIC, &server.base_url())
                .dead("administratively down for test"),
        )
        .lane(LaneSpec::new(
            "fbmember",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            busbar_core::config::OnExhausted::FallbackPool("fb".into()),
        )
        .build();

    // Drive the "fb" pool cell into expired-Open so the FallbackPool dispatch CAS-wins the
    // single-flight HalfOpen recovery probe — the precise state where an errant transient penalty
    // (backoff) would be observable as a refused immediate re-acquire.
    app.store.force_open_in("fb", 1, t0.saturating_sub(10));

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "FallbackPool must relay the upstream client-error 4xx verbatim"
    );
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The probe must have been RELEASED (not wedged HalfOpen) — same probe-leak invariant as the
    // fault path, here carried solely by the armed probe_guard since NOTHING recorded an outcome.
    assert!(
        !matches!(app.store.breaker_state_in("fb", 1), BreakerState::HalfOpen),
        "fb POOL cell must NOT be wedged HalfOpen after a client-error 4xx; got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    // THE PX1 DISCRIMINATOR: no transient was recorded, so the cooldown is NOT bumped by backoff —
    // the cell is immediately re-acquirable. Against the old unconditional `record_transient_in`
    // this returned false (the 400 bumped the cooldown into the future — a healthy upstream's 400
    // penalizing the breaker).
    assert!(
        app.store.acquire_for_dispatch_in("fb", 1, store_now()),
        "a client-error 4xx must NOT penalize the breaker: the fb POOL cell must remain \
         immediately re-acquirable (no transient/backoff recorded)"
    );
    // The default "" cell is never touched by the degraded path's recordings.
    assert!(
        matches!(app.store.breaker_state_in("", 1), BreakerState::Closed),
        "default cell must remain Closed (degraded path targets the pool cell only)"
    );
    server.shutdown().await;
}

/// An A<->B FallbackPool cycle must terminate via the visited-pool guard,
/// NOT recurse back into the originating pool. The guard in `handle_fallback_pool` only
/// checks/marks the FALLBACK pool name, so an A->B->A chain was not caught on the second hop:
/// when B fell back to A, the guard saw A as unvisited and RE-ENTERED A's members. The fix marks
/// the ORIGINATING pool at the top of `handle_exhaustion_for_pool`, so the hop back to A is
/// recognized as a cycle and terminates with 503.
///
/// Discriminator topology: pool A's ORIGINATING member (lane 0) is dead and pool B's member
/// (lane 1) is dead, so both pools exhaust and the chain is A->B->A. Pool A is ALSO reachable as
/// a FALLBACK target whose member (lane 2) is a LIVE upstream serving 200. With the fix the
/// second hop to A is caught by the guard and the request 503s WITHOUT ever dispatching lane 2.
/// Against the old code the un-guarded re-entry into A dispatches lane 2 and returns 200 — so a
/// 200 here is the regression signature.
#[tokio::test]
async fn test_fallback_pool_a_b_a_cycle_terminates_via_guard() {
    crate::testkit::install_test_seams();
    // Lane 2 (pool A's FALLBACK member) is a live upstream that would serve 200 if the cycle
    // erroneously re-entered pool A. The guard must prevent that dispatch entirely.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": [] }),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        // Lane 0: pool A's ORIGINATING member — dead, so pool A exhausts on entry.
        .lane(
            LaneSpec::new(
                "a-origin",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .dead("administratively down for test"),
        )
        // Lane 1: pool B's member — dead, so pool B exhausts and falls back to A.
        .lane(
            LaneSpec::new(
                "b-member",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .dead("administratively down for test"),
        )
        // Lane 2: pool A's FALLBACK member — LIVE. Only reached if the cycle re-enters A (bug).
        .lane(LaneSpec::new(
            "a-fallback",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("A", &[(0, 1)])
        // A reachable as a fallback target routes to the live lane 2; B routes to the dead lane 1.
        .fallback_pool("A", &[(2, 1)])
        .fallback_pool("B", &[(1, 1)])
        // A -> B -> A cycle.
        .on_exhausted("A", busbar_core::config::OnExhausted::FallbackPool("B".into()))
        .on_exhausted("B", busbar_core::config::OnExhausted::FallbackPool("A".into()))
        .build();

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        &app,
        // Originating candidate set for pool A = its dead member (lane 0) → A exhausts.
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "A",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    let status = response.status().as_u16();
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    // The A<->B cycle must terminate at the guard with 503 — NOT recurse back into A and serve
    // the live lane-2 200. A 200 here means the second-hop guard missed the cycle (the bug).
    assert_eq!(
        status, 503,
        "an A<->B fallback cycle must terminate via the visited-pool guard (503), not \
             re-enter pool A and serve its live member (200); got {status}"
    );
    server.shutdown().await;
}

/// The degraded (`forward_once`/walk.rs) untranslatable-2xx fallthrough must ALSO refund the
/// headers-time lane budget unit AND record a breaker transient against the ROUTING POOL cell —
/// the identical two omissions as the main-path arm, on the FallbackPool path. Lane 1 (the fb
/// member) speaks OpenAI while ingress is anthropic (cross-protocol), and returns a 2xx with an
/// empty `choices` array — the OpenAI reader rejects it, so `forward_once` falls to its
/// "not translatable" arm. Mirrors `test_forward_once_fallback_transport_error_opens_pool_cell`'s
/// topology (dead primary -> FallbackPool "fb"), but the fb member succeeds at the transport level
/// and fails only to translate.
#[tokio::test]
async fn test_forward_once_untranslatable_2xx_refunds_budget_and_trips_breaker() {
    crate::testkit::install_test_seams();
    use busbar_core::store::{BreakerCfg, BreakerState, TripConfig, TripMode};
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "chatcmpl-EMPTY",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "glm-4.5",
            "choices": [],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto_codec::PROTO_ANTHROPIC,
                "http://127.0.0.1:1",
            )
            .dead("administratively down for test"),
        )
        .lane(LaneSpec::new("fbmember", crate::proto_codec::PROTO_OPENAI, &server.base_url()).budget(1))
        .pool("primary", &[(0, 1)])
        .fallback_pool("fb", &[(1, 1)])
        .on_exhausted(
            "primary",
            busbar_core::config::OnExhausted::FallbackPool("fb".into()),
        )
        // The 2xx headers optimistically record a SUCCESS before the untranslatable check runs,
        // which closes the probe-won HalfOpen cell immediately — so the default ErrorRate config
        // (min_requests: 5) would never trip on the single compensating transient. Consecutive
        // mode with n=1 makes one transient an observable trip even from Closed, isolating the
        // discriminator (a transient IS recorded) from unrelated volume thresholds.
        .pool_breaker(
            "fb",
            &BreakerCfg {
                trip: TripConfig {
                    mode: TripMode::Consecutive,
                    consecutive_n: 1,
                    ..TripConfig::default()
                },
                ..BreakerCfg::default()
            },
        )
        .build();

    app.store.force_open_in("fb", 1, t0.saturating_sub(10));
    assert_eq!(app.store.lane_budget_remaining(1), Some(1));

    let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
    let response = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "primary",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        500,
        "an untranslatable cross-protocol 2xx on the degraded path must surface an ingress-native 500"
    );
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

    assert_eq!(
        app.store.lane_budget_remaining(1),
        Some(1),
        "the degraded untranslatable-2xx fallthrough must refund the headers-time spend_budget unit"
    );
    assert!(
        matches!(
            app.store.breaker_state_in("fb", 1),
            BreakerState::Open { .. }
        ),
        "an untranslatable 2xx via forward_once must reopen the fb POOL cell (breaker parity \
             with the transport-error arm); got {:?}",
        app.store.breaker_state_in("fb", 1)
    );
    server.shutdown().await;
}

/// The upstream/breaker METRIC pool label must resolve to the ROUTED
/// MODEL name for the default (`""`) breaker cell — the cell shared by every direct/ad-hoc
/// (single-model) route via `forward()` — so those series correlate with `REQUESTS_TOTAL`
/// (which labels model-routed traffic by model, never `""`). For a NAMED pool the label is the
/// pool name verbatim. The breaker-CELL key is NOT repointed by this helper (that stays `""`);
/// only the metric LABEL is decoupled, which is exactly what `metric_pool_label` computes.
#[test]
fn test_metric_pool_label_resolves_model_for_default_cell() {
    crate::testkit::install_test_seams();
    use super::metric_pool_label;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude-sonnet",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1",
        ))
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .build();

    // Default ("") cell → the routed lane's MODEL name (so upstream metrics align with
    // REQUESTS_TOTAL's model label instead of an empty-string series).
    assert_eq!(
        metric_pool_label(&app, "", 0),
        "claude-sonnet",
        "default-cell traffic must be labeled by the routed model, not the empty cell key"
    );
    assert_eq!(
        metric_pool_label(&app, "", 1),
        "gpt-4o",
        "the label tracks the specific routed lane's model"
    );
    // A NAMED pool keeps its pool name verbatim (bounded, operator-controlled label).
    assert_eq!(
        metric_pool_label(&app, "prod-pool", 0),
        "prod-pool",
        "named-pool traffic stays labeled by its pool name"
    );
}
