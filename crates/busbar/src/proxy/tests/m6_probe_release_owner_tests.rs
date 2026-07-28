//! M6: the four post-`.await` single-flight-probe release sites in `engine/mod.rs`
//! (the ClientFault disposition and the three passthrough/context-length abandon arms) must use the
//! OWNER-CHECKED `release_probe_owned_in`, not the unowned `release_probe_in` — a stalled request
//! that finally reaches its release AFTER a successor has already won a NEWER probe on the same
//! cell must not revert that newer probe back to Open.
//!
//! This is the real, call-site-level RED proof: it drives ONE genuine request all the way through
//! `forward_with_pool` (dispatch → 400 ClientFault → the release site), gated deterministically
//! mid-body-read via `MockResponse::Gated` (a `Notify`, not a `sleep` — a real-clock delay is a race
//! by construction). While that request is parked, a SECOND probe is won on the same cell via
//! direct store calls — the same idiom `probe_guard_tests.rs`'s
//! `stalled_guard_does_not_release_a_newer_probe` already uses to prove the primitive, applied here
//! at the engine call-site level instead of directly against `ProbeGuard`.

use super::forward_with_pool;
use crate::store::BreakerState;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::json;
use std::sync::Arc;

/// RED at HEAD (before the M6 fix): the stalled request's unowned `release_probe_in` reverts the
/// SECOND request's freshly-won probe back to Open, losing the single-flight invariant.
/// GREEN after: the owned release, keyed on the epoch captured before dispatch, is a no-op against
/// the superseded probe and the second probe's HalfOpen cell survives untouched.
#[tokio::test]
async fn a_stale_resume_does_not_revert_a_newer_probe() {
    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    // A plain 400 with no recognizable error code/type classifies via the HTTP-status default
    // (400..500, not 401/403/408/429) as StatusClass::ClientError -> Disposition::ClientFault -
    // the disposition that reaches `app.store.release_probe_owned_in` WITHOUT ever recording a
    // breaker outcome first (see engine/mod.rs's own comment at that site).
    state.push(MockResponse::Gated {
        status: reqwest::StatusCode::BAD_REQUEST,
        body: json!({"error": {"message": "malformed request"}}),
        started: started.clone(),
        release: release.clone(),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        ))
        .pool("pa", &[(0, 1)])
        .build();

    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();

    let app_a = app.clone();
    let cands = vec![crate::state::WeightedLane {
        reasoning: None,
        idx: 0,
        weight: 1,
        attempt_timeout_ms: None,
    }];
    let request_a = tokio::spawn(async move {
        forward_with_pool(
            app_a,
            cands,
            body.into(),
            None,
            "pa",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        )
        .await
    });

    // Wait until request A's body read has actually started (i.e. it is parked inside
    // `read_capped_body(r).await`) before touching the store — this is the deterministic
    // replacement for a wall-clock sleep.
    started.notified().await;

    // Request A's dispatch already ran `acquire_for_dispatch_in` inside `pick_among`, synchronously,
    // before it ever sent the HTTP request — so by the time it is parked reading this gated body,
    // the cell already reflects whatever that dispatch did (Closed cells are untouched by
    // `probe_epoch`; a HalfOpen recovery-probe win bumps it). Read whatever epoch is live now as the
    // baseline the simulated second win must move past.
    let epoch_before = app.store.probe_epoch_in("pa", 0);

    // Simulate the SECOND probe: A's (implicit) probe is consumed by a recorded outcome, the lane
    // trips back to expired-Open, and a fresh probe is won — bumping the epoch past whatever A
    // captured before it dispatched. Copied from `probe_guard_tests.rs`'s
    // `stalled_guard_does_not_release_a_newer_probe`.
    app.store.record_success_in("pa", 0);
    app.store.force_open_in("pa", 0, 0);
    assert!(
        app.store
            .acquire_for_dispatch_in("pa", 0, crate::store::now().saturating_add(86_400)),
        "a NEW probe must be won on the re-opened cell"
    );
    let epoch_after = app.store.probe_epoch_in("pa", 0);
    assert_ne!(
        epoch_before, epoch_after,
        "sanity: the second win must bump the epoch"
    );
    assert!(
        matches!(app.store.breaker_state_in("pa", 0), BreakerState::HalfOpen),
        "precondition: the fresh probe leaves the cell HalfOpen"
    );

    // Let request A resume: its ClientFault branch releases the probe it captured BEFORE dispatch —
    // an epoch that is now stale.
    release.notify_one();
    let resp = request_a.await.unwrap();
    assert_eq!(resp.status().as_u16(), 400, "the gated 400 relays through");

    assert!(
        matches!(app.store.breaker_state_in("pa", 0), BreakerState::HalfOpen),
        "a stale request's release must NOT revert the current (second) probe owner's HalfOpen \
         cell — the owner-checked release must be a no-op against a superseded epoch"
    );

    server.shutdown().await;
}
