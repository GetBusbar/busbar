// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRONT-DOOR SESSION-OPEN REPORT — the `metrics × voice-server` cell (item 566). A governed
//! session-open is reported through the host's `request_finished` seam with the plane's own key, its
//! ingress dialect, the front-door pool and its outcome — AND the elapsed duration. On the engine's host
//! that call lands the `busbar_plane_requests_total{plane="voice"}` count (the same family and labels
//! this door used to emit by hand) and the `busbar_plane_request_duration_seconds{plane="voice"}` sample
//! the hand emit never recorded; the fixture host records the call itself. Revert `finish` to the
//! hand-emitted counter and the host is told nothing — the assertion fails. (The name is the one
//! `qa/capability-equality.json` cites for this cell; the report carries the count and the duration.)

use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::{EchoToolExecutor, VoiceRuntime};
use crate::testkit::fixture_host::FixtureHost;
use busbar_kernel::plane::handle_engine::DurableHandleEngine;
use std::sync::Arc;

#[tokio::test]
async fn a_voice_session_open_increments_the_plane_labelled_counter() {
    let host = Arc::new(FixtureHost::new());
    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(EchoToolExecutor),
    );

    // A governed session-open through the front door (no provider configured ⇒ the WS-accept leg
    // answers 501, but the front-door request is REPORTED all the same).
    let resp = open_governed(GovernedOpen {
        rt: &rt,
        host: Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        provider: None,
        ingress: Ingress::Sideband,
        owner: "acct".to_string(),
        call_id: "call-metrics".to_string(),
        vkey: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    })
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_IMPLEMENTED);

    let reported = host.finished_requests();
    assert_eq!(reported.len(), 1, "one front-door request, reported once");
    let r = &reported[0];
    assert_eq!(
        (
            r.plane.as_str(),
            r.ingress_protocol.as_str(),
            r.pool.as_str()
        ),
        (crate::PLANE_KEY, crate::OPENAI_REALTIME, "voice-server"),
        "the labels the hand-emitted counter carried"
    );
    assert_eq!(
        r.outcome,
        busbar_kernel::telemetry::outcome_of(501),
        "the outcome of the answer the caller got"
    );
    assert!(
        r.seconds.is_finite() && r.seconds >= 0.0,
        "a duration sample rides the same report: {}",
        r.seconds
    );
}
