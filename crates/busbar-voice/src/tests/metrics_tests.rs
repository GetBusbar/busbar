// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRONT-DOOR SESSION-OPEN COUNT on a real scrape — the `metrics × voice-server` cell. A governed
//! session-open lands on the neutral `busbar_plane_requests_total` family with `plane="voice"`, read
//! back off the SAME process-global prometheus recorder the core `/metrics` route renders.
//!
//! The recorder is process-global and other siblings in this binary drive the same emit, so this
//! asserts the series is PRESENT after a driven open, never an absence. Delete the emit at
//! `open_governed`'s `finish` and nothing in the voice tree emits this family — the assertion fails.

use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use std::sync::Arc;

#[tokio::test]
async fn a_voice_session_open_increments_the_plane_labelled_counter() {
    // The process-global prometheus recorder the core `/metrics` route renders — the same one the
    // voice front-door counter emits into.
    busbar_core::metrics::init();

    let app = busbar_core::test_support::TestApp::new().build();
    let host = busbar_core::plane_host::engine_host(&app);
    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    );

    // A governed session-open through the front door (no provider configured ⇒ the WS-accept leg
    // answers 501, but the front-door request is COUNTED all the same).
    let resp = open_governed(GovernedOpen {
        rt: &rt,
        host: Arc::clone(&host),
        provider: None,
        ingress: Ingress::Sideband,
        owner: "acct".to_string(),
        call_id: "call-metrics".to_string(),
        key: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    })
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_IMPLEMENTED);

    // The plane-labelled family carries a `plane="voice"` series on the real exposition.
    let exposition = busbar_core::metrics::render();
    let counted = exposition.lines().any(|l| {
        l.starts_with("busbar_plane_requests_total")
            && l.contains("plane=\"voice\"")
            && !l.starts_with('#')
    });
    assert!(
        counted,
        "a voice session-open must appear on busbar_plane_requests_total under plane=\"voice\". \
         Exposition:\n{exposition}"
    );
}
