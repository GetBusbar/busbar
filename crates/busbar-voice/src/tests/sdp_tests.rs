// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SDP BROKER + `rtc_<call_id>` CORRELATION, end-to-end over a loopback. The browser's SDP offer
//! is brokered to the provider's `POST /v1/realtime/calls`; the provider's `Location:
//! …/rtc_<call_id>` is PRESERVED on the answer AND stamped onto the durable session row — so
//! busbar's governance (this session) and the brokered media call name the SAME session. A mismatch
//! silently attaches the sideband to the wrong call, so the correlation is asserted broker → row.
//!
//! RED before the wiring: the SDP route answered `501` (no broker), so there was no `Location` to
//! preserve and no `rtc_` on the row.

use crate::mount::{open_governed, GovernedOpen, Ingress, ProviderEndpoint};
use crate::runtime::scope::SessionHandle;
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use std::sync::{Arc, Mutex};

const RTC_CALL_ID: &str = "rtc_correlated_call_9f8e7d";
const SDP_ANSWER: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
const PROVIDER_KEY: &str = "sk-real-key-held-server-side";
/// The caller's inbound governance bearer — a sentinel that MUST NEVER reach the provider hop.
const INBOUND_GOVERNANCE_BEARER: &str = "Bearer inbound-governance-token-MUST-NOT-LEAK";

/// A loopback "provider" for `POST /v1/realtime/calls`: it RECORDS the `Authorization` it was dialed
/// with (into `seen`) and answers `201` carrying the SDP answer and a `Location:
/// /v1/realtime/calls/rtc_<call_id>` header — the exact broker contract.
async fn spawn_calls_broker(seen: Arc<Mutex<Option<String>>>) -> std::net::SocketAddr {
    async fn calls(
        axum::extract::State(seen): axum::extract::State<Arc<Mutex<Option<String>>>>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        *seen.lock().unwrap() = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        axum::response::Response::builder()
            .status(axum::http::StatusCode::CREATED)
            .header(http::header::CONTENT_TYPE, "application/sdp")
            .header(
                http::header::LOCATION,
                format!("/v1/realtime/calls/{RTC_CALL_ID}"),
            )
            .body(axum::body::Body::from(SDP_ANSWER))
            .unwrap()
    }
    let app = axum::Router::new()
        .route("/v1/realtime/calls", axum::routing::post(calls))
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn the_sdp_broker_correlates_the_rtc_call_id_from_the_location_header_onto_the_row() {
    let seen_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let addr = spawn_calls_broker(Arc::clone(&seen_auth)).await;
    let app = busbar_core::test_support::TestApp::new().build();
    let host = busbar_core::plane_host::engine_host(&app);

    let engine = Arc::new(DurableHandleEngine::new());
    let rt = VoiceRuntime::new(
        Arc::clone(&engine),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    );
    let provider = ProviderEndpoint {
        base_url: format!("http://{addr}"),
        api_key: PROVIDER_KEY.to_string(),
    };

    // The caller reached the `RouteAuth::Key` SDP route with a GOVERNANCE bearer (a sentinel) + an SDP
    // offer. The broker hop must authenticate to the provider with busbar's OWN provider key and NEVER
    // forward this inbound token upstream.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static(INBOUND_GOVERNANCE_BEARER),
    );

    let resp = open_governed(GovernedOpen {
        rt: &rt,
        host: Arc::clone(&host),
        provider: Some(&provider),
        ingress: Ingress::Sdp,
        owner: "acct-sdp".to_string(),
        call_id: "call-sdp".to_string(),
        key: None,
        body: axum::body::Bytes::from_static(b"v=0\r\no=browser 0 0 IN IP4 0.0.0.0\r\n"),
        headers,
        now: 42,
    })
    .await;

    // The answer preserved the provider's `Location` header verbatim.
    assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
    assert_eq!(
        resp.headers()
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/v1/realtime/calls/{RTC_CALL_ID}").as_str()),
        "the SDP broker preserves the Location header verbatim"
    );

    // CREDENTIAL ISOLATION (regression guard for the forward-the-inbound-bearer leak): the provider hop
    // saw busbar's OWN provider key, and the caller's inbound governance bearer NEVER left the boundary.
    let dialed_with = seen_auth.lock().unwrap().clone();
    assert_eq!(
        dialed_with.as_deref(),
        Some(format!("Bearer {PROVIDER_KEY}").as_str()),
        "the SDP broker authenticates upstream with busbar's OWN provider credential"
    );
    assert_ne!(
        dialed_with.as_deref(),
        Some(INBOUND_GOVERNANCE_BEARER),
        "the caller's inbound governance bearer must NEVER be forwarded to the provider"
    );

    // BROKER → ROW: the `rtc_<call_id>` derived from that Location is stamped onto the durable session
    // row, read back by the session's own (owner, id).
    let row = SessionHandle::bind(engine, "acct-sdp", "call-sdp")
        .get()
        .expect("the durable session row exists after the governed open");
    assert_eq!(
        row.rtc_call_id.as_deref(),
        Some(RTC_CALL_ID),
        "the rtc_<call_id> from the broker's Location header correlates onto the session row — the \
         single key tying governance here to the media that flows there"
    );
}
