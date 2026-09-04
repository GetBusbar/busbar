// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOKS-TAP CELL — `hooks-tap × {voice-client, voice-server}` (one wiring, both directions).
//! `streams.hooks: [rewrite]` with a `prompt: rw` gate is attached, a session-open is driven through
//! the governed choke point, and the params THE PROVIDER RECEIVES are the ones the hook rewrote them
//! to — asserted on the ACTUAL mint request the loopback provider saw (a rewrite is only real if the
//! thing downstream saw the rewritten value). The tap fires through the neutral `host.transform_over`
//! seam, after the gate and before the credential is leased. The host is the substrate's in-memory
//! fixture host carrying a scripted rewrite under the plane's own decl key and `streams` container, so
//! the plane's `tap_attached` / `transform_over` legs run exactly as they do over a configured
//! deployment. (The same rewrite over the real loaded hook plugin is the engine's own hook battery to
//! prove; this plane's tests do not link the engine.)
//!
//! ## The control is the byte-identical guarantee, exercised
//!
//! The identical open with the rewrite hook REMOVED must reach the provider carrying the plane's
//! ORIGINAL locked params, byte for byte — the no-op-absent-hooks guarantee.
//!
//! RED before the wiring: `open_governed` never ran the transform, so the provider always saw the
//! plane's own params and no rewrite could change a byte.

use crate::ir::config::SessionConfig;
use crate::mount::{open_governed, GovernedOpen, Ingress, ProviderEndpoint};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane_host::{EngineHost, TransformVerdict};
use busbar_substrate::testkit::fixture_host::{FixtureHost, RewriteScript};
use busbar_substrate::testkit::loopback_http::{MockResponse, MockServer, MockServerState};
use std::sync::Arc;

/// The `streams:` container the voice plane files its operator hooks under.
const GATE_CONTAINER: &str = "streams";

/// A `prompt: rw` REWRITE whose `raw_transform_reply` drives its rewrite — the same reply shape the
/// hermetic test hook plugin reads off its settings: a `rewrite.messages[0].content` is the payload the
/// hook committed in place of the plane's own; anything else abstains (the payload passes unchanged).
fn rewrite(raw_transform_reply: serde_json::Value) -> RewriteScript {
    let rewritten = raw_transform_reply["rewrite"]["messages"][0]["content"].clone();
    Arc::new(move |args_json: &[u8]| {
        if rewritten.is_null() {
            return TransformVerdict::Proceed {
                applied: false,
                args_json: args_json.to_vec(),
            };
        }
        TransformVerdict::Proceed {
            applied: true,
            args_json: serde_json::to_vec(&rewritten).expect("the rewrite serializes"),
        }
    })
}

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
}

/// A host with nothing attached: the tap is a no-op.
fn untapped_host() -> Arc<dyn EngineHost> {
    FixtureHost::new().into_host()
}

/// Build a host whose `voice`/`streams` container carries the attached rewrite chain, filed under the
/// plane's own decl key exactly where production's resolved rewrite map puts it, so `tap_attached`
/// answers true and `transform_over` runs the rewrite. `hook_name` is the operator's name for the
/// hook (it only labels the attachment here).
fn tapped_host(_hook_name: &'static str, script: RewriteScript) -> Arc<dyn EngineHost> {
    FixtureHost::new()
        .attach_rewrite(crate::PLANE_DECL.key, GATE_CONTAINER, script)
        .into_host()
}

/// A loopback provider `client_secrets` endpoint that returns an `ek_` and RECORDS the mint request —
/// the request body carries the `session:` params the mint (and therefore the provider dial) saw.
async fn mint_provider() -> (MockServer, Arc<MockServerState>) {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({ "value": "ek_minted", "expires_at": 1_700_000_000u64 }),
    });
    let server = MockServer::new(Arc::clone(&state)).await;
    (server, state)
}

/// Drive one `Mint` open through the governed choke point against the loopback provider, and return
/// the `session:` object the mint request carried.
async fn minted_session(
    host: Arc<dyn EngineHost>,
    base_url: &str,
    state: &MockServerState,
) -> serde_json::Value {
    let rt = runtime();
    let provider = ProviderEndpoint {
        base_url: base_url.to_string(),
        api_key: "sk-real-key".to_string(),
    };
    let resp = open_governed(GovernedOpen {
        rt: &rt,
        host,
        provider: Some(&provider),
        ingress: Ingress::Mint,
        owner: "acct".to_string(),
        call_id: "call-tap".to_string(),
        vkey: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    })
    .await;
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "the mint pass serves"
    );
    let raw = state
        .get_last_request_body()
        .expect("the mint sent a request body");
    let sent: serde_json::Value = serde_json::from_slice(&raw).expect("the mint body is json");
    sent["session"].clone()
}

#[tokio::test]
async fn no_hook_leaves_the_params_byte_identical() {
    let (server, state) = mint_provider().await;
    // Nothing attached ⇒ the tap is a no-op and the provider sees the plane's ORIGINAL locked params.
    let session = minted_session(untapped_host(), &server.base_url(), &state).await;
    assert_eq!(
        session,
        serde_json::to_value(runtime().session_defaults).unwrap(),
        "with no rewrite hook the provider must receive the plane's locked params BYTE FOR BYTE — the \
         no-op-absent-hooks guarantee"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_rewrite_hook_edits_the_session_open_params_before_the_provider_dial() {
    let (server, state) = mint_provider().await;

    // The rewrite REPLACES the session-open params with a hook-authored posture — a distinct
    // instructions string the plane default never carries, so its presence at the provider is proof
    // the rewrite reached the wire.
    let rewritten: SessionConfig = SessionConfig {
        instructions: Some("rewritten-by-hook".to_string()),
        voice: Some("marin".to_string()),
        ..SessionConfig::default()
    };
    let host = tapped_host(
        "rewrite",
        rewrite(serde_json::json!({
            "rewrite": {
                "messages": [
                    { "role": "user", "content": serde_json::to_value(&rewritten).unwrap() }
                ]
            }
        })),
    );

    let session = minted_session(host, &server.base_url(), &state).await;
    assert_eq!(
        session["instructions"], "rewritten-by-hook",
        "the provider mint must carry the params THE HOOK REWROTE THEM TO. The plane's own \
         instructions here would be the whole finding: the rewrite fired in memory but never reached \
         the wire. Session the provider saw: {session}"
    );
    server.shutdown().await;
}
