// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOKS-TAP CELL — `hooks-tap × {voice-client, voice-server}` (one wiring, both directions).
//! `streams.hooks: [rewrite]` with a `prompt: rw` gate is attached, a session-open is driven through
//! the governed choke point, and the params THE PROVIDER RECEIVES are the ones the hook rewrote them
//! to — asserted on the ACTUAL mint request the loopback provider saw (a rewrite is only real if the
//! thing downstream saw the rewritten value). The tap fires through the neutral `host.transform_over`
//! seam, after the gate and before the credential is leased.
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
use busbar_core::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use busbar_core::test_support::{MockResponse, MockServer, MockServerState, TestApp};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane_host::EngineHost;
use std::sync::Arc;

/// A `prompt: rw` REWRITE gate on the hermetic test cdylib; `raw_transform_reply` drives its rewrite.
fn rewrite(raw_transform_reply: serde_json::Value) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 10_000,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::Rw,
        user: UserAccess::Ro,
        priority: 0,
        settings: serde_json::json!({ "raw_transform_reply": raw_transform_reply })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

fn hook_env() -> busbar_core::hooks::HookEnv {
    busbar_core::test_support::test_hook_env(
        &["test-hook"],
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
    .expect(
        "the busbar-hook-test-plugin cdylib is not built. This battery is the voice half of the \
         release's hooks-tap acceptance test and it CANNOT be skipped. Build it: \
         `cargo build -p busbar-hook-test-plugin`.",
    )
}

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
}

/// Build a host whose `voice`/`streams` container carries the attached rewrite chain, resolved the way
/// production resolves it (`build()` itself resolves only `tools:`/`agents:`; the voice plane is
/// registered so the neutral [`busbar_substrate::plane_host::ContainerGateSink`] files the rewrite map
/// under the plane's own decl key). The `App` is returned so it outlives the borrowed host.
fn tapped_host(
    hook_name: &'static str,
    cfg: HookCfg,
) -> (Arc<busbar_core::state::App>, Arc<dyn EngineHost>) {
    use busbar_substrate::plane_host::ContainerGateSink;
    busbar_core::plane::registry::register_test_plane(&crate::PLANE_DECL);
    let mut app = TestApp::new()
        .hook(hook_name, cfg)
        .hook_env(hook_env())
        .build();
    {
        let app_mut = Arc::get_mut(&mut app).expect("a freshly built test app is sole-owned");
        let hooks = vec![hook_name.to_string()];
        let containers: [(&str, &[String]); 1] = [("streams", hooks.as_slice())];
        app_mut.reresolve_container_gates("voice", &containers, &[]);
    }
    let host = busbar_core::plane_host::engine_host(&app);
    (app, host)
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
    let ungated = busbar_core::plane_host::engine_host(&TestApp::new().build());
    let session = minted_session(ungated, &server.base_url(), &state).await;
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
    let (_app, host) = tapped_host(
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
