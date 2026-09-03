// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOKS-GATE CELL — `hooks-gate × {voice-client, voice-server}` (one wiring, both directions).
//! `streams.hooks: [reject-all]` is attached, a session-open is driven through the governed choke
//! point, and it is REFUSED before any lease / mint / dial. The gate is the SAME real `dlopen`ed
//! cdylib the MCP/A2A hook batteries drive, and it fires through the neutral `host.gate_decide` seam
//! (the Seam-B inversion — this plane names no core hook symbol).
//!
//! The control makes the refusal falsifiable: the identical open with NOTHING attached proceeds past
//! the gate (the byte-identical-when-unconfigured guarantee, exercised).
//!
//! RED before the wiring: `open_governed` never consulted the gate, so `reject-all` served the open.

use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_core::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use busbar_core::test_support::TestApp;
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane_host::EngineHost;
use std::sync::Arc;

/// A `kind: gate` on the hermetic test cdylib whose `raw_decide_reply` drives its verdict verbatim.
fn gate(settings: serde_json::Value) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        // Not the 1ms default: these assert the VERDICT, not the deadline (which under parallel-suite
        // load fires on scheduling delay alone and `on_error: weighted` maps to PROCEED).
        timeout_ms: 10_000,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::Ro,
        user: UserAccess::Ro,
        priority: 0,
        settings: settings.as_object().cloned().unwrap_or_default(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// The env that loads the test cdylib under the alias `test-hook`. ABSENCE IS A HARD FAILURE (never a
/// skip): with no gate to load every assertion below is vacuous. The panic names the fix.
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
         release's hooks-gate acceptance test and it CANNOT be skipped. Build it: \
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

/// Build a host whose `voice`/`streams` container carries the attached gate, resolved the way
/// production resolves it. The voice plane is registered in the test registry so the neutral
/// [`busbar_substrate::plane_host::ContainerGateSink`] files the gate map under the plane's own decl
/// key (`build()` itself resolves only the `tools:`/`agents:` sections). The `App` is returned so it
/// outlives the borrowed host.
fn gated_host(
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

fn an_open<'a>(rt: &'a VoiceRuntime, host: Arc<dyn EngineHost>) -> GovernedOpen<'a> {
    GovernedOpen {
        rt,
        host,
        provider: None,
        ingress: Ingress::Sideband,
        owner: "acct".to_string(),
        call_id: "call-gate".to_string(),
        key: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    }
}

#[tokio::test]
async fn streams_hooks_reject_all_refuses_a_session_open() {
    let rt = runtime();

    // ── THE CONTROL: nothing attached ⇒ the open proceeds PAST the gate (byte-identical, no gate hop).
    let ungated = busbar_core::plane_host::engine_host(&TestApp::new().build());
    let control = open_governed(an_open(&rt, ungated)).await;
    assert_eq!(
        control.status(),
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "with no gate attached the session-open proceeds past the gate to the governed open"
    );

    // ── THE TEST: `streams.hooks: [reject-all]`, same open, REFUSED before any lease/mint/dial. ──────
    let (_app, host) = gated_host(
        "reject-all",
        gate(serde_json::json!({
            "raw_decide_reply": {"reject": {"status": 403, "message": "no voice session today"}}
        })),
    );

    let refused = open_governed(an_open(&rt, host)).await;
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::FORBIDDEN,
        "`streams.hooks: [reject-all]` must REFUSE the session-open before any lease/mint/dial"
    );
    let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .expect("the refusal body reads");
    assert_eq!(
        String::from_utf8_lossy(&body),
        "no voice session today",
        "the hook's OWN message reaches the caller, so an operator can tell WHICH control refused"
    );
}
