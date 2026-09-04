// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOKS-GATE CELL — `hooks-gate × {voice-client, voice-server}` (one wiring, both directions).
//! `streams.hooks: [reject-all]` is attached, a session-open is driven through the governed choke
//! point, and it is REFUSED before any lease / mint / dial. The gate fires through the neutral
//! `host.gate_decide` seam (the Seam-B inversion — this plane names no core hook symbol): the host is
//! the substrate's in-memory fixture host carrying a scripted gate under the plane's own decl key and
//! `streams` container, so the plane's `gate_attached` / `gate_decide` legs run exactly as they do over
//! a configured deployment. (The same verdict over the real loaded hook plugin is the engine's own
//! hook battery to prove; this plane's tests do not link the engine.)
//!
//! The control makes the refusal falsifiable: the identical open with NOTHING attached proceeds past
//! the gate (the byte-identical-when-unconfigured guarantee, exercised).
//!
//! RED before the wiring: `open_governed` never consulted the gate, so `reject-all` served the open.

use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane_host::{EngineHost, GateOutcome};
use busbar_substrate::testkit::fixture_host::{FixtureHost, GateScript};
use std::sync::Arc;

/// The `streams:` container the voice plane files its operator hooks under.
const GATE_CONTAINER: &str = "streams";

/// A gate whose `raw_decide_reply` drives its verdict verbatim — the same reply shape the hermetic
/// test hook plugin reads off its settings: `{"reject": {"status", "message"}}` refuses, anything
/// else proceeds.
fn gate(settings: serde_json::Value) -> GateScript {
    let reply = settings["raw_decide_reply"].clone();
    Arc::new(move |_args_json: &[u8]| match reply.get("reject") {
        Some(reject) => GateOutcome::Reject {
            status: reject["status"].as_u64().unwrap_or(403) as u16,
            message: reject["message"].as_str().unwrap_or_default().to_string(),
            hook: "test-hook".to_string(),
        },
        None => GateOutcome::Proceed,
    })
}

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
}

/// A host with nothing attached: the open proceeds past the gate untouched.
fn ungated_host() -> Arc<dyn EngineHost> {
    FixtureHost::new().into_host()
}

/// Build a host whose `voice`/`streams` container carries the attached gate, filed under the plane's
/// own decl key exactly where production's resolved gate map puts it, so `gate_attached` answers true
/// and `gate_decide` runs the gate. `hook_name` is the operator's name for the hook (it only labels
/// the attachment here).
fn gated_host(_hook_name: &'static str, script: GateScript) -> Arc<dyn EngineHost> {
    FixtureHost::new()
        .attach_gate(crate::PLANE_DECL.key, GATE_CONTAINER, script)
        .into_host()
}

fn an_open<'a>(rt: &'a VoiceRuntime, host: Arc<dyn EngineHost>) -> GovernedOpen<'a> {
    GovernedOpen {
        rt,
        host,
        provider: None,
        // The `ek_` MINT one-shot pass — a LIVE `open_governed` production ingress (browser WebRTC),
        // so this cell proves the gate on a path production actually takes. The WS-accept front door
        // (sideband + telephony) runs the SAME `hook_gate` before the upgrade; that production path is
        // proven by `a_reject_all_operator_gate_refuses_a_ws_accept_before_the_upgrade` below.
        ingress: Ingress::Mint,
        owner: "acct".to_string(),
        call_id: "call-gate".to_string(),
        vkey: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    }
}

#[tokio::test]
async fn streams_hooks_reject_all_refuses_a_session_open() {
    let rt = runtime();

    // ── THE CONTROL: nothing attached ⇒ the open proceeds PAST the gate (byte-identical, no gate hop).
    let control = open_governed(an_open(&rt, ungated_host())).await;
    assert_eq!(
        control.status(),
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "with no gate attached the session-open proceeds past the gate to the governed open"
    );

    // ── THE TEST: `streams.hooks: [reject-all]`, same open, REFUSED before any lease/mint/dial. ──────
    let host = gated_host(
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

/// The plane's real dispatch slot, built the way `appbuild` does — a `BuildCtx` over a `public_url`.
fn a_slot() -> Arc<dyn std::any::Any + Send + Sync> {
    let unit = ();
    let ctx = busbar_substrate::plane::registry::BuildCtx {
        mcp_slot: None,
        agent_defs: &unit,
        public_url: Some("https://voice.example"),
        prior: None,
    };
    crate::mount::voice_build(&ctx).expect("voice_build yields a slot for a public_url")
}

/// Drive the REAL `ws_accept` over a loopback WS server with `host`, and return the client handshake
/// outcome: `Ok` on a 101 upgrade (the gate proceeded), `Err` on a pre-upgrade refusal (the gate
/// rejected — a 403, no socket bound). A WS upgrade cannot be forged off a live connection
/// (`ConnectionNotUpgradable`), so the accept fn must be driven through a real server + client.
async fn ws_accept_handshake(host: Arc<dyn EngineHost>) -> Result<(), ()> {
    #[derive(Clone)]
    struct S {
        host: Arc<dyn EngineHost>,
        slot: Arc<dyn std::any::Any + Send + Sync>,
    }
    async fn route(
        axum::extract::State(s): axum::extract::State<S>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        let arrival = busbar_substrate::ingress::duplex_ws::WsArrival {
            upgrade,
            gov: None,
            principal: None,
            caller_principal: Some("acct".to_string()),
            path: "/telephony/call-ws".to_string(),
            uri: axum::http::Uri::from_static("/telephony/call-ws"),
            headers: axum::http::HeaderMap::new(),
            path_params: vec![("call_id".to_string(), "call-ws".to_string())],
            host: s.host,
            slot: s.slot,
        };
        crate::mount::ws_accept(arrival, Ingress::Telephony).await
    }
    let app = axum::Router::new()
        .route("/telephony/call-ws", axum::routing::get(route))
        .with_state(S {
            host,
            slot: a_slot(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let policy = busbar_substrate::net_guard::GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..busbar_substrate::net_guard::GuardPolicy::default()
    };
    match busbar_substrate::egress::duplex_ws::dial(
        &format!("ws://{addr}/telephony/call-ws"),
        policy,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// THE WS-ACCEPT FRONT DOOR honors the operator gate — telephony is the sharp case (it has NO preceding
/// `ek_` mint pass, so before this wiring it reached the media leg screened by nothing but the
/// destination gauntlet). A `reject-all` gate REFUSES the session-open BEFORE the socket upgrades, so
/// the client handshake FAILS (a pre-upgrade 403, no socket, no session). The control (no gate)
/// upgrades (101), making the refusal falsifiable.
#[tokio::test]
async fn a_reject_all_operator_gate_refuses_a_ws_accept_before_the_upgrade() {
    assert!(
        ws_accept_handshake(ungated_host()).await.is_ok(),
        "with no gate attached the telephony WS-accept proceeds past the gate and upgrades (101)"
    );

    let host = gated_host(
        "reject-all",
        gate(serde_json::json!({
            "raw_decide_reply": {"reject": {"status": 403, "message": "no voice session today"}}
        })),
    );
    assert!(
        ws_accept_handshake(host).await.is_err(),
        "a reject-all operator gate REFUSES a telephony WS-accept BEFORE the socket upgrades — telephony \
         has no `ek_` mint pass, so the operator gate on this front door is its ONLY request screening"
    );
}
