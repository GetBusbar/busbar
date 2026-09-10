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

/// THE SUBJECT THIS PLANE NAMES IS THE SESSION MODE — not a method name it never had.
///
/// Until the neutral seam could be told what a gate is deciding about, this plane spelled the
/// literal `"session.open"` into the tool-shaped argument the seam took: a callable name, on a
/// protocol with no callables, carrying one bit of information a gate already had from the
/// container it was attached to. The mode is the fact an operator screening this door can act on —
/// a `mint` is a browser sideband, a `telephony` is a media leg with no preceding `ek_` pass — and
/// it is the plane's own, resolved from which route the operator mounted before any frame arrives.
///
/// Falsifiable two ways: the two opens differ only in their ingress and the subjects differ with
/// them, and the string that used to be sent appears nowhere.
#[tokio::test]
async fn the_gate_is_told_which_session_mode_is_opening() {
    let rt = runtime();
    // A gate that PROCEEDS: this cell is about what the gate is TOLD, not about the verdict.
    let recorder = Arc::new(FixtureHost::new().attach_gate(
        crate::PLANE_DECL.key,
        GATE_CONTAINER,
        Arc::new(|_args_json: &[u8]| GateOutcome::Proceed) as GateScript,
    ));

    let mut open = an_open(&rt, Arc::clone(&recorder) as Arc<dyn EngineHost>);
    open.ingress = Ingress::Mint;
    let _ = open_governed(open).await;
    let mut open = an_open(&rt, Arc::clone(&recorder) as Arc<dyn EngineHost>);
    open.ingress = Ingress::Telephony;
    let _ = open_governed(open).await;

    let seen: Vec<Option<String>> = recorder.subjects_seen();
    assert_eq!(
        seen,
        vec![
            Some("mint".to_string()),
            Some("telephony".to_string())
        ],
        "each open must name the mode IT opened in — a subject that did not change with the ingress \
         would be a subject that says nothing about the request"
    );
    assert!(
        !seen.iter().flatten().any(|s| s == "session.open"),
        "the stand-in this face replaced was the literal `session.open`; a plane with no methods \
         must not be spelling one to be governed"
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
        crate::mount::ws_accept(
            arrival,
            Ingress::Telephony,
            crate::ir::codec::OpenAiRealtimeCodec,
        )
        .await
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
