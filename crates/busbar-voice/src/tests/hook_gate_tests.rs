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

// THE WS-ACCEPT FRONT DOOR and its operator gate — MOVED with the body they drove. `ws_accept` was
// this crate's inbound WS door; the three duplex rows are mounted by the ROOT off the plane's
// declared surface now, so the claim (a reject-all gate REFUSES the open before the socket upgrades,
// with a control that upgrades) is made where the gate is fired:
// `root::ws_arrival::tests::a_reject_all_operator_gate_refuses_the_open_before_the_upgrade`.
