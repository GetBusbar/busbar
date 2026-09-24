// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVED ROUTE ASKS THE KERNEL'S BUDGET VIEW, AND A SERVED SESSION LEDGERS THE PLANE'S COUNTS.
//!
//! OWNER RULING Q21b replaced the per-key D2 lease with the kernel's session account. Two facts,
//! proven through the mounted open (`open_governed`) rather than the runtime alone:
//!
//!  1. THE GATE IS THE KERNEL'S. A presenting key whose chain the kernel's budget view reads dry is
//!     refused `402` before any session opens; the same key with room is served.
//!  2. THE COUNTS ARE THE PLANE'S. A turn of the session the route opened lands on the presenting key's
//!     ledger as the streaming plane's classes, under the voice lane.

use crate::ir::codec::WireEvent;
use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::{EchoToolExecutor, VoiceRuntime};
use crate::testkit::fixture_host::FixtureHost;
use busbar_kernel::plane::handle_engine::DurableHandleEngine;
use std::sync::Arc;

fn key() -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: "vk-voice-session".to_string(),
        name: "voice-session".to_string(),
        ..Default::default()
    }
}

async fn open(host: &Arc<FixtureHost>, rt: &VoiceRuntime, call_id: &str) -> axum::http::StatusCode {
    open_governed(GovernedOpen {
        rt,
        host: Arc::clone(host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        provider: None,
        ingress: Ingress::Mint,
        owner: "acct-meter".to_string(),
        call_id: call_id.to_string(),
        vkey: Some(key()),
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 5,
    })
    .await
    .status()
}

#[tokio::test]
async fn a_served_open_is_refused_when_the_kernel_reads_the_chain_dry() {
    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(EchoToolExecutor),
    );
    let dry = Arc::new(FixtureHost::new().governed().with_count_cap(0));
    assert_eq!(
        open(&dry, &rt, "call-dry").await,
        axum::http::StatusCode::PAYMENT_REQUIRED,
        "a dry chain is refused before any session opens"
    );
    let room = Arc::new(FixtureHost::new().governed().with_count_cap(1_000));
    assert_eq!(
        open(&room, &rt, "call-room").await,
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "the same key with room is served (nothing to dial here)"
    );
}

#[tokio::test]
async fn a_served_sessions_turn_lands_the_planes_counts_on_the_presenting_key() {
    let host = Arc::new(FixtureHost::new().governed());
    let rt = crate::runtime::build_runtime_hosted(
        &VoiceRuntime::new(
            Arc::new(DurableHandleEngine::new()),
            Arc::new(EchoToolExecutor),
        ),
        Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
    );
    let meter = crate::runtime::TurnMeter::new(
        Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        key(),
        "voice-server",
        crate::OPENAI_REALTIME,
    );
    let (core, _handle) = crate::topology::begin_session(
        &rt,
        crate::ir::codec::OpenAiRealtimeCodec,
        "acct-meter",
        "call-turn",
        None,
        crate::runtime::Carrier::sideband(),
        Some(meter),
        5,
    )
    .expect("the session opens");
    let done = serde_json::json!({
        "type": "response.done",
        "response": { "usage": {
            "input_token_details": { "audio_tokens": 120 },
            "output_token_details": { "audio_tokens": 80 },
        }},
    });
    let _ = core
        .on_server_frame(WireEvent(bytes::Bytes::from(
            serde_json::to_vec(&done).unwrap(),
        )))
        .await;
    let rows = host.ledger_rows(&key().id);
    let lane = "voice\u{1f}openai_realtime".to_string();
    assert_eq!(
        rows.get(&(lane.clone(), "audio_tokens_in".to_string())),
        Some(&120)
    );
    assert_eq!(rows.get(&(lane, "audio_tokens_out".to_string())), Some(&80));
    assert_eq!(rows.len(), 2, "only the classes the turn carried");
}
