// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T2 RUNTIME TESTS (behind `runtime`): pump lifecycle, tool-call correlation under interleaving,
//! SessionScope reattach + foreign-owner refusal, and the D2 HARD-CLOSE-ON-EXHAUSTION path. The
//! WS/transport is mocked with in-memory `futures` channel pairs; the metering lease is the faithful
//! [`LocalLease`] whose reserve/settle/exhaustion contract is byte-for-byte the host D2 lease's.

use crate::ir::codec::{OpenAiRealtimeCodec, WireEvent};
use crate::ir::usage::IrDuplexUsage;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::{LeaseState, LocalMeteringPort, MeteringPort, Pricing};
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{SessionCore, VoiceSession};
use busbar_substrate::ingress::byte_duplex::serve_messages;
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::handle_engine::{HandleDenied, ScopedMutateError};
use bytes::Bytes;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::StreamExt;
use std::sync::Arc;

// ── fixtures ──────────────────────────────────────────────────────────────────────────────────────

fn test_pricing() -> Pricing {
    // 1 nanodollar per token of every class — keeps the arithmetic legible in assertions.
    Pricing {
        audio_in_nanos: 1,
        audio_out_nanos: 1,
        text_in_nanos: 1,
        text_out_nanos: 1,
        cached_nanos: 1,
    }
}

/// A downlink-facing core with a real downlink sink, a metering lease over `cap` nanodollars, and the
/// echo tool executor. Returns the core plus the downlink receiver the client would read.
fn core_with_downlink(
    cap: Option<u64>,
) -> (
    Arc<SessionCore<OpenAiRealtimeCodec>>,
    UnboundedReceiver<Vec<u8>>,
) {
    let (dtx, drx) = unbounded::<Vec<u8>>();
    let carrier = Carrier::with_downlink(dtx);
    let lease = LocalMeteringPort
        .reserve(1_000, 0, cap)
        .expect("lease opens for a non-refuse-all cap");
    let core = Arc::new(SessionCore::new(
        OpenAiRealtimeCodec,
        lease,
        Arc::new(crate::runtime::tools::EchoToolExecutor),
        test_pricing(),
        carrier,
        None,
    ));
    (core, drx)
}

fn wire(json: serde_json::Value) -> WireEvent {
    WireEvent(Bytes::from(serde_json::to_vec(&json).unwrap()))
}

fn usage_frame(audio_out: u64) -> WireEvent {
    wire(serde_json::json!({
        "type": "response.done",
        "response": { "usage": {
            "total_tokens": audio_out,
            "output_token_details": { "audio_tokens": audio_out },
        }},
    }))
}

fn audio_delta(b64: &str) -> WireEvent {
    wire(serde_json::json!({ "type": "response.output_audio.delta", "delta": b64 }))
}

// ── metering: pricing + lease semantics ─────────────────────────────────────────────────────────

#[test]
fn pricing_sums_every_token_class() {
    let p = Pricing {
        audio_in_nanos: 2,
        audio_out_nanos: 3,
        text_in_nanos: 5,
        text_out_nanos: 7,
        cached_nanos: 11,
    };
    let u = IrDuplexUsage {
        audio_in: 1,
        audio_out: 1,
        text_in: 1,
        text_out: 1,
        cached: 1,
    };
    assert_eq!(p.price(&u), 2 + 3 + 5 + 7 + 11);
}

#[test]
fn local_lease_exhausts_at_cap_and_refuse_all_denies() {
    let lease = LocalMeteringPort.reserve(100, 10, Some(50)).unwrap();
    assert_eq!(lease.settle(20), LeaseState::Live);
    assert_eq!(lease.settle(20), LeaseState::Live);
    assert_eq!(
        lease.settle(20),
        LeaseState::Exhausted,
        "settled 60 >= cap 50"
    );
    assert_eq!(lease.settled_nanos(), 60);
    // An uncapped lease never exhausts.
    let unc = LocalMeteringPort.reserve(0, 0, None).unwrap();
    assert_eq!(unc.settle(u64::MAX), LeaseState::Live);
    // A refuse-all cap denies the reserve outright (fail closed).
    assert!(LocalMeteringPort.reserve(0, 0, Some(0)).is_none());
}

// ── THE D2 HARD-CLOSE-ON-EXHAUSTION PATH (the marquee guarantee) ─────────────────────────────────

#[tokio::test]
async fn settle_past_cap_hard_closes_the_carrier() {
    // Cap of 5 nanodollars; each usage frame settles 3.
    let (core, mut drx) = core_with_downlink(Some(5));

    // Frame 1: 3 audio-out tokens → settle 3, under cap → still live, no close.
    let plan = core.on_server_frame(usage_frame(3)).await;
    assert!(!plan.close, "under cap: no hard close");
    assert!(!core.carrier().is_closed());
    assert_eq!(core.settled_nanos(), 3);

    // Frame 2: another 3 → settled 6 >= cap 5 → EXHAUSTED → hard close.
    let plan = core.on_server_frame(usage_frame(3)).await;
    assert!(plan.close, "over cap: the frame plan demands a hard close");
    assert!(
        plan.upstream
            .iter()
            .any(|w| String::from_utf8_lossy(&w.0).contains("response.cancel")),
        "exhaustion cancels the in-flight response upstream"
    );
    assert!(core.carrier().is_closed(), "the carrier hard-closed");
    assert_eq!(core.settled_nanos(), 6);

    // After the hard close, nothing more is processed and no downlink reaches the client.
    let plan = core.on_server_frame(audio_delta("AAAA")).await;
    assert!(plan.downlink.is_empty(), "closed carrier processes nothing");
    assert!(
        !core.carrier().send_downlink(vec![1, 2, 3]),
        "the carrier drops downlink after hard close"
    );
    // Drain: the client never received a post-close audio frame.
    drx.close();
    let mut leaked_post_close = false;
    while let Some(_f) = drx.next().await {
        // Any frames here are pre-close (there were none of audio before exhaustion in this test).
        leaked_post_close = true;
    }
    assert!(!leaked_post_close, "no downlink audio leaked to the client");
}

// ── pump lifecycle: frames both ways, close ends cleanly ────────────────────────────────────────

#[tokio::test]
async fn pump_relays_downlink_audio_and_close_ends_cleanly() {
    let (core, mut drx) = core_with_downlink(None);
    let session = Arc::new(VoiceSession::new(Arc::clone(&core)));

    // Feed two server audio frames then EOF (drop the sender).
    let (in_tx, in_rx) = unbounded::<Vec<u8>>();
    let (out_tx, _out_rx) = unbounded::<Vec<u8>>();
    in_tx
        .unbounded_send(
            serde_json::to_vec(&serde_json::json!({
                "type": "response.output_audio.delta", "delta": "AAAA"
            }))
            .unwrap(),
        )
        .unwrap();
    in_tx
        .unbounded_send(
            serde_json::to_vec(&serde_json::json!({
                "type": "response.output_audio.done", "item_id": "it1"
            }))
            .unwrap(),
        )
        .unwrap();
    drop(in_tx); // EOF ends the pump cleanly.

    // serve_messages returns when the stream ends and the drain completes.
    serve_messages(in_rx, out_tx, session).await;

    // The client received the two downlink frames, in order.
    drx.close();
    let mut kinds = Vec::new();
    while let Some(f) = drx.next().await {
        let v: serde_json::Value = serde_json::from_slice(&f).unwrap();
        kinds.push(v["type"].as_str().unwrap().to_string());
    }
    assert_eq!(
        kinds,
        vec![
            "response.output_audio.delta".to_string(),
            "response.output_audio.done".to_string()
        ]
    );
}

// ── tool-call correlation under interleaving ────────────────────────────────────────────────────

#[tokio::test]
async fn tool_calls_correlate_under_interleaving() {
    let (core, _drx) = core_with_downlink(None);

    // Two calls, A (call_id "ca") and B (call_id "cb"), their OPEN/ARGS/CLOSE interleaved.
    let frames = [
        wire(
            serde_json::json!({"type":"response.output_item.added","item":{"type":"function_call","call_id":"ca","name":"alpha"}}),
        ),
        wire(
            serde_json::json!({"type":"response.output_item.added","item":{"type":"function_call","call_id":"cb","name":"beta"}}),
        ),
        wire(
            serde_json::json!({"type":"response.function_call_arguments.delta","call_id":"ca","delta":"{\"x\":1}"}),
        ),
        wire(
            serde_json::json!({"type":"response.function_call_arguments.delta","call_id":"cb","delta":"{\"y\":2}"}),
        ),
        wire(serde_json::json!({"type":"response.function_call_arguments.done","call_id":"cb"})),
        wire(serde_json::json!({"type":"response.function_call_arguments.done","call_id":"ca"})),
    ];

    let mut upstream = Vec::new();
    for f in frames {
        let plan = core.on_server_frame(f).await;
        upstream.extend(plan.upstream);
    }

    // Each close produced a function_call_output correlating the RIGHT call_id to the RIGHT args, plus
    // a response.create to continue.
    let texts: Vec<String> = upstream
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).to_string())
        .collect();
    let joined = texts.join("\n");
    assert!(
        joined.contains("\"call_id\":\"cb\"")
            && joined.contains("beta")
            && joined.contains("{\\\"y\\\":2}"),
        "call B's result correlates its own id + args: {joined}"
    );
    assert!(
        joined.contains("\"call_id\":\"ca\"")
            && joined.contains("alpha")
            && joined.contains("{\\\"x\\\":1}"),
        "call A's result correlates its own id + args: {joined}"
    );
    assert_eq!(
        texts
            .iter()
            .filter(|t| t.contains("function_call_output"))
            .count(),
        2,
        "exactly two tool results, one per call"
    );
    assert_eq!(
        texts
            .iter()
            .filter(|t| t.contains("response.create"))
            .count(),
        2,
        "each result asks the model to continue"
    );
}

// ── barge-in: speech_started cancels + truncates at the heard position ───────────────────────────

#[tokio::test]
async fn barge_in_cancels_and_truncates_at_heard_ms() {
    let (core, _drx) = core_with_downlink(None);
    // pcm16 default: 48 bytes/ms. Play 96 bytes of downlink audio = 2 ms heard.
    // 96 raw bytes base64-encodes to 128 chars; use a 96-byte payload.
    let payload = vec![0u8; 96];
    let b64 = busbar_substrate::media::base64_encode(&Bytes::from(payload));
    let _ = core.on_server_frame(audio_delta(&b64)).await;

    let plan = core
        .on_server_frame(wire(serde_json::json!({
            "type":"input_audio_buffer.speech_started","audio_start_ms":0,"item_id":"it7"
        })))
        .await;
    let joined: String = plan
        .upstream
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("response.cancel"),
        "barge-in cancels the response"
    );
    assert!(
        joined.contains("conversation.item.truncate") && joined.contains("\"audio_end_ms\":2"),
        "truncate carries the 2 ms actually heard: {joined}"
    );
}

// ── SessionScope: reattach + foreign-owner refusal ──────────────────────────────────────────────

#[test]
fn session_scope_reattach_and_foreign_owner_refusal() {
    let engine = Arc::new(DurableHandleEngine::new());
    let alice = SessionHandle::bind(Arc::clone(&engine), "alice", "call-1");
    alice.open(1).expect("alice opens her session");

    // A per-turn checkpoint bumps the durable cursor.
    assert_eq!(alice.bump_turn(2).expect("owner bump"), 1);
    assert_eq!(alice.bump_turn(3).expect("owner bump"), 2);

    // REATTACH: a fresh binding for the SAME (owner, id) reads the live row through the scoped path.
    let alice_again = SessionHandle::bind(Arc::clone(&engine), "alice", "call-1");
    assert_eq!(
        alice_again.get().map(|r| r.turns),
        Some(2),
        "reattach sees the durable turns"
    );

    // FOREIGN OWNER: a session bound to the same id under a different owner is refused identically to a
    // missing handle — cannot read, resume, or evict, and cannot even tell it exists.
    let mallory = SessionHandle::bind(Arc::clone(&engine), "mallory", "call-1");
    assert!(mallory.get().is_none(), "foreign owner cannot read");
    assert!(
        matches!(
            mallory.scope_mutate_probe(),
            Err(ScopedMutateError::NotYours)
        ),
        "foreign owner cannot resume/mutate"
    );
    assert!(!mallory.close(), "foreign owner evicts nothing");

    // The rightful owner drives terminal, then closes (owner-gated, terminal-only).
    assert!(!alice.close(), "an active handle is not evicted");
    alice.settle_terminal(4).expect("owner settles terminal");
    assert!(alice.close(), "a terminal handle is evicted by its owner");
    assert!(
        alice.get().is_none(),
        "closed session is gone from the working set"
    );
}

// A tiny probe used only by the foreign-owner test — proves the mutate path refuses NotYours without
// the test needing to reconstruct a full mutation.
impl SessionHandle {
    fn scope_mutate_probe(&self) -> Result<u64, ScopedMutateError> {
        self.bump_turn(9)
    }
}

#[test]
fn read_denied_maps_to_notyours() {
    // Belt-and-braces: the raw scoped read for a foreign owner is exactly HandleDenied::NotYours.
    let engine = Arc::new(DurableHandleEngine::new());
    let alice = SessionHandle::bind(Arc::clone(&engine), "alice", "s");
    alice.open(1).unwrap();
    let raw: Result<_, HandleDenied> = SessionScopeRawProbe::probe(&engine);
    assert!(matches!(raw, Err(HandleDenied::NotYours)));
}

// Helper that reaches the raw scoped read to assert the exact read-denial variant.
struct SessionScopeRawProbe;
impl SessionScopeRawProbe {
    fn probe(
        engine: &Arc<DurableHandleEngine>,
    ) -> Result<Arc<dyn std::any::Any + Send + Sync>, HandleDenied> {
        busbar_substrate::plane_host::SessionScope::new(Arc::clone(engine), "mallory", "s").get()
    }
}
