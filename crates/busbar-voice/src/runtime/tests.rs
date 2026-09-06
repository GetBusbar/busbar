// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T2 RUNTIME TESTS (behind `runtime`): pump lifecycle, tool-call correlation under interleaving,
//! SessionScope reattach + foreign-owner refusal, and the D2 HARD-CLOSE-ON-EXHAUSTION path. The
//! WS/transport is mocked with in-memory `futures` channel pairs; the metering lease is the faithful
//! [`LocalLease`] whose reserve/settle/exhaustion contract is byte-for-byte the host D2 lease's.

use crate::ir::codec::{OpenAiRealtimeCodec, WireEvent};
use crate::ir::usage::IrDuplexUsage;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::{
    HostMeteringPort, LeaseState, LocalMeteringPort, MeteringPort, MockMeteringHost,
};
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{SessionCore, VoiceSession};
use busbar_substrate::ingress::byte_duplex::serve_messages;
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::handle_engine::{HandleDenied, ScopedMutateError};
use busbar_substrate::plane_host::MeteringHost;
use bytes::Bytes;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::StreamExt;
use std::sync::Arc;

// ── fixtures ──────────────────────────────────────────────────────────────────────────────────────

/// A downlink-facing core with a real downlink sink, a metering lease over `cap` nanodollars, the echo
/// tool executor, and the PRODUCTION money hop (a host lease + host pricing over [`MockMeteringHost`],
/// which prices every reserved unit at 1 nano). Returns the core plus the downlink receiver the client
/// would read.
fn core_with_downlink(
    cap: Option<u64>,
) -> (
    Arc<SessionCore<OpenAiRealtimeCodec>>,
    UnboundedReceiver<Vec<u8>>,
) {
    let (dtx, drx) = unbounded::<Vec<u8>>();
    let carrier = Carrier::with_downlink(dtx);
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    let lease = HostMeteringPort::new(host)
        .reserve(1_000, 0, cap)
        .expect("lease opens for a non-refuse-all cap");
    let core = Arc::new(SessionCore::new(
        OpenAiRealtimeCodec,
        lease,
        None,
        Arc::new(crate::runtime::tools::EchoToolExecutor),
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
fn usage_folds_five_classes_onto_the_four_reserved_keys() {
    // The 5→4 map: (audio_in+text_in)-cached→input, audio_out+text_out→output, cached→cache_read. No
    // new unit/label/constant — only the existing reserved keys, and only non-zero classes are keyed.
    // `cached` is a SUBSET of the input classes in both dialects, so it is netted out of the input
    // lane and billed once, on the cache-read lane.
    let u = IrDuplexUsage {
        audio_in: 20,
        audio_out: 3,
        text_in: 5,
        text_out: 7,
        cached: 11,
    };
    let usage = u.to_billing_usage();
    assert_eq!(
        usage.usage_units.get(busbar_api::UNIT_INPUT).copied(),
        Some(20 + 5 - 11),
        "audio_in + text_in fold onto `input`, less the cached subset"
    );
    assert_eq!(
        usage.usage_units.get(busbar_api::UNIT_OUTPUT).copied(),
        Some(3 + 7),
        "audio_out + text_out fold onto `output`"
    );
    assert_eq!(
        usage.usage_units.get(busbar_api::UNIT_CACHE_READ).copied(),
        Some(11),
        "cached folds onto `cache_read`"
    );
    assert_eq!(
        usage.usage_units.len(),
        3,
        "only the three touched reserved keys"
    );
    // The billed lanes never exceed the turn the provider reported.
    assert_eq!(
        usage.usage_units.values().sum::<u64>(),
        20 + 5 + 3 + 7,
        "the four classes bill once each, never the cached subset twice"
    );
    // A fully-cached turn bills nothing on the input lane (and keys no zero component).
    let all_cached = IrDuplexUsage {
        audio_in: 40,
        cached: 40,
        ..IrDuplexUsage::default()
    }
    .to_billing_usage();
    assert_eq!(all_cached.usage_units.get(busbar_api::UNIT_INPUT), None);
    assert_eq!(
        all_cached
            .usage_units
            .get(busbar_api::UNIT_CACHE_READ)
            .copied(),
        Some(40)
    );
    // An over-reported cache figure FLOORS the input lane at zero — it never wraps to a huge charge.
    let over = IrDuplexUsage {
        audio_in: 10,
        cached: 999,
        ..IrDuplexUsage::default()
    }
    .to_billing_usage();
    assert_eq!(over.usage_units.get(busbar_api::UNIT_INPUT), None);
    // An empty turn keys nothing (no zero components ever price).
    assert!(IrDuplexUsage::default()
        .to_billing_usage()
        .usage_units
        .is_empty());
}

#[test]
fn host_prices_usage_then_settles_the_priced_increment() {
    // The price_usage → settle path: the mock host prices every reserved unit at 1 nano, so a turn of
    // (audio_out 3, text_out 4) folds to output=7 and prices to 7 nanos, settled against the lease.
    let host = Arc::new(MockMeteringHost::default());
    let port = HostMeteringPort::new(Arc::clone(&host) as Arc<dyn MeteringHost>);
    let lease = port
        .reserve(0, 0, Some(100))
        .expect("uncapped-enough opens");
    let u = IrDuplexUsage {
        audio_out: 3,
        text_out: 4,
        ..IrDuplexUsage::default()
    };
    let usage = u.to_billing_usage();
    let nanos = lease
        .price_usage("gpt-realtime", &usage)
        .expect("model is priced");
    assert_eq!(nanos, 7, "output 3+4 priced at 1 nano each = 7");
    assert_eq!(lease.settle(nanos), LeaseState::Live);
    assert_eq!(lease.settled_nanos(), 7);
    // An UNPRICED model fails closed (None) — never meters as free.
    assert!(
        lease
            .price_usage(MockMeteringHost::UNPRICED_MODEL, &usage)
            .is_none(),
        "an unpriced model returns None so the caller hard-closes"
    );
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

// ── THE HOST-LEASE PORT (the REAL D2 money hop) — the production `HostMeteringPort` over a mock host ─

#[test]
fn host_lease_reserves_settles_and_hard_closes_at_the_real_cap() {
    use crate::runtime::metering::HostMeteringPort;
    let host = Arc::new(MockMeteringHost::default());
    let port = HostMeteringPort::new(Arc::clone(&host) as Arc<dyn MeteringHost>);

    // Reserve estimate 100 + flat fee 10, TRUE cap 50 (the flat fee is folded into `reserved`, NOT the
    // cap — exhaustion is judged against the cap only, so the fee is never double-counted on settle).
    let lease = port
        .reserve(100, 10, Some(50))
        .expect("a real cap opens the lease");
    // The flat fee folded into `reserved` ONCE (estimate 100 + fee 10), never into the cap.
    assert_eq!(
        host.reserved_of(1),
        Some(110),
        "reserve = estimate + flat fee, charged once"
    );
    assert_eq!(lease.settle(20), LeaseState::Live, "20 < 50 → live");
    assert_eq!(lease.settle(20), LeaseState::Live, "40 < 50 → live");
    assert_eq!(
        lease.settled_nanos(),
        40,
        "settled tap reads through the host"
    );
    assert_eq!(
        lease.settle(20),
        LeaseState::Exhausted,
        "60 ≥ cap 50 → exhausted (hard close)"
    );
    assert_eq!(lease.settled_nanos(), 60, "exact accrual, no drift");
    // Dropping the handle closes the lease host-side (no registry leak).
    drop(lease);
    assert!(
        host.closed_ids().contains(&1),
        "the dropped HostLease closed its lease host-side"
    );
}

#[test]
fn host_port_refuse_all_fails_the_session_closed() {
    use crate::runtime::metering::HostMeteringPort;
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    let port = HostMeteringPort::new(host);
    // A refuse-all cap denies the reserve — the session never opens (fail closed).
    assert!(
        port.reserve(0, 0, Some(0)).is_none(),
        "refuse-all → no lease"
    );
    // An uncapped lease never exhausts.
    let unc = port.reserve(0, 0, None).expect("uncapped opens");
    assert_eq!(unc.settle(u64::MAX), LeaseState::Live, "uncapped never dry");
}

#[test]
fn host_lease_unknown_or_closed_settle_fails_closed() {
    use crate::runtime::metering::HostMeteringPort;
    let host = Arc::new(MockMeteringHost::default());
    let port = HostMeteringPort::new(Arc::clone(&host) as Arc<dyn MeteringHost>);
    let lease = port.reserve(0, 0, Some(100)).unwrap();
    // Forget the lease host-side out from under the handle: the next settle names no open lease and the
    // adapter maps the host's `None` to `Refused`, so the plane hard-closes fail-closed (not silently).
    host.clear_leases();
    assert_eq!(
        lease.settle(1),
        LeaseState::Refused,
        "unknown lease → Refused"
    );
    assert!(lease.settle(1).must_close(), "Refused demands a hard close");
    assert_eq!(lease.settled_nanos(), 0, "an unknown lease reads 0 settled");
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

#[test]
fn session_scope_rtc_call_id_correlation_is_owner_gated_and_durable() {
    let engine = Arc::new(DurableHandleEngine::new());
    let alice = SessionHandle::bind(Arc::clone(&engine), "alice", "call-1");
    alice.open(1).expect("alice opens her session");
    assert_eq!(
        alice.get().and_then(|r| r.rtc_call_id),
        None,
        "no correlation key until the SDP broker sets it"
    );

    // The SDP broker stamps the provider's rtc_<call_id> preserved from the Location header.
    alice
        .set_rtc_call_id("rtc_abc123", 2)
        .expect("owner stamps the correlation key");
    assert_eq!(
        alice.get().and_then(|r| r.rtc_call_id).as_deref(),
        Some("rtc_abc123"),
        "the correlation key is durable on the row"
    );

    // It survives a subsequent turn checkpoint (the mutate clones the live row).
    alice.bump_turn(3).expect("owner bump");
    let row = alice.get().expect("row present");
    assert_eq!(row.turns, 1);
    assert_eq!(
        row.rtc_call_id.as_deref(),
        Some("rtc_abc123"),
        "a turn bump preserves the correlation key"
    );

    // A foreign owner cannot stamp a correlation key — the same indistinguishable refusal.
    let mallory = SessionHandle::bind(Arc::clone(&engine), "mallory", "call-1");
    assert!(
        matches!(
            mallory.set_rtc_call_id("rtc_evil", 4),
            Err(ScopedMutateError::NotYours)
        ),
        "a foreign owner cannot forge the media correlation"
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

// ── the governed wait: a client-served tool call ────────────────────────────────────────────────
//
// The other half of the tool moat. A call for a tool this node does NOT serve cannot be answered
// in-process — the answer is the client's — so the runtime opens no execution for it and routes the
// client's reply to the node's own table instead. Three facts, and each of them failed before this:
// the reply woke the wait, a reply naming a call nobody is waiting on is refused rather than carried
// upstream, and a call nobody answered is swept by the tick.

/// A tool executor that serves exactly one tool and leaves the rest to the client.
#[derive(Debug)]
struct ServesOnly(&'static str);

#[async_trait::async_trait]
impl crate::runtime::ToolExecutor for ServesOnly {
    fn serves(&self, name: &str) -> bool {
        name == self.0
    }
    async fn execute(&self, name: &str, _arguments: &[u8]) -> Vec<u8> {
        format!(r#"{{"served":"{name}"}}"#).into_bytes()
    }
}

/// The node's table, as the runtime is allowed to see it: which identifiers are open, and a sweep.
#[derive(Debug, Default)]
struct TableFake {
    sessions: std::sync::Mutex<std::collections::BTreeMap<u64, Vec<String>>>,
}

impl crate::runtime::GovernedCalls for TableFake {
    fn replied(&self, session: u64, call_id: &str) -> Result<(), crate::runtime::ReplyRefusal> {
        let mut s = self.sessions.lock().unwrap();
        let open = s
            .get_mut(&session)
            .ok_or(crate::runtime::ReplyRefusal::NoSuchSession)?;
        let i = open
            .iter()
            .position(|c| c == call_id)
            .ok_or(crate::runtime::ReplyRefusal::UnknownCall)?;
        open.remove(i);
        Ok(())
    }

    fn expired(&self, _now_ms: u64) -> usize {
        let mut s = self.sessions.lock().unwrap();
        let n: usize = s.values().map(Vec::len).sum();
        s.clear();
        n
    }
}

/// A core bound to `table` as session 7, serving only the tool `local`.
fn governed_core(table: Arc<TableFake>) -> Arc<SessionCore<OpenAiRealtimeCodec>> {
    let (dtx, _drx) = unbounded::<Vec<u8>>();
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    let lease = HostMeteringPort::new(host)
        .reserve(1_000, 0, None)
        .expect("lease opens");
    Arc::new(
        SessionCore::new(
            OpenAiRealtimeCodec,
            lease,
            None,
            Arc::new(ServesOnly("local")),
            Carrier::with_downlink(dtx),
            None,
        )
        .with_governed(crate::runtime::GovernedSession {
            session: 7,
            calls: table as Arc<dyn crate::runtime::GovernedCalls>,
        }),
    )
}

/// The three server→client frames that announce, stream and close one call for `tool`.
fn call_frames(call_id: &str, tool: &str) -> [WireEvent; 3] {
    [
        wire(serde_json::json!({"type":"response.output_item.added",
            "item":{"type":"function_call","call_id":call_id,"name":tool}})),
        wire(serde_json::json!({"type":"response.function_call_arguments.delta",
            "call_id":call_id,"delta":"{}"})),
        wire(serde_json::json!({"type":"response.function_call_arguments.done","call_id":call_id})),
    ]
}

/// The client's own `function_call_output` for `call_id`.
fn client_reply(call_id: &str) -> WireEvent {
    wire(serde_json::json!({"type":"conversation.item.create",
        "item":{"type":"function_call_output","call_id":call_id,"output":"42"}}))
}

#[tokio::test]
async fn a_client_served_call_waits_and_its_reply_wakes_the_unit() {
    let table = Arc::new(TableFake::default());
    let core = governed_core(Arc::clone(&table));

    // The node serves `local` and does not serve `remote`. Both calls close in the same turn.
    let mut upstream = Vec::new();
    for f in call_frames("cl", "local")
        .into_iter()
        .chain(call_frames("cr", "remote"))
    {
        upstream.extend(core.on_server_frame(f).await.upstream);
    }
    let joined: String = upstream
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("\"call_id\":\"cl\""),
        "the tool the node serves is still executed in-process: {joined}"
    );
    assert!(
        !joined.contains("\"call_id\":\"cr\""),
        "the node never authors an answer for a call it does not serve: {joined}"
    );

    // The root entered the wait where it planned the leg. The runtime is what tells it the answer
    // arrived — and the reply goes on upstream only because the wait was woken.
    table.sessions.lock().unwrap().insert(7, vec!["cr".to_string()]);
    let plan = core.on_client_frame(client_reply("cr"));
    assert!(
        !plan.refused_reply,
        "the wait was open, so nothing is refused"
    );
    let up: String = plan
        .upstream
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        up.contains("function_call_output") && up.contains("response.create"),
        "the woken reply reaches the model and asks it to continue: {up}"
    );
    assert!(
        table.sessions.lock().unwrap()[&7].is_empty(),
        "the table no longer holds the call"
    );
}

#[tokio::test]
async fn a_reply_naming_no_open_call_is_refused_rather_than_carried_upstream() {
    let table = Arc::new(TableFake::default());
    let core = governed_core(Arc::clone(&table));
    for f in call_frames("cr", "remote") {
        core.on_server_frame(f).await;
    }
    // The session's table holds `cr`; the client answers `cz`.
    table.sessions.lock().unwrap().insert(7, vec!["cr".to_string()]);
    let plan = core.on_client_frame(client_reply("cz"));
    assert!(plan.refused_reply, "a reply matching nothing is refused");
    assert!(
        plan.upstream.is_empty(),
        "and a refused reply reaches the model on no wire at all"
    );
    assert_eq!(
        table.sessions.lock().unwrap()[&7],
        vec!["cr".to_string()],
        "the call it did not answer is still waiting"
    );
}

#[tokio::test]
async fn an_unanswered_client_served_call_is_swept_by_the_tick() {
    let table = Arc::new(TableFake::default());
    let core = governed_core(Arc::clone(&table));
    for f in call_frames("cr", "remote") {
        core.on_server_frame(f).await;
    }
    table.sessions.lock().unwrap().insert(7, vec!["cr".to_string()]);

    // The tick is what runs beside the pump; without it the wait is never ended and the call's hold
    // is held open by a client that simply never replied.
    assert_eq!(
        core.sweep_expired(1_000),
        1,
        "the tick swept the one open call"
    );
    // And a reply that turns up after the sweep is refused, not paid out against a settled call.
    let plan = core.on_client_frame(client_reply("cr"));
    assert!(plan.refused_reply, "a late reply answers nothing");
    assert!(plan.upstream.is_empty());
}
