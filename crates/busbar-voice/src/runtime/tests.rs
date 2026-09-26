// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T2 RUNTIME TESTS (behind `runtime`): pump lifecycle, tool-call correlation under interleaving,
//! SessionScope reattach + foreign-owner refusal, and the session's METERING — each closed turn's raw
//! counts per class handed to the kernel's session account (Q21b), and the HARD CLOSE the kernel's
//! budget view answers when a turn dries the caller's chain. The WS/transport is mocked with in-memory
//! `futures` channel pairs; the host is the fixture host, whose budget view a test sets or caps by
//! count (what a count is WORTH is proven over the real engine in the composition root's tests).

use crate::ir::codec::{OpenAiRealtimeCodec, WireEvent};
use crate::ir::usage::IrDuplexUsage;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::{SessionMetering, TurnMeter, TurnVerdict};
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::{SessionCore, VoiceSession};
use crate::testkit::fixture_host::FixtureHost;
use busbar_kernel::ingress::byte_duplex::serve_messages;
use busbar_kernel::plane::handle_engine::{DurableHandleEngine, HandleDenied, ScopedMutateError};
use bytes::Bytes;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::StreamExt;
use std::collections::BTreeMap;
use std::sync::Arc;

// ── fixtures ──────────────────────────────────────────────────────────────────────────────────────

/// The presenting key every metered cell opens its session for.
fn caller() -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: "vk-voice".to_string(),
        name: "voice".to_string(),
        ..Default::default()
    }
}

/// The lane an unmodelled OpenAI Realtime session's counts are ledgered under: the voice plane's key,
/// the separator, and the provider label (the dialect carries its model server-side).
const LANE: &str = "voice\u{1f}openai_realtime";

/// A governed fixture host whose budget view is ONE bucket capped at `cap` counts (`None`: uncapped).
fn governed_host(cap: Option<i64>) -> Arc<FixtureHost> {
    let host = FixtureHost::new().governed();
    Arc::new(match cap {
        Some(cap) => host.with_count_cap(cap),
        None => host,
    })
}

/// Open the presenting key's kernel account over `host`.
fn metering(host: &Arc<FixtureHost>) -> SessionMetering {
    TurnMeter::new(
        Arc::clone(host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        caller(),
        "voice-server",
        crate::OPENAI_REALTIME,
    )
    .open("")
    .expect("a chain with room opens")
    .expect("a governed host opens an account")
}

/// A downlink-facing core with a real downlink sink, the echo tool executor, and the session's
/// metering over `host` (`None`: an ungoverned session). Returns the core plus the downlink receiver
/// the client would read.
fn core_on(
    host: Option<&Arc<FixtureHost>>,
) -> (
    Arc<SessionCore<OpenAiRealtimeCodec>>,
    UnboundedReceiver<Vec<u8>>,
) {
    let (dtx, drx) = unbounded::<Vec<u8>>();
    let core = Arc::new(SessionCore::new(
        OpenAiRealtimeCodec,
        host.map(metering),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
        Carrier::with_downlink(dtx),
        None,
    ));
    (core, drx)
}

/// A downlink-facing core metered over a count-capped host (`None`: ungoverned).
fn core_with_downlink(
    cap: Option<i64>,
) -> (
    Arc<SessionCore<OpenAiRealtimeCodec>>,
    UnboundedReceiver<Vec<u8>>,
) {
    match cap {
        Some(cap) => core_on(Some(&governed_host(Some(cap)))),
        None => core_on(None),
    }
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

/// `ms` milliseconds of PCM16 uplink audio (24 kHz mono, 48 bytes a millisecond) as the client sends it.
fn uplink_audio(ms: usize) -> WireEvent {
    let pcm = Bytes::from(vec![0u8; ms * 48]);
    wire(serde_json::json!({
        "type": "input_audio_buffer.append",
        "audio": busbar_contract::media::base64_encode(&pcm),
    }))
}

/// The upstream opening one tool call.
fn call_opened(call_id: &str) -> WireEvent {
    wire(serde_json::json!({"type":"response.output_item.added",
        "item":{"type":"function_call","call_id":call_id,"name":"lookup"}}))
}

/// The rows `host` holds for the caller, as `(class, count)` under [`LANE`].
fn rows(host: &FixtureHost) -> BTreeMap<String, u64> {
    host.ledger_rows(&caller().id)
        .into_iter()
        .map(|((lane, class), n)| {
            assert_eq!(lane, LANE, "every count is ledgered under the voice lane");
            (class, n)
        })
        .collect()
}

fn row_set(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(c, n)| ((*c).to_string(), *n)).collect()
}

// ── metering: the plane's counts, the kernel's verdict ──────────────────────────────────────────

#[test]
fn usage_folds_five_classes_onto_the_four_reserved_keys() {
    // The codec's own 5→4 fold (no longer the voice billing path, which ledgers the plane's classes —
    // see `a_served_turn_ledgers_the_planes_counts_per_class`), kept honest while it exists.
    let u = IrDuplexUsage {
        audio_in: 20,
        audio_out: 3,
        text_in: 5,
        text_out: 7,
        cached: 11,
    };
    let usage = u.to_billing_usage();
    assert_eq!(
        usage
            .usage_units
            .get(busbar_contract::records::UNIT_INPUT)
            .copied(),
        Some(20 + 5 - 11)
    );
    assert_eq!(
        usage
            .usage_units
            .get(busbar_contract::records::UNIT_OUTPUT)
            .copied(),
        Some(3 + 7)
    );
    assert_eq!(
        usage
            .usage_units
            .get(busbar_contract::records::UNIT_CACHE_READ)
            .copied(),
        Some(11)
    );
    assert!(IrDuplexUsage::default()
        .to_billing_usage()
        .usage_units
        .is_empty());
}

/// Q21b EXIT TEST — a served voice session writes the streaming plane's count rows. One turn: a
/// second of uplink audio, one tool call opened, a usage report naming all five token classes. The
/// ledger holds exactly the plane's SIX billable classes, under the voice lane, at the counts the
/// turn carried — never a price, and never the llm plane's reserved token keys.
///
/// #71 EXIT TEST (money-model integrity, P2-voicefix): the upstream's `cached_tokens` figure is a
/// SUBSET of `input_token_details.audio_tokens`/`text_tokens`, not a class beside them, so it must
/// NOT produce a ledger row — a streams card that priced it would double-bill the same cached input.
/// This turn reports `cached_tokens: 1` and the ledger holds no `cached_tokens` row for it (before
/// this fix it did, at count 1, RED against this exact assertion).
#[tokio::test]
async fn a_served_turn_ledgers_the_planes_counts_per_class() {
    let host = governed_host(None);
    let (core, _drx) = core_on(Some(&host));
    let _ = core.on_client_frame(uplink_audio(1_000));
    let _ = core.on_server_frame(call_opened("call_1")).await;
    let done = wire(serde_json::json!({
        "type": "response.done",
        "response": { "usage": {
            "input_token_details": { "audio_tokens": 10, "text_tokens": 3, "cached_tokens": 1 },
            "output_token_details": { "audio_tokens": 20, "text_tokens": 4 },
        }},
    }));
    let plan = core.on_server_frame(done).await;
    assert!(!plan.close, "an uncapped chain never closes the carrier");
    assert_eq!(
        rows(&host),
        row_set(&[
            ("audio_seconds_in", 1),
            ("audio_tokens_in", 10),
            ("audio_tokens_out", 20),
            ("text_tokens_in", 3),
            ("text_tokens_out", 4),
            ("tool_calls", 1),
        ]),
        "no cached_tokens row: it is a subset of audio_tokens_in/text_tokens_in, not a class beside \
         them (architect ruling #71) — pricing it too would double-bill the same cached input",
    );
    assert!(
        !rows(&host).contains_key("cached_tokens"),
        "cached_tokens must never reach the ledger as a billable class (#71)",
    );
    // The turn's counters closed with it: the next report carries only what the next turn did.
    let _ = core.on_server_frame(usage_frame(2)).await;
    assert_eq!(rows(&host)["audio_tokens_out"], 22);
    assert_eq!(rows(&host)["audio_seconds_in"], 1);
    assert_eq!(rows(&host)["tool_calls"], 1);
}

/// A turn that ends on an upstream error, or with the session, was served all the same: the audio
/// the caller spoke and the tool calls the upstream opened reach the ledger either way.
#[tokio::test]
async fn an_errored_or_abandoned_turn_still_ledgers_what_it_served() {
    let host = governed_host(None);
    let (core, _drx) = core_on(Some(&host));
    let _ = core.on_client_frame(uplink_audio(1_500));
    let _ = core.on_server_frame(call_opened("call_1")).await;
    let error = wire(serde_json::json!({
        "type": "error",
        "error": { "type": "server_error", "code": "boom", "message": "upstream failed" },
    }));
    let _ = core.on_server_frame(error).await;
    assert_eq!(
        rows(&host),
        row_set(&[("audio_seconds_in", 2), ("tool_calls", 1)]),
        "an error-ended turn ledgers its own counts (1.5 s rounds up to 2)"
    );
    let _ = core.on_client_frame(uplink_audio(400));
    core.settle_open_turn();
    assert_eq!(
        rows(&host)["audio_seconds_in"],
        3,
        "the teardown settles the open turn"
    );
    core.settle_open_turn();
    assert_eq!(rows(&host)["audio_seconds_in"], 3, "and settles it once");
}

/// THE HARD CLOSE (the marquee guarantee), now the kernel's count-based check: the turn that dries
/// the caller's chain is delivered and ledgered, and the verdict cancels the in-flight response and
/// closes the carrier. Replaces `settle_past_cap_hard_closes_the_carrier` (the D2 lease).
#[tokio::test]
async fn a_turn_that_dries_the_chain_hard_closes_the_carrier() {
    // A chain of 5 counts; each usage frame ledgers 3.
    let (core, mut drx) = core_with_downlink(Some(5));

    let plan = core.on_server_frame(usage_frame(3)).await;
    assert!(!plan.close, "3 of 5: no hard close");
    assert!(!core.carrier().is_closed());

    let plan = core.on_server_frame(usage_frame(3)).await;
    assert!(plan.close, "6 of 5: the frame plan demands a hard close");
    assert!(
        plan.upstream
            .iter()
            .any(|w| String::from_utf8_lossy(&w.0).contains("response.cancel")),
        "a dry chain cancels the in-flight response upstream"
    );
    assert!(core.carrier().is_closed(), "the carrier hard-closed");

    let plan = core.on_server_frame(audio_delta("AAAA")).await;
    assert!(plan.downlink.is_empty(), "closed carrier processes nothing");
    assert!(
        !core.carrier().send_downlink(vec![1, 2, 3]),
        "the carrier drops downlink after hard close"
    );
    drx.close();
    assert!(
        drx.next().await.is_none(),
        "no downlink audio leaked to the client"
    );
}

/// The chain a turn meets is the LIVE one: spend the key takes elsewhere between two turns counts,
/// which the lease's once-read cap never saw.
#[tokio::test]
async fn a_chain_dried_elsewhere_closes_the_session_at_its_next_turn() {
    let host = governed_host(None);
    let (core, _drx) = core_on(Some(&host));
    assert!(!core.on_server_frame(usage_frame(1)).await.close);
    host.set_budget_chain(vec![busbar_contract::hooks::BudgetBucketState {
        bucket_id: "group:g@day".to_string(),
        budget_group: Some("g".to_string()),
        pool: None,
        spend_micros_at_current_rate: 10_000,
        remaining_micros: Some(0),
        window_start: 0,
        budget_period: "day".to_string(),
    }]);
    assert!(core.on_server_frame(usage_frame(1)).await.close);
}

/// Q21b EXIT TEST (the budget gate) — a key whose chain is already dry is refused at the open; one
/// with room, or with nothing capped, opens; an ungoverned host opens no account at all.
#[test]
fn a_dry_chain_refuses_the_open() {
    let open = |host: Arc<FixtureHost>| {
        TurnMeter::new(host, caller(), "voice-server", crate::OPENAI_REALTIME)
            .open("gpt-realtime")
            .map(|m| m.is_some())
    };
    assert!(
        open(governed_host(Some(0))).is_err(),
        "a spent chain refuses"
    );
    assert_eq!(open(governed_host(Some(1))), Ok(true), "room opens");
    assert_eq!(open(governed_host(None)), Ok(true), "uncapped opens");
    assert_eq!(
        open(Arc::new(FixtureHost::new())),
        Ok(false),
        "an ungoverned host opens no account"
    );
    // A pool-scoped bucket for another pool does not govern this one.
    let other_pool = FixtureHost::new().governed().with_budget_chain(vec![
        busbar_contract::hooks::BudgetBucketState {
            bucket_id: "group:g@day#other-pool".to_string(),
            budget_group: Some("g".to_string()),
            pool: Some("other-pool".to_string()),
            spend_micros_at_current_rate: 1,
            remaining_micros: Some(0),
            window_start: 0,
            budget_period: "day".to_string(),
        },
    ]);
    assert_eq!(open(Arc::new(other_pool)), Ok(true));
}

/// A turn on an ungoverned session ledgers nothing and is never closed on budget.
#[tokio::test]
async fn an_ungoverned_session_is_never_closed_on_budget() {
    let (core, _drx) = core_with_downlink(None);
    for _ in 0..3 {
        assert!(!core.on_server_frame(usage_frame(u64::MAX / 4)).await.close);
    }
    let _ = TurnVerdict::Live;
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
    let b64 = busbar_contract::media::base64_encode(&Bytes::from(payload));
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
        busbar_kernel::plane_host::SessionScope::new(Arc::clone(engine), "mallory", "s").get()
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

/// The node's table, as the runtime is allowed to see it: which identifiers are open (entered as the
/// runtime plans them), and a sweep.
#[derive(Debug, Default)]
struct TableFake {
    sessions: std::sync::Mutex<std::collections::BTreeMap<u64, Vec<String>>>,
}

impl crate::runtime::GovernedCalls for TableFake {
    fn planned(&self, session: u64, call_id: &str, _now_ms: u64) -> bool {
        let mut s = self.sessions.lock().unwrap();
        s.entry(session).or_default().push(call_id.to_string());
        true
    }

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
        s.values_mut().map(|open| open.drain(..).count()).sum()
    }
}

/// A core bound to `table` as session 7, serving only the tool `local`.
fn governed_core(table: Arc<TableFake>) -> Arc<SessionCore<OpenAiRealtimeCodec>> {
    let (dtx, _drx) = unbounded::<Vec<u8>>();
    Arc::new(
        SessionCore::new(
            OpenAiRealtimeCodec,
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
        wire(
            serde_json::json!({"type":"response.function_call_arguments.delta",
            "call_id":call_id,"delta":"{}"}),
        ),
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
    table
        .sessions
        .lock()
        .unwrap()
        .insert(7, vec!["cr".to_string()]);
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
    table
        .sessions
        .lock()
        .unwrap()
        .insert(7, vec!["cr".to_string()]);
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
    table
        .sessions
        .lock()
        .unwrap()
        .insert(7, vec!["cr".to_string()]);

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

/// **The tick actually runs, and it ends with the pump.**
///
/// `sweep_expired` is the sweep; this is whether anything on a served session ever calls it. A wait
/// nobody sweeps is a hold nobody settles, and a client that never replies sends no frame on which
/// anyone would notice — so time passing has to be the event, and it has to stop being one when the
/// conversation does.
/// Real time rather than a paused clock: pausing needs tokio's `test-util`, and shipping a test
/// feature into the runtime build to make one assertion cheaper is a worse trade than a slow test.
#[tokio::test]
async fn the_sweep_rides_the_pump_and_ends_with_it() {
    let table = Arc::new(TableFake::default());
    let core = governed_core(Arc::clone(&table));
    table
        .sessions
        .lock()
        .unwrap()
        .insert(7, vec!["cr".to_string()]);

    // A pump that runs past one tick and then returns, exactly as a socket closing would.
    //
    // THE MARGIN IS THE POINT. `SWEEP_EVERY` is one second and this is real time, not a paused
    // clock, so the pump has to outlive the tick by enough that a loaded CI runner's scheduler
    // jitter cannot land the tick after the pump returns — 400 ms of headroom was not enough, and
    // the failure would have read as "the sweep does not run" rather than "the box was busy".
    let pump = tokio::time::sleep(std::time::Duration::from_millis(2_500));
    crate::runtime::serve_with_sweep(Arc::clone(&core), pump).await;

    assert!(
        table.sessions.lock().unwrap()[&7].is_empty(),
        "the tick beside the pump swept the call nobody answered"
    );

    // And once the pump is gone so is the tick: a fresh call opened afterwards is swept by nobody.
    table
        .sessions
        .lock()
        .unwrap()
        .insert(7, vec!["cs".to_string()]);
    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    assert_eq!(
        table.sessions.lock().unwrap()[&7],
        vec!["cs".to_string()],
        "a sweep that outlived its session would be the background loop this plane does not have"
    );
}

/// A HARD CLOSE THAT LANDS WHILE THE SUPERVISOR IS ARRIVING AT THE GATE STILL WAKES IT.
///
/// The topology's teardown `select!` parks one arm on `Carrier::closed()`, and that await is the only
/// thing that turns a dry budget into a torn-down session. The gate's wake reaches the waiters that
/// are registered when it fires and stores nothing for one that registers a moment later — so a close
/// racing the supervisor's arrival is the one ordering in which the marquee guarantee can be dropped
/// on the floor, and the session runs on to socket EOF instead.
///
/// Driven as a race rather than a sequence, because the window is between two instructions and no
/// sequential ordering can enter it: each round starts a fresh carrier, hands it to a thread that
/// closes it immediately, and demands the await finish. A run that parks forever is the defect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_racing_the_supervisors_arrival_still_wakes_it() {
    for round in 0..2_000 {
        let carrier = Carrier::sideband();
        let closer = carrier.clone();
        std::thread::spawn(move || {
            closer.hard_close();
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), carrier.closed())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "round {round}: the carrier hard-closed and the supervisor never woke — a \
                     session whose budget is dry that nothing tears down"
                )
            });
    }
}

// ── Item 137: a voice session's durable row is settled, never leaked ACTIVE ─────────────────────

/// The retention sweep ABANDONS an idle ACTIVE session terminal, and a later sweep evicts it.
///
/// The session's own `open` opted OUT of the sweep (`|_, _, _, _| None`), and the cap rule evicts
/// only terminal rows, so a session whose teardown never ran stayed ACTIVE in the working set for
/// ever. Any later session's open is what claims the sweep.
#[test]
fn an_idle_voice_session_is_abandoned_terminal_then_evicted() {
    let engine = Arc::new(DurableHandleEngine::new());
    let idle = SessionHandle::bind(Arc::clone(&engine), "alice", "call-idle");
    idle.open(1).expect("the idle session opens");

    // An hour and a bit later another session opens, which claims the retention sweep.
    let later = SessionHandle::bind(Arc::clone(&engine), "bob", "call-later");
    later.open(1 + 3_600 + 2).expect("a later session opens");
    assert_eq!(
        idle.get().map(|row| row.terminal),
        Some(true),
        "a session idle past the abandon bound is settled terminal by the sweep"
    );

    // And a terminal-TTL later still, a third open evicts it.
    let third = SessionHandle::bind(Arc::clone(&engine), "carol", "call-third");
    third
        .open(1 + 3_600 + 2 + 3_600 + 2)
        .expect("a third session opens");
    assert!(
        idle.get().is_none(),
        "the abandoned session leaves the working set"
    );
}

/// A served session's pump returning settles its durable row terminal and evicts it.
#[tokio::test]
async fn serving_a_session_to_its_teardown_settles_and_evicts_its_row() {
    let rt = VoiceRuntimeFixture::runtime();
    let (core, handle) = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-served",
        None,
        Carrier::sideband(),
        None,
        1,
    )
    .expect("the session opens");
    crate::runtime::serve_to_teardown(core, handle, async {}, || 2).await;
    assert!(
        SessionHandle::bind(Arc::clone(&rt.engine), "acct-1", "call-served")
            .get()
            .is_none(),
        "the served session's row is settled and evicted when its pump returns"
    );
}

/// OWNER RULING Q21a — NO CONFIG, NO LIMIT. A runtime whose operator configured no
/// `streams.session_max_secs` binds no ceiling, so a session that has run far past the hour the
/// retired default cut at is still open. (The test clock is the `now` handed to the comparison.)
#[test]
fn an_unconfigured_session_is_never_cut_by_a_ceiling() {
    let rt = VoiceRuntimeFixture::runtime();
    assert_eq!(
        rt.session_max_secs, None,
        "nothing configured, nothing bound"
    );
    let (core, _handle) = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-unbounded",
        None,
        Carrier::sideband(),
        None,
        1,
    )
    .expect("the session opens");
    let much_later = std::time::Instant::now() + std::time::Duration::from_secs(3_600 * 5);
    assert!(
        !core.enforce_ceiling(much_later),
        "five hours in, an unconfigured session is not closed"
    );
    assert!(!core.carrier().is_closed());
}

/// Q21a — A CONFIGURED ceiling closes the session at the limit, with the dialect's own error frame
/// under the named reason, and the turn it cut is settled with the session.
///
/// The ceiling was once declared, defaulted, parsed and plumbed onto the runtime and then compared
/// with nothing; it is compared, and only when configured.
#[tokio::test]
async fn a_configured_ceiling_closes_the_session_and_settles_its_counts() {
    let mut rt = VoiceRuntimeFixture::runtime();
    rt.session_max_secs = std::num::NonZeroU32::new(1);
    let host = governed_host(None);
    let (dtx, mut drx) = unbounded::<Vec<u8>>();
    let (core, handle) = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-long",
        None,
        Carrier::with_downlink(dtx),
        Some(TurnMeter::new(
            Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
            caller(),
            "voice-server",
            crate::OPENAI_REALTIME,
        )),
        1,
    )
    .expect("the session opens");
    let _ = core.on_client_frame(uplink_audio(2_000));
    // A pump that never ends on its own: only the ceiling can end this session.
    let served = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::runtime::serve_to_teardown(
            Arc::clone(&core),
            handle,
            futures::future::pending::<()>(),
            || 2,
        ),
    )
    .await;
    assert!(
        served.is_ok(),
        "a one-second ceiling ends the session well inside five seconds"
    );
    assert!(core.carrier().is_closed(), "the ceiling closes the carrier");
    drx.close();
    let told: Vec<serde_json::Value> = drx
        .collect::<Vec<_>>()
        .await
        .iter()
        .map(|f| serde_json::from_slice(f).expect("a json frame"))
        .collect();
    assert!(
        told.iter().any(|v| v["type"] == "error"
            && v["error"]["code"] == crate::runtime::session::SESSION_CEILING_REASON),
        "the client is told why, in its dialect's own error frame: {told:?}"
    );
    assert_eq!(
        rows(&host),
        row_set(&[("audio_seconds_in", 2)]),
        "the turn the ceiling cut is settled with the session"
    );
}

/// The runtime these three cells open sessions on.
struct VoiceRuntimeFixture;
impl VoiceRuntimeFixture {
    fn runtime() -> crate::runtime::VoiceRuntime {
        crate::runtime::VoiceRuntime::new(
            Arc::new(DurableHandleEngine::new()),
            Arc::new(crate::runtime::tools::EchoToolExecutor),
        )
    }
}
