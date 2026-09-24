// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TOPOLOGY TESTS (behind `runtime`): the telephony proxy relays both ways over in-memory sockets and
//! tears down on hard-close; the WebRTC sideband mints a token, governs the locked config, and relays
//! NO media (media is peer-to-peer).

use crate::ir::codec::OpenAiRealtimeCodec;
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::TurnMeter;
use crate::runtime::VoiceRuntime;
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::webrtc::{attach, EphemeralToken, MintError, TokenMinter};
use busbar_kernel::plane::handle_engine::DurableHandleEngine;
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use std::sync::Arc;
// Test-support-only: the guarded provider-dial battery (dial_provider through the net-guard) and its
// loopback EchoProvider. These symbols are used ONLY by the `#[cfg(feature = "test-support")]` dial
// tests, so gate the imports to match — otherwise a `runtime`-without-`test-support` build (the
// workspace clippy default now that voice ships default-on) sees them as unused.
use crate::testkit::fixture_host::FixtureHost;
#[cfg(feature = "test-support")]
use crate::topology::dial_provider;
#[cfg(feature = "test-support")]
use busbar_kernel::ingress::byte_duplex::{CallRef, DuplexHandle, DuplexPlane};
#[cfg(feature = "test-support")]
use busbar_kernel::ingress::duplex_ws as ws_ingress;
#[cfg(feature = "test-support")]
use busbar_kernel::net_guard::GuardPolicy;
#[cfg(feature = "test-support")]
use futures::SinkExt;

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
    )
}

/// A presenting key's meter over a governed fixture host whose budget view is capped at `cap` counts.
fn meter_capped(cap: i64) -> TurnMeter {
    TurnMeter::new(
        Arc::new(FixtureHost::new().governed().with_count_cap(cap)),
        busbar_api::VirtualKey {
            id: "vk".to_string(),
            ..Default::default()
        },
        "voice-server",
        crate::OPENAI_REALTIME,
    )
}

fn json_frame(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}

// ── Topology B: the thin telephony proxy relays both directions ─────────────────────────────────

#[tokio::test]
async fn telephony_proxy_relays_both_directions() {
    let rt = runtime();
    // g711 end-to-end: 8 kHz µ-law passes straight through, no resample.
    let cfg = g711_config();
    assert_eq!(
        cfg.output_audio_format,
        Some(crate::ir::media::AudioFormat::G711Ulaw)
    );
    let proxy = begin_telephony(&rt, OpenAiRealtimeCodec, "acct-1", "call-9", cfg, None, 1)
        .expect("telephony begins");

    let (prov_in_tx, prov_in_rx) = unbounded::<Vec<u8>>();
    let (prov_out_tx, mut prov_out_rx) = unbounded::<Vec<u8>>();
    let (cli_in_tx, cli_in_rx) = unbounded::<Vec<u8>>();
    let (cli_out_tx, mut cli_out_rx) = unbounded::<Vec<u8>>();

    // The provider emits a downlink audio frame → it must reach the client.
    prov_in_tx
        .unbounded_send(json_frame(serde_json::json!({
            "type":"response.output_audio.delta","delta":"AAAA"
        })))
        .unwrap();
    // The client (phone) sends an uplink audio frame → it must reach the provider.
    cli_in_tx
        .unbounded_send(json_frame(serde_json::json!({
            "type":"input_audio_buffer.append","audio":"BBBB"
        })))
        .unwrap();
    // EOF both sockets so the proxy returns cleanly.
    drop(prov_in_tx);
    drop(cli_in_tx);

    proxy
        .run(prov_in_rx, prov_out_tx, cli_in_rx, cli_out_tx)
        .await;

    // Downlink: the client received the provider's audio.
    cli_out_rx.close();
    let mut downlink = Vec::new();
    while let Some(f) = cli_out_rx.next().await {
        let v: serde_json::Value = serde_json::from_slice(&f).unwrap();
        downlink.push(v["type"].as_str().unwrap().to_string());
    }
    assert!(
        downlink.contains(&"response.output_audio.delta".to_string()),
        "provider downlink audio reached the client: {downlink:?}"
    );

    // Uplink: the provider received the client's forwarded audio append.
    prov_out_rx.close();
    let mut uplink = Vec::new();
    while let Some(f) = prov_out_rx.next().await {
        let v: serde_json::Value = serde_json::from_slice(&f).unwrap();
        uplink.push(v["type"].as_str().unwrap().to_string());
    }
    assert!(
        uplink.contains(&"input_audio_buffer.append".to_string()),
        "client uplink audio reached the provider: {uplink:?}"
    );
}

/// Item 137: a telephony call that ends settles its durable row terminal and evicts it. The proxy
/// used to bind its handle as `_handle` and drop it unsettled, so every call's row stayed ACTIVE in
/// the working set after both sockets were gone.
#[tokio::test]
async fn a_finished_telephony_call_settles_and_evicts_its_durable_row() {
    let rt = runtime();
    let proxy = begin_telephony(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-ended",
        g711_config(),
        None,
        1,
    )
    .expect("telephony begins");
    let (prov_in_tx, prov_in_rx) = unbounded::<Vec<u8>>();
    let (prov_out_tx, _prov_out_rx) = unbounded::<Vec<u8>>();
    let (cli_in_tx, cli_in_rx) = unbounded::<Vec<u8>>();
    let (cli_out_tx, _cli_out_rx) = unbounded::<Vec<u8>>();
    // Both sockets end at once: the call is over.
    drop(prov_in_tx);
    drop(cli_in_tx);
    proxy
        .run(prov_in_rx, prov_out_tx, cli_in_rx, cli_out_tx)
        .await;
    assert!(
        crate::runtime::SessionHandle::bind(Arc::clone(&rt.engine), "acct-1", "call-ended")
            .get()
            .is_none(),
        "the ended call's durable row is settled terminal and evicted"
    );
}

// ── The provider WSS dials THROUGH the neutral guarded transport (HARD RULE 3) ───────────────────

/// A loopback echo "provider" served over the neutral WS ingress acceptor — stands in for the Realtime
/// upstream so the plane's `dial_provider` can be driven end to end without a network. Test-support-only
/// (the guarded-dial battery it feeds is `#[cfg(feature = "test-support")]`).
#[cfg(feature = "test-support")]
struct EchoProvider;

#[cfg(feature = "test-support")]
#[async_trait::async_trait]
impl DuplexPlane for EchoProvider {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        // The echo is what these tests observe, so a write that did not land is reported rather
        // than read later as a frame the provider never sent.
        if let Err(e) = out.emit(frame).await {
            eprintln!("echo provider: the frame could not be written: {e}");
        }
    }
}

#[cfg(feature = "test-support")]
async fn spawn_echo_provider() -> std::net::SocketAddr {
    async fn route(upgrade: axum::extract::ws::WebSocketUpgrade) -> axum::response::Response {
        ws_ingress::serve(upgrade, Arc::new(EchoProvider))
    }
    let app = axum::Router::new().route("/", axum::routing::get(route));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// The plane SELECTS `Transport::WebSocket` and lets the substrate open the socket: `dial_provider`
/// dials the loopback provider THROUGH the net-guard and a frame crosses both directions. This is the
/// plane using the neutral transport instead of carrying its own socket plumbing. Gated on
/// `test-support` because the governed dial now rides the breaker beneath it, reached through the
/// substrate's in-memory fixture host.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn dial_provider_routes_through_the_guarded_ws_transport() {
    let addr = spawn_echo_provider().await;
    let url = format!("ws://{addr}/");
    let policy = GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    };
    let host = FixtureHost::new();
    let pool = crate::topology::stream_breaker_key("openai-realtime");
    let (mut stream, mut sink) = dial_provider(&host, &pool, 0, &url, policy)
        .await
        .expect("the plane dials the provider through the guarded transport");
    sink.send(b"realtime-frame".to_vec()).await.ok();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a reply arrived")
        .expect("the stream yielded a frame");
    assert_eq!(
        got, b"realtime-frame",
        "a frame crossed the guarded WS both ways"
    );
}

/// The provider dial FAILS CLOSED on a guard-failing target — the plane never opens a socket the
/// net-guard did not pin (the egress-audit finding this closes).
#[cfg(feature = "test-support")]
#[tokio::test]
async fn dial_provider_fails_closed_on_a_guarded_target() {
    // A public loopback under the fail-closed default is an internal address — refused, no socket.
    let host = FixtureHost::new();
    let pool = crate::topology::stream_breaker_key("openai-realtime");
    assert!(
        dial_provider(&host, &pool, 0, "wss://127.0.0.1/", GuardPolicy::default())
            .await
            .is_err(),
        "the provider dial must refuse an unpinned/guard-failing target"
    );
}

// ── Topology A: the WebRTC sideband mints a token and relays no media ────────────────────────────

struct FakeMinter {
    fail: bool,
}

#[async_trait::async_trait]
impl TokenMinter for FakeMinter {
    async fn mint(&self, config: &SessionConfig) -> Result<EphemeralToken, MintError> {
        if self.fail {
            return Err(MintError::Provider("endpoint down".into()));
        }
        // The minted secret is scoped to the SAME locked config busbar governs.
        assert_eq!(config.instructions.as_deref(), Some("be helpful"));
        Ok(EphemeralToken {
            value: "ek_test_secret".into(),
            expires_at_unix: 9_999,
        })
    }
}

#[tokio::test]
async fn webrtc_sideband_mints_token_locks_config_and_relays_no_media() {
    let rt = runtime();
    let minter = FakeMinter { fail: false };
    let mut locked = SessionConfig {
        instructions: Some("be helpful".into()),
        ..SessionConfig::default()
    };
    locked.tools = vec![serde_json::json!({"type":"function","name":"lookup"})];

    let attached = attach(
        &rt,
        &minter,
        OpenAiRealtimeCodec,
        "acct-2",
        "call-42",
        locked,
        Some(meter_capped(3)),
        1,
    )
    .await
    .expect("sideband attaches");

    assert_eq!(attached.token.value, "ek_test_secret");
    // The sideband carrier relays NO media (the browser's media path is peer-to-peer).
    assert!(
        !attached.core.carrier().send_downlink(vec![1, 2, 3]),
        "sideband relays no downlink media"
    );

    // Metering is real over the sideband too: a turn that dries a chain of 3 hard-closes.
    let usage = crate::ir::codec::WireEvent(bytes::Bytes::from(json_frame(serde_json::json!({
        "type":"response.done",
        "response": { "usage": { "output_token_details": { "audio_tokens": 5 } } },
    }))));
    let plan = attached.core.on_server_frame(usage).await;
    assert!(plan.close, "sideband session hard-closes on exhaustion");
    assert!(attached.core.carrier().is_closed());
}

// ── D3 CALL-SITE WITNESS: begin_session runs run_gauntlet_session at the TOP (refuse ⇒ zero charge) ──

#[test]
fn begin_session_refuses_a_denied_destination_before_any_charge() {
    // The D3 call-site witness: `begin_session` ACTUALLY calls `run_gauntlet_session` at the top, so a
    // denied upstream destination is refused BEFORE the kernel account's budget check — the caller
    // below has a dry chain, and the answer is still the destination refusal, not the budget one.
    let rt = runtime().with_denied_destinations(["blocked-model"]);
    let locked = SessionConfig {
        model: Some("blocked-model".into()),
        ..SessionConfig::default()
    };
    let started = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-denied",
        Some(locked),
        Carrier::sideband(),
        Some(meter_capped(0)),
        1,
    );
    assert!(
        matches!(
            started,
            Err(crate::topology::StartError::DestinationRefused)
        ),
        "a denied destination is refused at the open-pass gate, before the budget is asked"
    );

    // A NON-denied destination proceeds past the gate to the budget check: a dry chain is refused
    // there, and a chain with room opens.
    let ok_cfg = SessionConfig {
        model: Some("allowed-model".into()),
        ..SessionConfig::default()
    };
    let open = |call: &str, cap| {
        crate::topology::begin_session(
            &rt,
            OpenAiRealtimeCodec,
            "acct",
            call,
            Some(ok_cfg.clone()),
            Carrier::sideband(),
            Some(meter_capped(cap)),
            1,
        )
    };
    assert!(matches!(
        open("call-dry", 0),
        Err(crate::topology::StartError::BudgetRefused)
    ));
    assert!(
        open("call-ok", 10).is_ok(),
        "an allowed destination with room opens"
    );
}

// ── A SESSION HOLDS NOTHING OPEN (the D2 lease-leak witness, retired with the lease) ─────────────────

/// The lease this replaced held a reserve that only a by-value guard could release when a parked
/// handler pinned the core. A session now holds no reserve at all: each turn's counts reach the ledger
/// as the turn closes, so a pinned core has nothing left to release and nothing waits on its drop.
#[tokio::test]
async fn a_pinned_core_holds_nothing_open() {
    let host = Arc::new(FixtureHost::new().governed());
    let meter = TurnMeter::new(
        Arc::clone(&host) as Arc<dyn busbar_kernel::plane_host::EngineHost>,
        busbar_api::VirtualKey {
            id: "vk-pin".to_string(),
            ..Default::default()
        },
        "voice-server",
        crate::OPENAI_REALTIME,
    );
    let (core, _handle) = crate::topology::begin_session(
        &runtime(),
        OpenAiRealtimeCodec,
        "acct",
        "call-pin",
        None,
        Carrier::sideband(),
        Some(meter),
        1,
    )
    .expect("session begins");
    let usage = crate::ir::codec::WireEvent(bytes::Bytes::from(json_frame(serde_json::json!({
        "type":"response.done",
        "response": { "usage": { "output_token_details": { "audio_tokens": 4 } } },
    }))));
    let _ = core.on_server_frame(usage).await;
    let pinned = Arc::clone(&core);
    drop(core);
    assert_eq!(
        host.ledger_usage("vk-pin").map(|u| u.tokens),
        Some(4),
        "the turn is ledgered as it closed — nothing waits on the core's drop"
    );
    drop(pinned);
    assert_eq!(host.ledger_usage("vk-pin").map(|u| u.tokens), Some(4));
}

/// A minter that RECORDS whether it was ever asked to mint — the witness for the ordering fix: on a
/// refused governed open NOTHING may mint.
struct RecordingMinter {
    minted: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl TokenMinter for RecordingMinter {
    async fn mint(&self, _config: &SessionConfig) -> Result<EphemeralToken, MintError> {
        self.minted.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(EphemeralToken {
            value: "ek_should_never_be_minted".into(),
            expires_at_unix: 1,
        })
    }
}

/// THE ORDERING FIX: `attach` runs the gauntlet + the budget check FIRST and mints the ephemeral secret
/// only past a clean open. A session whose destination the plane denies is refused at the gate BEFORE
/// any mint — so the browser is handed NO `ek_` on a denied session (zero bytes, zero charge, zero
/// credential). RED before the reorder: the mint ran before `begin_session`, so a denied session still
/// minted a secret.
#[tokio::test]
async fn the_gauntlet_refuses_before_the_mint_on_a_denied_destination() {
    let rt = runtime().with_denied_destinations(["blocked-model"]);
    let minter = RecordingMinter {
        minted: std::sync::atomic::AtomicBool::new(false),
    };
    let locked = SessionConfig {
        model: Some("blocked-model".into()),
        ..SessionConfig::default()
    };
    let r = attach(
        &rt,
        &minter,
        OpenAiRealtimeCodec,
        "acct",
        "call-denied",
        locked,
        Some(meter_capped(0)),
        1,
    )
    .await;
    assert!(
        matches!(
            r,
            Err(crate::topology::webrtc::AttachError::Start(
                crate::topology::StartError::DestinationRefused
            ))
        ),
        "a denied destination is refused at the open-pass gate, before the mint and the budget"
    );
    assert!(
        !minter.minted.load(std::sync::atomic::Ordering::SeqCst),
        "NOTHING mints on a refused session — the gauntlet runs before the mint"
    );
}

#[tokio::test]
async fn webrtc_attach_fails_closed_when_mint_fails() {
    let rt = runtime();
    let minter = FakeMinter { fail: true };
    let r = attach(
        &rt,
        &minter,
        OpenAiRealtimeCodec,
        "acct-3",
        "call-x",
        SessionConfig::default(),
        None,
        1,
    )
    .await;
    assert!(r.is_err(), "a failed mint refuses the session");
}
