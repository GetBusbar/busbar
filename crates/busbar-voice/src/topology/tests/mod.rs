// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TOPOLOGY TESTS (behind `runtime`): the telephony proxy relays both ways over in-memory sockets and
//! tears down on hard-close; the WebRTC sideband mints a token, governs the locked config, and relays
//! NO media (media is peer-to-peer).

use crate::ir::codec::OpenAiRealtimeCodec;
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::{HostMeteringPort, MockMeteringHost};
use crate::runtime::VoiceRuntime;
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::webrtc::{attach, EphemeralToken, MintError, TokenMinter};
use crate::topology::SessionBudget;
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane_host::MeteringHost;
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use std::sync::Arc;
// Test-support-only: the guarded provider-dial battery (dial_provider through the net-guard) and its
// loopback EchoProvider. These symbols are used ONLY by the `#[cfg(feature = "test-support")]` dial
// tests, so gate the imports to match — otherwise a `runtime`-without-`test-support` build (the
// workspace clippy default now that voice ships default-on) sees them as unused.
#[cfg(feature = "test-support")]
use crate::topology::dial_provider;
#[cfg(feature = "test-support")]
use busbar_substrate::ingress::byte_duplex::{CallRef, DuplexHandle, DuplexPlane};
#[cfg(feature = "test-support")]
use busbar_substrate::ingress::duplex_ws as ws_ingress;
#[cfg(feature = "test-support")]
use busbar_substrate::net_guard::GuardPolicy;
#[cfg(feature = "test-support")]
use futures::SinkExt;

fn runtime() -> VoiceRuntime {
    // The PRODUCTION money hop: a host lease + host pricing over the mock host (prices every reserved
    // unit at 1 nano), so metering is real over both topologies.
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(HostMeteringPort::new(host)),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
    )
}

fn json_frame(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}

// ── Topology B: the thin telephony proxy relays both directions ─────────────────────────────────

#[tokio::test]
async fn telephony_proxy_relays_both_directions() {
    let rt = runtime();
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    };
    // g711 end-to-end: 8 kHz µ-law passes straight through, no resample.
    let cfg = g711_config();
    assert_eq!(
        cfg.output_audio_format,
        Some(crate::ir::media::AudioFormat::G711Ulaw)
    );
    let proxy = begin_telephony(&rt, OpenAiRealtimeCodec, "acct-1", "call-9", cfg, budget, 1)
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
        out.emit(frame).await;
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
/// `test-support` because the governed dial now rides the breaker beneath it, reached through a real
/// `EngineHost` double over a bare app.
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
    let app = busbar_core::test_support::TestApp::new().build();
    let host = busbar_core::plane_host::engine_host(&app);
    let pool = crate::topology::stream_breaker_key("openai-realtime");
    let (mut stream, mut sink) = dial_provider(host.as_ref(), &pool, 0, &url, policy)
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
    let app = busbar_core::test_support::TestApp::new().build();
    let host = busbar_core::plane_host::engine_host(&app);
    let pool = crate::topology::stream_breaker_key("openai-realtime");
    assert!(
        dial_provider(
            host.as_ref(),
            &pool,
            0,
            "wss://127.0.0.1/",
            GuardPolicy::default()
        )
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
    let budget = SessionBudget {
        estimate_nanos: 500,
        fee_nanos: 10,
        cap_nanos: Some(3),
    };

    let attached = attach(
        &rt,
        &minter,
        OpenAiRealtimeCodec,
        "acct-2",
        "call-42",
        locked,
        budget,
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

    // Metering is real over the sideband too: settle past the cap of 3 hard-closes.
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
    // denied upstream destination is refused BEFORE the lease/durable open — zero bytes, zero charge.
    let host = Arc::new(MockMeteringHost::default());
    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(HostMeteringPort::new(
            Arc::clone(&host) as Arc<dyn MeteringHost>
        )),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
    )
    .with_denied_destinations(["blocked-model"]);
    let locked = SessionConfig {
        model: Some("blocked-model".into()),
        ..SessionConfig::default()
    };
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: Some(10_000),
    };
    let started = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-denied",
        Some(locked),
        Carrier::sideband(),
        budget,
        1,
    );
    assert!(
        matches!(
            started,
            Err(crate::topology::StartError::DestinationRefused)
        ),
        "a denied destination is refused at the open-pass gate"
    );
    // The refusal landed BEFORE any charge: NO lease was ever minted (open_lease never ran).
    assert_eq!(
        host.minted_count(),
        0,
        "a refused session opens no lease — zero bytes, zero charge"
    );

    // A NON-denied destination on the same runtime proceeds past the gate and DOES open a lease.
    let ok_cfg = SessionConfig {
        model: Some("allowed-model".into()),
        ..SessionConfig::default()
    };
    let (_core, _handle, _guard) = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-ok",
        Some(ok_cfg),
        Carrier::sideband(),
        budget,
        1,
    )
    .expect("an allowed destination opens the session");
    assert_eq!(
        host.minted_count(),
        1,
        "the admitted session opened exactly one lease past the gate"
    );
}

// ── THE D2 LEASE-LEAK WITNESS: the by-value close guard releases the reserve on abnormal close ───────

#[test]
fn abnormal_close_releases_the_reserve_via_the_by_value_guard() {
    // The session-drop leak (§SEAM 1): a per-frame handler PARKED at an `.await` during the hard-close
    // race keeps an `Arc<SessionCore>` alive detached, so the settle handle's own refcount-gated `Drop`
    // close NEVER fires while that clone lives — the reserve LEAKS. The by-value `LeaseCloseGuard` the
    // topology `run()` frame owns is DECOUPLED from that refcount: it closes the lease deterministically
    // the instant it drops on run() exit. This drives that exact decoupling: a pinned `Arc<SessionCore>`
    // stands in for the parked handler.
    let host = Arc::new(MockMeteringHost::default());
    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(HostMeteringPort::new(
            Arc::clone(&host) as Arc<dyn MeteringHost>
        )),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
    );
    let budget = SessionBudget {
        estimate_nanos: 100,
        fee_nanos: 0,
        cap_nanos: Some(1_000),
    };
    // begin_session hands back the core, the durable handle, AND the by-value close guard the topology
    // run() frame owns. A sideband carrier keeps the fixture minimal (no downlink plumbing).
    let (core, _handle, guard) = crate::topology::begin_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-leak",
        None,
        Carrier::sideband(),
        budget,
        1,
    )
    .expect("session begins");
    assert_eq!(
        host.closed_ids(),
        Vec::<u64>::new(),
        "no close before teardown"
    );

    // Pin an `Arc<SessionCore>` clone — the parked-handler stand-in holding the settle handle (`HostLease`),
    // whose refcount-gated `Drop` close therefore CANNOT fire while the clone lives.
    let pinned = Arc::clone(&core);
    drop(core); // the run() frame's own core ref goes away…
                // …yet the reserve is NOT released: the pinned clone still gates the settle handle's close. THIS is the
                // leak (red state) the guard exists to fix — without a guard, teardown would end here with 0 closes.
    assert_eq!(
        host.closed_ids(),
        Vec::<u64>::new(),
        "the settle handle is refcount-gated by the pinned clone — the reserve would leak"
    );

    // Dropping the by-value guard (exactly as run() does on exit) closes the lease DETERMINISTICALLY,
    // despite the pin — the green state.
    drop(guard);
    assert_eq!(
        host.closed_ids(),
        vec![1],
        "the by-value guard closed the lease exactly once, despite the pinned Arc<SessionCore>"
    );

    // The lingering settle handle's eventual drop is a harmless idempotent second close (no double refund).
    drop(pinned);
    assert_eq!(
        host.closed_ids(),
        vec![1],
        "the lingering settle handle's later close is a harmless no-op (no double refund)"
    );
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

/// THE ORDERING FIX: `attach` runs the gauntlet + D2 lease FIRST and mints the ephemeral secret
/// only past a clean open. A session whose destination the plane denies is refused at the gate BEFORE
/// any mint — so the browser is handed NO `ek_` on a denied session (zero bytes, zero charge, zero
/// credential). RED before the reorder: the mint ran before `begin_session`, so a denied session still
/// minted a secret.
#[tokio::test]
async fn the_gauntlet_refuses_before_the_mint_on_a_denied_destination() {
    let host = Arc::new(MockMeteringHost::default());
    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(HostMeteringPort::new(
            Arc::clone(&host) as Arc<dyn MeteringHost>
        )),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
    )
    .with_denied_destinations(["blocked-model"]);
    let minter = RecordingMinter {
        minted: std::sync::atomic::AtomicBool::new(false),
    };
    let locked = SessionConfig {
        model: Some("blocked-model".into()),
        ..SessionConfig::default()
    };
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    };
    let r = attach(
        &rt,
        &minter,
        OpenAiRealtimeCodec,
        "acct",
        "call-denied",
        locked,
        budget,
        1,
    )
    .await;
    assert!(
        matches!(r, Err(crate::topology::webrtc::AttachError::Start(_))),
        "a denied destination is refused at the open-pass gate before the mint"
    );
    assert!(
        !minter.minted.load(std::sync::atomic::Ordering::SeqCst),
        "NOTHING mints on a refused session — the gauntlet/lease run before the mint"
    );
    assert_eq!(
        host.minted_count(),
        0,
        "no lease opened on the refused session either — zero charge"
    );
}

#[tokio::test]
async fn webrtc_attach_fails_closed_when_mint_fails() {
    let rt = runtime();
    let minter = FakeMinter { fail: true };
    let budget = SessionBudget {
        estimate_nanos: 1,
        fee_nanos: 0,
        cap_nanos: None,
    };
    let r = attach(
        &rt,
        &minter,
        OpenAiRealtimeCodec,
        "acct-3",
        "call-x",
        SessionConfig::default(),
        budget,
        1,
    )
    .await;
    assert!(r.is_err(), "a failed mint refuses the session");
}
