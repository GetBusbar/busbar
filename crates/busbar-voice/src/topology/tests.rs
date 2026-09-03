// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TOPOLOGY TESTS (behind `runtime`): the telephony proxy relays both ways over in-memory sockets and
//! tears down on hard-close; the WebRTC sideband mints a token, governs the locked config, and relays
//! NO media (media is peer-to-peer).

use crate::ir::codec::OpenAiRealtimeCodec;
use crate::ir::config::SessionConfig;
use crate::runtime::metering::{LocalMeteringPort, Pricing};
use crate::runtime::VoiceRuntime;
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::webrtc::{attach, EphemeralToken, MintError, TokenMinter};
use crate::topology::{dial_provider, SessionBudget};
use busbar_substrate::ingress::byte_duplex::{CallRef, DuplexHandle, DuplexPlane};
use busbar_substrate::ingress::duplex_ws as ws_ingress;
use busbar_substrate::net_guard::GuardPolicy;
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use futures::channel::mpsc::unbounded;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
        Pricing {
            audio_in_nanos: 1,
            audio_out_nanos: 1,
            text_in_nanos: 1,
            text_out_nanos: 1,
            cached_nanos: 1,
        },
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
/// upstream so the plane's `dial_provider` can be driven end to end without a network.
struct EchoProvider;

#[async_trait::async_trait]
impl DuplexPlane for EchoProvider {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        out.emit(frame).await;
    }
}

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
/// plane using the neutral transport instead of carrying its own socket plumbing.
#[tokio::test]
async fn dial_provider_routes_through_the_guarded_ws_transport() {
    let addr = spawn_echo_provider().await;
    let url = format!("ws://{addr}/");
    let policy = GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    };
    let (mut stream, mut sink) = dial_provider(&url, policy)
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
#[tokio::test]
async fn dial_provider_fails_closed_on_a_guarded_target() {
    // A public loopback under the fail-closed default is an internal address — refused, no socket.
    assert!(
        dial_provider("wss://127.0.0.1/", GuardPolicy::default())
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
