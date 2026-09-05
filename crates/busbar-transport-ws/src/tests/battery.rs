// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ws transport battery: the upgrade path, byte-exact round trip, half-close (the WS closing
//! handshake), cancel mid-frame, backpressure, K writers and honest frame meta.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use busbar_contract::wire::{CloseReason, Direction, TransportError};
use busbar_contract::{ArenaBytes, StreamId, Transport};

use crate::WsTransport;

/// Build a connected pair of live WS connections over an in-memory duplex — one performs the
/// server handshake role, the other the client role, exactly as `accept`/`dial` would over a real
/// socket. This is the exact seam a real `tcp`/`tls`/`http` transport would hand this crate a
/// connection through once composed (see the crate's own report).
async fn pair(t: &WsTransport, cap: usize) -> (busbar_contract::wire::Conn, busbar_contract::wire::Conn) {
    let (end_a, end_b) = tokio::io::duplex(cap);
    let server = t.handshake_over(end_a, true, "peer-a");
    let client = t.handshake_over(end_b, false, "peer-b");
    let (server, client) = tokio::join!(server, client);
    (server.unwrap(), client.unwrap())
}

#[tokio::test]
async fn upgrade_then_round_trip_byte_exact() {
    let t = WsTransport::new();
    // The handshake succeeding at all IS the upgrade path (`Unit0Trigger::Upgrade`): a peer that
    // is not speaking the WS opening handshake never produces a connection.
    let (a, b) = pair(&t, 64 * 1024).await;

    let payload = b"the quick brown fox \xE2\x9C\x93".to_vec();
    let n = t.write(&a, StreamId(0), ArenaBytes::new(&payload)).await.unwrap();
    assert_eq!(n, payload.len());

    let mut frames = t.frames(b);
    let (stream, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(stream, StreamId(0));
    assert_eq!(frame.direction, Direction::Inbound);
    assert_eq!(frame.bytes.as_slice(), payload.as_slice(), "byte-exact");
    assert_eq!(frame.meta.bytes, payload.len() as u64, "honest frame meta");
    assert_eq!(frame.meta.transport_units, None);
    assert_eq!(frame.meta.status, None, "no status leg after the upgrade");
}

/// The in-band `http` → `ws` upgrade, driven through the seam the design names: `http` accepts the
/// connection, `ws` adopts the stream it gives up, and the handshake runs on the layer that speaks
/// it. The facts of the pre-upgrade layer do not survive it — `http` no longer knows the connection
/// — and the composed chain the adopted connection reports is the real one, not a name for itself.
#[tokio::test]
async fn an_in_band_upgrade_over_http_with_cleared_facts() {
    let http = Arc::new(busbar_transport_http::HttpTransport::new(
        busbar_transport_http::ClientSettings::default(),
    ));
    let ws = Arc::new(WsTransport::new());
    let keys = test_key_handle();
    let listener = http
        .listen(&HttpCfg("127.0.0.1:0".to_string()), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();

    let upgrade_task = {
        let (http, ws, keys) = (http.clone(), ws.clone(), test_key_handle());
        tokio::spawn(async move {
            let http_conn = http.accept(&listener).await.unwrap();
            let before = http.arrival(&http_conn).transport_chain;
            let upgraded = ws.adopt(&*http, http_conn.clone(), &keys).await.unwrap();
            (before, http.arrival(&http_conn), upgraded)
        })
    };

    let client_t = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    let url: &'static str = Box::leak(format!("ws://{addr}/duplex").into_boxed_str());
    let client_conn = client_t.dial(&verified_upstream(url), &keys).await.unwrap();
    let (before, after_source, upgraded) = upgrade_task.await.unwrap();

    assert_eq!(before, vec!["tcp", "http"], "the layer below named itself");
    assert_eq!(
        ws.arrival(&upgraded).transport_chain,
        vec!["tcp", "http", "ws"],
        "the composed chain, not a name for itself"
    );
    assert_eq!(
        after_source.port, 0,
        "the source gave the stream up and knows nothing about it"
    );

    // And the adopted connection carries frames, which is what makes the upgrade real rather than
    // a shape that only type-checks.
    ws.write(&upgraded, StreamId(0), ArenaBytes::new(b"after the upgrade"))
        .await
        .unwrap();
    let mut frames = client_t.frames(client_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"after the upgrade");
}

/// The genuine network path, over the layers this transport composes over rather than over sockets
/// of its own: the `http` layer binds and accepts, the `tcp` layer dials, and this one does the one
/// thing it owns — the WebSocket handshake — on the streams they give up.
#[tokio::test]
async fn a_composed_round_trip_over_the_layers_below() {
    let http = Arc::new(busbar_transport_http::HttpTransport::new(
        busbar_transport_http::ClientSettings::default(),
    ));
    let server_t = Arc::new(WsTransport::over(http));
    let client_t = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    let keys = test_key_handle();
    let listener = server_t
        .listen(&HttpCfg("127.0.0.1:0".to_string()), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let host: &'static str = Box::leak(format!("ws://{addr}/").into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    // Both ends report the stack they actually stand on, not a name for themselves.
    assert_eq!(
        server_t.arrival(&server_conn).transport_chain,
        vec!["tcp", "http", "ws"]
    );
    assert_eq!(
        client_t.arrival(&client_conn).transport_chain,
        vec!["tcp", "ws"]
    );

    client_t
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"hello over the layers below"))
        .await
        .unwrap();
    let mut frames = server_t.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"hello over the layers below");
}

/// With no layer under it this transport has no socket to reach for, and inventing one is exactly
/// what the composition exists to stop.
#[tokio::test]
async fn a_transport_with_no_lower_layer_cannot_listen_or_dial() {
    let t = WsTransport::new();
    let keys = test_key_handle();
    assert_eq!(
        t.listen(&HttpCfg("127.0.0.1:0".to_string()), &keys)
            .await
            .unwrap_err(),
        TransportError::HandoffMismatch
    );
    assert_eq!(
        t.dial(&verified_upstream("ws://127.0.0.1:1/"), &keys)
            .await
            .unwrap_err(),
        TransportError::HandoffMismatch
    );
}

/// A bind address, for the layer below.
struct HttpCfg(String);
impl busbar_contract::ConfigView for HttpCfg {
    fn get_str(&self, _k: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _k: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _k: &str) -> Option<bool> {
        None
    }
}
impl busbar_contract::TransportConfigView for HttpCfg {
    fn bind(&self) -> Option<&str> {
        Some(&self.0)
    }
}

#[tokio::test]
async fn half_close_is_the_ws_closing_handshake() {
    let t = WsTransport::new();
    let (a, b) = pair(&t, 64 * 1024).await;
    t.write(&a, StreamId(0), ArenaBytes::new(b"last words")).await.unwrap();
    // `close` sends the WS Close control frame — the initiator's half of the closing handshake.
    t.close(a, CloseReason::Normal);

    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"last words");
    // The Close frame ends the stream cleanly (`None`), never as a `Reset` error.
    assert!(frames.next().await.is_none());
}

#[tokio::test]
async fn cancel_mid_frame_fences_the_connection() {
    let t = WsTransport::new();
    let (a, _b) = pair(&t, 8).await;
    let big = vec![b'x'; 1_000_000];
    let write_fut = t.write(&a, StreamId(0), ArenaBytes::new(&big));
    let raced = tokio::time::timeout(Duration::from_millis(1), write_fut).await;
    assert!(raced.is_err(), "the write did not have time to complete");

    let err = t
        .write(&a, StreamId(0), ArenaBytes::new(b"x"))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Framing);
}

#[tokio::test]
async fn backpressure_is_bidirectional() {
    let t = Arc::new(WsTransport::new());
    let (a, b) = pair(&t, 8).await;
    let payload = vec![b'y'; 65536];
    let t2 = t.clone();
    let payload2 = payload.clone();
    let writer = tokio::spawn(async move {
        t2.write(&a, StreamId(0), ArenaBytes::new(&payload2)).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!writer.is_finished(), "an oversized write must block on a full duplex");
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.len(), payload.len());
    writer.await.unwrap().unwrap();
}

#[tokio::test]
async fn k_writers_serialise_without_interleaving() {
    let t = Arc::new(WsTransport::new());
    let (a, b) = pair(&t, 64 * 1024).await;
    const K: usize = 32;
    let mut handles = Vec::new();
    for i in 0..K {
        let t = t.clone();
        let a = a.clone();
        handles.push(tokio::spawn(async move {
            let line = format!("writer-{i:02}");
            t.write(&a, StreamId(0), ArenaBytes::new(line.as_bytes())).await.unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let mut frames = t.frames(b);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..K {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        let line = String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap();
        assert!(line.starts_with("writer-"));
        seen.insert(line);
    }
    assert_eq!(seen.len(), K);
}

/// A handoff from a layer `ws` does not compose over is refused before anything is read, and the
/// source keeps its stream: an upgrade neither leg declared is not one the session may continue on.
#[tokio::test]
async fn a_handoff_from_an_undeclared_layer_is_a_mismatch() {
    let t = WsTransport::new();
    let (a, _b) = pair(&t, 4096).await;
    let keys = test_key_handle();
    // `ws` does not compose over `ws`; offering it its own connection names no declared handoff.
    let err = t.adopt(&t, a, &keys).await.unwrap_err();
    assert_eq!(err, TransportError::HandoffMismatch);
}

#[tokio::test]
async fn unit0_refusal_writes_then_closes() {
    let t = WsTransport::new();
    let (a, b) = pair(&t, 4096).await;
    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    t.unit0_refusal(a, None, &refusal, ArenaBytes::new(b"refused")).await.unwrap();
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"refused");
}

#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::wire::Unit0Trigger;
    use busbar_contract::TransportMeta;
    assert_eq!(<WsTransport as TransportMeta>::KEY, "ws");
    assert!(<WsTransport as TransportMeta>::SESSION);
    assert!(<WsTransport as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <WsTransport as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::Upgrade)
    );
    // The layers this one is actually built over, which the Cargo edges must agree with.
    assert_eq!(
        <WsTransport as TransportMeta>::COMPOSES_OVER,
        &["http", "tcp"]
    );
    assert!(<WsTransport as TransportMeta>::UPGRADES_TO.is_empty());
    assert_eq!(<WsTransport as TransportMeta>::STATUS_CLASS, None);
}

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    struct Seal;
    impl busbar_contract::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

fn verified_upstream(host: &'static str) -> busbar_contract::VerifiedDestination {
    struct Seal;
    impl busbar_contract::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "ws",
            address: busbar_contract::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "ws",
        None,
    )
}
