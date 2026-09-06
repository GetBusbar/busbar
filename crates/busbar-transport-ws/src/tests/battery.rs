// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ws transport battery: the upgrade path, byte-exact round trip, half-close (the WS closing
//! handshake), cancel mid-frame, backpressure, K writers and honest frame meta.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use busbar_contract::{ArenaBytes, StreamId, Transport};
use busbar_contract_transport::wire::CloseReason;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::TransportError;

use crate::WsTransport;

/// Build a connected pair of live WS connections over an in-memory duplex — one performs the
/// server handshake role, the other the client role, exactly as `accept`/`dial` would over a real
/// socket. This is the exact seam a real `tcp`/`tls`/`http` transport would hand this crate a
/// connection through once composed (see the crate's own report).
async fn pair(
    t: &WsTransport,
    cap: usize,
) -> (
    busbar_contract_transport::wire::Conn,
    busbar_contract_transport::wire::Conn,
) {
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
    let n = t
        .write(&a, StreamId(0), ArenaBytes::new(&payload))
        .await
        .unwrap();
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
    ws.write(
        &upgraded,
        StreamId(0),
        ArenaBytes::new(b"after the upgrade"),
    )
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
        .write(
            &client_conn,
            StreamId(0),
            ArenaBytes::new(b"hello over the layers below"),
        )
        .await
        .unwrap();
    let mut frames = server_t.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"hello over the layers below");
}

/// The layer this instance reports is the one it was built over, and it is one the crate declares
/// — which is what the registry's boot check compares. A composition nobody declared refuses the
/// boot rather than running as a stack the declarations do not describe.
#[tokio::test]
async fn the_layer_reported_is_one_the_transport_declares() {
    use busbar_contract::TransportMeta;

    let over_http = WsTransport::over(Arc::new(busbar_transport_http::HttpTransport::new(
        busbar_transport_http::ClientSettings::default(),
    )));
    let over_tcp = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    assert_eq!(over_http.composed_over(), Some("http"));
    assert_eq!(over_tcp.composed_over(), Some("tcp"));
    assert_eq!(WsTransport::new().composed_over(), None);

    for used in [over_http.composed_over(), over_tcp.composed_over()] {
        let used = used.unwrap();
        assert!(
            <WsTransport as TransportMeta>::COMPOSES_OVER.contains(&used),
            "`{used}` is a layer this crate declares it composes over"
        );
    }
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

/// The upgrade is the session's Unit 0, and until it completes the connection is an accepted socket
/// answering to nobody. A peer that opens one and then says nothing would hold that socket, and the
/// task upgrading it, for the lifetime of the process — the cheapest slot-exhaustion there is. The
/// handshake carries its own budget, and a peer that misses it gets a deadline error rather than a
/// permanent lease.
#[tokio::test(start_paused = true)]
async fn an_upgrade_the_peer_never_answers_expires_on_the_handshake_budget() {
    let t = WsTransport::new();
    // The far half is held open and never written to: the accept side can only wait.
    let (end_a, _end_b) = tokio::io::duplex(64 * 1024);
    let started = tokio::time::Instant::now();
    let err = t
        .handshake_over(end_a, true, "silent-peer")
        .await
        .expect_err("an unanswered upgrade must not wait forever");
    assert_eq!(err, TransportError::Timeout);
    assert!(
        started.elapsed() >= crate::transport::HANDSHAKE_BUDGET,
        "the budget is what ended it"
    );
}

#[tokio::test]
async fn half_close_is_the_ws_closing_handshake() {
    let t = WsTransport::new();
    let (a, b) = pair(&t, 64 * 1024).await;
    t.write(&a, StreamId(0), ArenaBytes::new(b"last words"))
        .await
        .unwrap();
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

    // The read arm of the same cell. A `frames()` future dropped while suspended in the socket
    // read must leave the connection readable: the reader belongs to the connection, not to the
    // future that was polling it, so the next pump sees the frame that arrived rather than a
    // silent end-of-stream indistinguishable from the peer closing.
    let t = Arc::new(WsTransport::new());
    let (a, b) = pair(&t, 64 * 1024).await;
    {
        let mut frames = t.frames(b.clone());
        let first = frames.next();
        tokio::pin!(first);
        let raced = tokio::time::timeout(Duration::from_millis(1), first.as_mut()).await;
        assert!(
            raced.is_err(),
            "the read must still be suspended when dropped"
        );
    }
    t.write(&a, StreamId(0), ArenaBytes::new(b"after the cancel"))
        .await
        .unwrap();
    let mut frames = t.frames(b);
    let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("a cancelled read must not lose the reader")
        .expect("the stream must not end")
        .expect("and must not be a fenced error");
    assert_eq!(frame.bytes.as_slice(), b"after the cancel");
}

/// A write that never reached the writer at all did not tear a frame. The fence exists for a send
/// that started and stopped half-way; a future dropped while still queued on the writer lock wrote
/// nothing, so fencing it condemns a healthy connection for the lifetime of the process on nothing
/// worse than contention. The guard must therefore be armed AFTER the lock is held, not before.
#[tokio::test]
async fn a_write_dropped_while_queued_on_the_writer_does_not_fence_the_connection() {
    let t = Arc::new(WsTransport::new());
    let (a, b) = pair(&t, 64 * 1024).await;

    // One holder of the writer, so the next write can only queue on the lock and never send.
    let state = t.state_of(a.id()).expect("the connection is live");
    let held = state.writer.lock().await;
    {
        let queued = t.write(&a, StreamId(0), ArenaBytes::new(b"never sent"));
        tokio::pin!(queued);
        let raced = tokio::time::timeout(Duration::from_millis(20), queued.as_mut()).await;
        assert!(raced.is_err(), "the write must still be queued on the lock");
    }
    drop(held);

    // Nothing was written, so nothing was torn: the connection carries the next frame.
    t.write(&a, StreamId(0), ArenaBytes::new(b"after the queue"))
        .await
        .expect("a write that never reached the socket must not fence the connection");
    let mut frames = t.frames(b);
    let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the frame must arrive")
        .expect("the stream must not end")
        .expect("and must not be a fenced error");
    assert_eq!(frame.bytes.as_slice(), b"after the queue");
}

#[tokio::test]
async fn backpressure_is_bidirectional() {
    let t = Arc::new(WsTransport::new());
    let (a, b) = pair(&t, 8).await;
    let payload = vec![b'y'; 65536];
    let t2 = t.clone();
    let payload2 = payload.clone();
    let writer =
        tokio::spawn(async move { t2.write(&a, StreamId(0), ArenaBytes::new(&payload2)).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !writer.is_finished(),
        "an oversized write must block on a full duplex"
    );
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
            t.write(&a, StreamId(0), ArenaBytes::new(line.as_bytes()))
                .await
                .unwrap();
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
    t.unit0_refusal(a, None, &refusal, ArenaBytes::new(b"refused"))
        .await
        .unwrap();
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"refused");
}

/// A refusal that never reached the peer is not a refusal. It is the only answer the far side will
/// ever get about bytes that reached no plane, so the caller must be told when it did not go out —
/// an `Ok(())` for a send that failed, or for a connection that was already fenced and skipped the
/// send entirely, reports a refusal delivered over a socket nothing was written to.
#[tokio::test]
async fn a_refusal_that_could_not_be_written_is_reported_rather_than_claimed() {
    let t = Arc::new(WsTransport::new());
    let (a, b) = pair(&t, 4096).await;

    // Take the far end away: its socket half is dropped, so a send on this end cannot land.
    let peer = t.state_of(b.id()).expect("the peer connection is live");
    t.close(b, CloseReason::Normal);
    tokio::time::timeout(Duration::from_secs(5), async {
        while Arc::strong_count(&peer) > 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the close task must finish and give up its handle");
    drop(peer);

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let err = t
        .unit0_refusal(a.clone(), None, &refusal, ArenaBytes::new(b"refused"))
        .await
        .expect_err("a refusal that could not be written must not report success");
    assert_eq!(err, TransportError::Reset);
    // And the connection is finalised either way: a refusal ends it.
    assert!(t.state_of(a.id()).is_none(), "the refusal closed it");

    // A connection this transport no longer holds cannot carry a refusal at all, and says so.
    let err = t
        .unit0_refusal(a, None, &refusal, ArenaBytes::new(b"refused"))
        .await
        .expect_err("a refusal over a connection that is gone must not report success");
    assert_eq!(err, TransportError::Closed);
}

#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::TransportMeta;
    use busbar_contract_transport::wire::Unit0Trigger;
    assert_eq!(<WsTransport as TransportMeta>::KEY, "ws");
    assert!(<WsTransport as TransportMeta>::SESSION);
    assert!(<WsTransport as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <WsTransport as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::Upgrade)
    );
    // The layers this one is actually built over: an inbound upgrade on `http`, an outbound dial
    // on `tcp` for a plaintext target and on `tls` for a secure one, which is the only lower layer
    // under which a `wss://` dial is honest.
    assert_eq!(
        <WsTransport as TransportMeta>::COMPOSES_OVER,
        &["http", "tcp", "tls"]
    );
    assert!(<WsTransport as TransportMeta>::UPGRADES_TO.is_empty());
    assert_eq!(<WsTransport as TransportMeta>::STATUS_CLASS, None);
}

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

fn verified_upstream(host: &'static str) -> busbar_contract::VerifiedDestination {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "ws",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "ws",
        None,
    )
}

/// `split_ws_url` on the bracketed-IPv6 shapes. A literal address with an explicit port is the one
/// case the bracket rule exists to serve, and it must come back as the address without its brackets
/// and the port the URL spelled — not as an authority that gets a default port stapled onto it.
#[test]
fn a_bracketed_ipv6_authority_parses_with_and_without_a_port() {
    assert_eq!(
        crate::transport::split_ws_url("wss://[::1]:8080/p").unwrap(),
        (true, "::1".to_string(), 8080, "/p".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("ws://[::1]/p").unwrap(),
        (false, "::1".to_string(), 80, "/p".to_string())
    );
    // The shapes the existing rule already got right stay right.
    assert_eq!(
        crate::transport::split_ws_url("ws://host:9000/p").unwrap(),
        (false, "host".to_string(), 9000, "/p".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("wss://host/p").unwrap(),
        (true, "host".to_string(), 443, "/p".to_string())
    );
}

/// A courtesy Close frame must not be able to outlive the process. `close` hands the send to a
/// detached task and keeps no handle to cancel it, so a peer whose receive window is full would
/// pin the writer lock — and the socket — forever. The budget is what makes the task terminate.
#[tokio::test]
async fn close_gives_up_on_a_peer_that_never_reads() {
    let t = Arc::new(WsTransport::new());
    // A duplex with no room left: the peer end is never read, so a Close frame cannot be sent.
    let (a, _b) = pair(&t, 8).await;
    let stuffing = vec![b'z'; 1_000_000];
    let t2 = t.clone();
    let a2 = a.clone();
    let stuffer =
        tokio::spawn(async move { t2.write(&a2, StreamId(0), ArenaBytes::new(&stuffing)).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!stuffer.is_finished(), "the duplex must be full");
    stuffer.abort();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // The only handle on the connection state, besides the one `close` hands its detached task.
    let state = t.state_of(a.id()).expect("the connection is live");
    t.close(a, CloseReason::Normal);

    let gave_up = tokio::time::timeout(crate::transport::CLOSE_BUDGET * 8, async {
        while Arc::strong_count(&state) > 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        gave_up.is_ok(),
        "the detached close task must give up within its budget and drop the socket"
    );
}

/// A redial against the same upstream must not allocate a second `'static` address. `dial` needs
/// both halves for the lifetime of the process, so the allocation is deliberate; what would not be
/// deliberate is one per dial, which a redial loop against a flapping upstream turns into unbounded
/// growth. Identical strings must come back as the identical allocation.
#[test]
fn a_redial_reuses_the_interned_address_rather_than_leaking_a_new_one() {
    let first = crate::transport::intern("example.invalid:8443");
    let again = crate::transport::intern("example.invalid:8443");
    assert!(
        std::ptr::eq(first, again),
        "a repeat dial must reuse the address the first one interned, not leak a second"
    );
    let other = crate::transport::intern("elsewhere.invalid:8443");
    assert!(!std::ptr::eq(first, other));
    assert_eq!(other, "elsewhere.invalid:8443");
}

/// A `wss://` target is a statement that the bytes are encrypted before they leave, and this
/// transport encrypts nothing: it upgrades whatever stream the layer below gives it. Over a
/// cleartext lower layer the handshake would therefore go out as a plain HTTP GET, with no
/// certificate ever validated, while the destination said `wss`. The dial is refused instead, and
/// nothing reaches the wire.
#[tokio::test]
async fn a_secure_target_over_a_cleartext_lower_layer_is_refused_before_any_byte_is_written() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = tokio::spawn(async move {
        // A refused dial connects to nothing, so the accept is bounded: no connection at all is
        // the passing shape, and waiting on one forever would hang rather than report.
        let Ok(Ok((mut sock, _))) =
            tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
        else {
            return Vec::new();
        };
        let mut buf = vec![0u8; 1024];
        match tokio::time::timeout(
            Duration::from_millis(500),
            tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
        )
        .await
        {
            Ok(Ok(n)) => buf[..n].to_vec(),
            _ => Vec::new(),
        }
    });

    let client_t = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    let url: &'static str = Box::leak(format!("wss://{addr}/duplex").into_boxed_str());
    let err = client_t
        .dial(&verified_upstream(url), &test_key_handle())
        .await
        .expect_err("a wss target dialled over a cleartext lower layer must be refused");
    assert_eq!(err, TransportError::AddressRefused);

    let first_bytes = seen.await.unwrap();
    assert!(
        !first_bytes.starts_with(b"GET "),
        "a wss dial must never put a cleartext HTTP upgrade on the wire: {:?}",
        String::from_utf8_lossy(&first_bytes)
    );
}
