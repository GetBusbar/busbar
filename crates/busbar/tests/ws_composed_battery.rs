// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `ws` transport's cross-transport composition battery: the six cells that drive a real
//! `busbar-transport-http` and/or `busbar-transport-tcp` instance underneath `busbar-transport-ws`.
//!
//! ## Why this lives here and not in `busbar-transport-ws`
//!
//! `busbar-transport-ws` is a plugin-kind crate: its own `Cargo.toml` is not allowed to name a
//! sibling transport even in `[dev-dependencies]`, because a dev-dependency's SHIPPED closure is
//! linked into that crate's `cargo test` binary whole (`kind-isolation:closure`'s
//! `closure-test-reach` finding) — the exact same closure a third party would take by depending on
//! the plugin from a published contract alone, just visible only in the test graph instead of the
//! artifact. `ws` composing OVER `http`/`tcp` is real and shipped (`WsTransport::over`, an
//! adoption through a contract trait — see the crate's own report), but PROVING that composition
//! with a real `http`/`tcp` instance requires naming both crates, and the one place in the tree a
//! real protocol may be named at all is the composition root: [`busbar_transport_grpc`]'s and
//! [`busbar_transport_http`]'s own `tests/no_plane_names.rs` say so explicitly ("The proof that a
//! real protocol's bytes survive this mount belongs where a real protocol may be named — the
//! composition root — and it is asserted there").
//!
//! `busbar` already carries `busbar-transport-ws`, `busbar-transport-http` and
//! `busbar-transport-tcp` as ordinary (non-dev) dependencies — `busbar-transport-ws` behind the
//! default-on `plane-voice` feature, which is why this file is gated on it too — so this file changes no
//! wire string, no config key and no customer-visible behaviour: it is the same six assertions
//! [`busbar-transport-ws/src/tests/battery.rs`] used to carry, moved to the one crate whose
//! manifest can honestly own the edge they exercise.
//!
//! The remaining `busbar-transport-ws` battery cells that do not construct another transport (the
//! byte-exact round trip, half-close, cancel-mid-frame, backpressure, K-writers, frame meta, and
//! the crate's own private-helper unit tests) are untouched and still live in that crate.

#![cfg(feature = "plane-voice")]

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use busbar_contract::transport::wire::TransportError;
use busbar_contract::{ScratchBytes, StreamId, Transport};
use busbar_transport_ws::WsTransport;

/// The target the client role names in its upgrade request — the same fixture value the crate's
/// own battery uses.
const WS_TARGET: &str = "ws://localhost/";

/// A minimal `http`-listener config view, duplicated from the crate's own battery fixture rather
/// than imported: it is a handful of lines built only from `busbar_contract`'s public
/// `ConfigView`/`TransportConfigView` traits, and this file must not reach back into
/// `busbar-transport-ws`'s private test internals (there is nothing to import — the type was never
/// public, and making it so just to share a fixture would be a public API grown for a test).
struct HttpCfg(String, Option<i64>);
impl busbar_contract::ConfigView for HttpCfg {
    fn get_str(&self, _k: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, k: &str) -> Option<i64> {
        self.1.filter(|_| k == busbar_transport_ws::MESSAGE_MAX_BYTES_KEY)
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

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    use busbar_contract::plugin::TestKernelSeal as Seal;
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

fn verified_upstream(host: &'static str) -> busbar_contract::VerifiedDestination {
    use busbar_contract::plugin::TestKernelSeal as Seal;
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "ws",
            address: busbar_contract::transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "ws",
        None,
    )
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
        .listen(&HttpCfg("127.0.0.1:0".to_string(), None), &keys)
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
        ScratchBytes::new(b"after the upgrade"),
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
        .listen(&HttpCfg("127.0.0.1:0".to_string(), None), &keys)
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
            ScratchBytes::new(b"hello over the layers below"),
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
/// The size of message this connection will accept is the operator's number, not the WebSocket
/// library's. Left to the default, a listener declaring a 1 KiB body cap would still buffer 64 MiB
/// per connection before saying no — the deployment's own limit silently widened by four orders of
/// magnitude, at the one layer where an oversized message is cheapest to refuse.
#[tokio::test]
async fn the_message_cap_is_the_operator_s_and_not_the_library_s() {
    const CAP: usize = 1024;
    let t = Arc::new(WsTransport::over(Arc::new(
        busbar_transport_tcp::TcpTransport::new(),
    )));
    // The listener is where the operator's configuration reaches this transport at all.
    let listener = t
        .listen(
            &HttpCfg("127.0.0.1:0".to_string(), Some(CAP as i64)),
            &test_key_handle(),
        )
        .await
        .unwrap();
    drop(listener);

    // The peer is an uncapped transport, because the cap this test is about is the RECEIVER's: a
    // limit that only holds when the far side agrees to it is not a limit.
    let peer = WsTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (accepted, dialled) = tokio::join!(
        t.handshake_over(end_a, true, WS_TARGET, "capped-peer"),
        peer.handshake_over(end_b, false, WS_TARGET, "uncapped-peer")
    );
    let (a, b) = (dialled.unwrap(), accepted.unwrap());

    let oversized = vec![b'w'; 2 * CAP];
    peer.write(&a, StreamId(0), ScratchBytes::new(&oversized))
        .await
        .expect("the uncapped peer puts the oversized message on the wire");

    let mut frames = t.frames(b);
    let outcome = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the cap must be enforced rather than waited on")
        .expect("an over-cap message is an error, not a clean end of session");
    assert_eq!(
        outcome.unwrap_err(),
        TransportError::Framing,
        "a message past the operator's cap is a framing refusal"
    );
}
/// And the other lifecycle: an instance that only ever DIALS holds the same ceiling.
///
/// The cell above reaches the transport through `listen`, which is the seam a served instance
/// learns the deployment's configuration through. A dial-side instance never reaches it — nothing
/// binds it, so nothing hands it a config view — and an upstream that streams audio is exactly the
/// connection an unbounded message ceiling costs the most on. The composition root holds the number
/// in both cases, so it names it at construction here and the same field answers.
#[tokio::test]
async fn a_dial_only_instance_holds_the_ceiling_its_root_named() {
    const CAP: usize = 1024;
    // No `listen` anywhere in this cell: the ceiling arrives only through the constructor.
    let t = WsTransport::over_with_max_message_bytes(
        Arc::new(busbar_transport_tcp::TcpTransport::new()),
        CAP,
    );

    let peer = WsTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (dialled, accepted) = tokio::join!(
        t.handshake_over(end_a, false, WS_TARGET, "capped-dialer"),
        peer.handshake_over(end_b, true, WS_TARGET, "uncapped-upstream")
    );
    let (mine, theirs) = (dialled.unwrap(), accepted.unwrap());

    // At the ceiling the message is a message, so this is a ceiling and not a smaller default.
    let at_cap = vec![b'k'; CAP];
    peer.write(&theirs, StreamId(0), ScratchBytes::new(&at_cap))
        .await
        .unwrap();
    let mut frames = t.frames(mine);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.len(), CAP);

    let oversized = vec![b'w'; 2 * CAP];
    peer.write(&theirs, StreamId(0), ScratchBytes::new(&oversized))
        .await
        .expect("the uncapped upstream puts the oversized message on the wire");
    let outcome = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the cap must be enforced rather than waited on")
        .expect("an over-cap message is an error, not a clean end of session");
    assert_eq!(
        outcome.unwrap_err(),
        TransportError::Framing,
        "a dial-side connection is bounded by the same number a served one is"
    );
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
