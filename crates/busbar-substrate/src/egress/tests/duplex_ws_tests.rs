// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the neutral full-duplex WebSocket transport — the egress dialer
//! (`crate::egress::duplex_ws`) and the ingress acceptor (`crate::ingress::duplex_ws`), proven
//! TOGETHER over a loopback WS pair: a frame crosses BOTH directions, the dialer REFUSES a
//! guard-failing/unpinned target, and `Transport::WebSocket` is ARMED (a real caller resolves the axis
//! to the dialer — no `unreachable!()`).

use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};

use crate::egress::duplex_ws::{self, DialError};
use crate::ingress::byte_duplex::{CallRef, DuplexHandle, DuplexPlane};
use crate::ingress::duplex_ws as ws_ingress;
use crate::net_guard::{GuardPolicy, GuardRefusal};
use crate::transport::{Transport, UpstreamWireKind};

/// A trivial ECHO plane bound to the acceptor: no protocol, no wire vocabulary — it echoes each frame
/// back verbatim. Exactly the shape the `serve_messages` header describes an upgraded WS session taking.
struct EchoPlane;

#[async_trait::async_trait]
impl DuplexPlane for EchoPlane {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        out.emit(frame).await;
    }
}

/// Bring up a loopback axum WS-acceptor server whose one route serves an [`EchoPlane`] over the neutral
/// ingress acceptor, and return the bound address. The upgrade/routing stays at the acceptor boundary;
/// the pump sees only `Vec<u8>` frames.
async fn spawn_echo_ws_server() -> SocketAddr {
    async fn ws_route(upgrade: axum::extract::ws::WebSocketUpgrade) -> axum::response::Response {
        ws_ingress::serve(upgrade, Arc::new(EchoPlane))
    }
    let app = axum::Router::new().route("/", axum::routing::get(ws_route));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A permissive policy for a LOOPBACK plaintext `ws://` dial: loopback is private and plaintext, so both
/// stances must be opened for the guard to admit the local test server. Everything else stays fail-closed.
fn loopback_policy() -> GuardPolicy {
    GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    }
}

/// THE ROUND TRIP over both halves of the neutral WS transport: the ingress acceptor serves an echo
/// session, the egress dialer dials it THROUGH the guard, and a frame crosses both directions.
#[tokio::test]
async fn ws_transport_round_trips_a_frame_both_directions() {
    let addr = spawn_echo_ws_server().await;
    let url = format!("ws://{addr}/");

    let (mut stream, mut sink) = duplex_ws::dial(&url, loopback_policy())
        .await
        .expect("dial through the guard to the loopback acceptor");

    // OUT: a frame written onto the dialer's sink crosses to the acceptor…
    sink.send(b"ping".to_vec()).await.ok();
    // …IN: …and the echo plane's reply comes back on the dialer's stream.
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a reply arrived")
        .expect("the stream yielded a frame");
    assert_eq!(got, b"ping", "the frame crossed both directions verbatim");
}

/// `Transport::WebSocket` IS ARMED: a real caller selects it, resolves the axis to
/// [`UpstreamWireKind::Duplex`] through `upstream_wire()`, and drives the guarded dialer that arm names
/// — the wire resolves to a LIVE socket, not an `unreachable!()`.
#[tokio::test]
async fn websocket_transport_is_armed_by_a_real_dialer() {
    // The axis answers the full-duplex leg with its neutral wire shape — the one match on the axis.
    assert_eq!(
        Transport::WebSocket.upstream_wire(),
        Some(UpstreamWireKind::Duplex),
        "the WebSocket transport must resolve to the Duplex upstream wire"
    );

    // A real caller that resolved `Duplex` maps it to THIS dialer — proven by driving a live dial.
    let addr = spawn_echo_ws_server().await;
    let url = format!("ws://{addr}/");
    let (mut stream, mut sink) = match Transport::WebSocket.upstream_wire() {
        Some(UpstreamWireKind::Duplex) => duplex_ws::dial(&url, loopback_policy())
            .await
            .expect("the Duplex wire dials a live socket"),
        other => panic!("WebSocket must select the Duplex wire, got {other:?}"),
    };
    sink.send(b"armed".to_vec()).await.ok();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a reply arrived")
        .expect("the stream yielded a frame");
    assert_eq!(got, b"armed");
}

/// THE DIALER REFUSES A GUARD-FAILING TARGET — it NEVER opens a socket to something the net-guard did
/// not pin. A loopback `wss://` under the fail-closed default is an internal address; a cloud-metadata
/// literal is refused unconditionally; a non-`ws(s)` scheme never reaches the resolver.
#[tokio::test]
async fn dial_refuses_unpinned_and_guard_failing_targets() {
    // The dial hands back a live `(Stream, Sink)` on success — neither is `Debug`, so a refusal test
    // takes the `.err()` (a `Debug` `Option<DialError>`) and never the whole `Result`.

    // Loopback, fail-closed default (no `allow_private`) ⇒ InternalAddress, no socket opened.
    let err = duplex_ws::dial("wss://127.0.0.1/", GuardPolicy::default())
        .await
        .err();
    assert!(
        matches!(
            err,
            Some(DialError::Guard(GuardRefusal::InternalAddress { .. }))
        ),
        "loopback under the default policy must be refused internal, got {err:?}"
    );

    // Cloud-metadata address ⇒ refused unconditionally, `allow_private` or not.
    let err = duplex_ws::dial("wss://169.254.169.254/latest/meta-data", loopback_policy())
        .await
        .err();
    assert!(
        matches!(
            err,
            Some(DialError::Guard(GuardRefusal::CloudMetadataAddress { .. }))
        ),
        "the metadata address must be refused unconditionally, got {err:?}"
    );

    // A non-ws(s) scheme is not a duplex target — refused before any resolution.
    let err = duplex_ws::dial("https://example.com/", loopback_policy())
        .await
        .err();
    assert!(
        matches!(err, Some(DialError::Url(_))),
        "a non-ws scheme must be a Url error, got {err:?}"
    );
}
