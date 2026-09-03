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

/// A stub open-pass gate for the governed WS-accept: it PROCEEDS or REFUSES at the verify stage, and
/// its `drive` is unreachable on the session path (the opener runs only the admission gate).
struct GatePlane {
    refuse: bool,
}

#[async_trait::async_trait]
impl crate::plane_host::GauntletPlane for GatePlane {
    fn verify_destination(
        &self,
        _req: &crate::plane_host::GauntletRequest<'_>,
    ) -> crate::plane_host::VerifyOutcome {
        if self.refuse {
            crate::plane_host::VerifyOutcome::Refuse(
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from("destination refused"))
                    .expect("refusal response builds"),
            )
        } else {
            crate::plane_host::VerifyOutcome::Proceed
        }
    }

    async fn drive(
        self: Box<Self>,
        _req: crate::plane_host::GauntletRequest<'_>,
    ) -> axum::response::Response {
        axum::response::Response::builder()
            .status(500)
            .body(axum::body::Body::from("session gate never drives"))
            .expect("fault response builds")
    }
}

/// Bring up a loopback WS server whose one route serves an [`EchoPlane`] THROUGH the governed
/// `serve_gauntlet` seam — the gauntlet runs BEFORE the socket is bound, refusing or proceeding per
/// `refuse`. Returns the bound address.
async fn spawn_gauntlet_ws_server(refuse: bool) -> SocketAddr {
    async fn ws_route(
        axum::extract::State(refuse): axum::extract::State<bool>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        let gov = busbar_api::PlaneRequestCtx::default();
        let req = crate::plane_host::GauntletRequest {
            gov: &gov,
            destination: "model-x",
            correlation_id: 1,
            charged_at: 1,
            started: std::time::Instant::now(),
        };
        ws_ingress::serve_gauntlet(
            upgrade,
            req,
            Box::new(GatePlane { refuse }),
            Arc::new(EchoPlane),
        )
    }
    let app = axum::Router::new()
        .route("/", axum::routing::get(ws_route))
        .with_state(refuse);
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

/// THE GOVERNED WS-ACCEPT RUNS THE GAUNTLET BEFORE BINDING THE SOCKET: a proceeding gate serves the
/// session (a frame round-trips), a refusing gate binds NO socket (the dial cannot upgrade) — so a
/// refused destination reaches neither the pump nor a charge. This is the open-pass invariant at the
/// WS-accept boundary: verify strictly before the socket is bound.
#[tokio::test]
async fn governed_ws_accept_serves_on_proceed_and_binds_no_socket_on_refuse() {
    // PROCEED: the gauntlet admits, the socket is bound to the echo pump, and a frame round-trips.
    let addr = spawn_gauntlet_ws_server(false).await;
    let url = format!("ws://{addr}/");
    let (mut stream, mut sink) = duplex_ws::dial(&url, loopback_policy())
        .await
        .expect("a proceeding gauntlet admits the session and binds the socket");
    sink.send(b"governed".to_vec()).await.ok();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a reply arrived")
        .expect("the stream yielded a frame");
    assert_eq!(got, b"governed", "the admitted session echoes the frame");

    // REFUSE: the gauntlet refuses at verify, the upgrade never happens, and the dial cannot complete
    // the WS handshake — the socket was never bound, so nothing reached the pump.
    let addr = spawn_gauntlet_ws_server(true).await;
    let url = format!("ws://{addr}/");
    let refused = duplex_ws::dial(&url, loopback_policy()).await;
    assert!(
        refused.is_err(),
        "a refused destination binds no socket, so the WS dial cannot upgrade"
    );
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

// ── THE INBOUND WS-ACCEPT ARRIVAL SEAM (WsArrival newtype + accept_gauntlet + registry) ──────────

use std::sync::atomic::{AtomicUsize, Ordering};

/// The socket-task counter the accept-fn's `on_socket` bumps — proves a REFUSED accept spawns ZERO
/// socket tasks (the R2 gauntlet-before-upgrade invariant), and a proceeding one spawns exactly one.
static ON_SOCKET_RUNS: AtomicUsize = AtomicUsize::new(0);

/// Bring up a loopback WS server whose route drives `accept_gauntlet` directly (the primitive a plane's
/// WS-accept fn uses) with a `GatePlane { refuse }` and an `on_socket` that BUMPS [`ON_SOCKET_RUNS`].
/// So a refused accept returns the refusal WITHOUT ever constructing the socket task, and the counter
/// stays 0; a proceeding one binds the socket and the counter reaches 1.
async fn spawn_accept_gauntlet_ws_server(refuse: bool) -> SocketAddr {
    async fn ws_route(
        axum::extract::State(refuse): axum::extract::State<bool>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        let gov = busbar_api::PlaneRequestCtx::default();
        let req = crate::plane_host::GauntletRequest {
            gov: &gov,
            destination: "model-x",
            correlation_id: 1,
            charged_at: 1,
            started: std::time::Instant::now(),
        };
        ws_ingress::accept_gauntlet(
            upgrade,
            req,
            Box::new(GatePlane { refuse }),
            |_stream, _sink| async move {
                ON_SOCKET_RUNS.fetch_add(1, Ordering::SeqCst);
            },
        )
    }
    let app = axum::Router::new()
        .route("/", axum::routing::get(ws_route))
        .with_state(refuse);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// GAUNTLET-BEFORE-UPGRADE, ZERO-TASK: a REFUSED destination returns the gate's refusal and spawns
/// ZERO socket tasks — the accept fn never reaches `accept`/`on_upgrade`. A PROCEEDING one binds the
/// socket, so exactly one task runs — proving the counter is live (the refuse `0` is not vacuous).
#[tokio::test]
async fn accept_gauntlet_refuse_returns_refusal_and_spawns_zero_socket_tasks() {
    ON_SOCKET_RUNS.store(0, Ordering::SeqCst);

    // REFUSE: the dial cannot upgrade (no socket bound) and NO on_socket task ran.
    let addr = spawn_accept_gauntlet_ws_server(true).await;
    let refused = duplex_ws::dial(&format!("ws://{addr}/"), loopback_policy()).await;
    assert!(
        refused.is_err(),
        "a refused destination binds no socket, so the dial cannot upgrade"
    );
    // The refusal is synchronous and precedes any task; give the server no chance to have spawned one.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        ON_SOCKET_RUNS.load(Ordering::SeqCst),
        0,
        "a refused accept spawns ZERO socket tasks — the accept fn never reached on_upgrade"
    );

    // PROCEED: the socket binds and the on_socket task runs exactly once — the counter is not vacuous.
    let addr = spawn_accept_gauntlet_ws_server(false).await;
    let (_stream, _sink) = duplex_ws::dial(&format!("ws://{addr}/"), loopback_policy())
        .await
        .expect("a proceeding gauntlet binds the socket");
    let mut ran = false;
    for _ in 0..50 {
        if ON_SOCKET_RUNS.load(Ordering::SeqCst) >= 1 {
            ran = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        ran,
        "a proceeding accept binds the socket and runs exactly one on_socket task"
    );
}

/// THE WS-ARRIVAL SPEC + PROCESS REGISTRY round-trip: a plane declares a `WsArrivalSpec` (the neutral,
/// single-compiled seam carrying the substrate-owned `WsArrival` newtype BY VALUE — never `Box<dyn
/// Any>`), the composition root installs it, and the core router drains it VERBATIM. Witnesses the R1
/// seam shape (spec is constructible with a by-value accept fn) and the install/take registry.
#[test]
fn ws_arrival_spec_installs_and_drains_verbatim() {
    use crate::ingress::duplex_ws::{
        install_ws_arrivals, take_ws_arrivals, WsArrival, WsArrivalSpec,
    };
    use busbar_plugin::cold::http_endpoint::RouteAuth;

    let spec = WsArrivalSpec {
        path: "/v1/duplex/{id}".to_string(),
        auth: RouteAuth::Key,
        slot_key: "test-duplex-plane",
        // The accept fn takes the newtype BY VALUE — the single-compiled `WsArrival`, never a box.
        accept: std::sync::Arc::new(|_a: WsArrival| {
            axum::response::Response::builder()
                .status(axum::http::StatusCode::NOT_IMPLEMENTED)
                .body(axum::body::Body::empty())
                .expect("response builds")
        }),
    };
    install_ws_arrivals(vec![spec]);
    let drained = take_ws_arrivals();
    assert_eq!(drained.len(), 1, "the installed arrival drains verbatim");
    assert_eq!(drained[0].path, "/v1/duplex/{id}");
    assert_eq!(drained[0].slot_key, "test-duplex-plane");
    assert!(matches!(drained[0].auth, RouteAuth::Key));
    // Read-many: a second drain still yields the same installed set (the router may build twice).
    assert_eq!(
        take_ws_arrivals().len(),
        1,
        "take is read-many, not destructive"
    );
}
