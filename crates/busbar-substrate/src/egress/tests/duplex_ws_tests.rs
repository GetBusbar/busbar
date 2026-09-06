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
        // A write that does not land would make this echo silently stop echoing, which reads as a
        // missing frame rather than a broken sink — so the loss is surfaced where it happens. The
        // session ending mid-echo is the one legitimate way to get here, and the assertions on the
        // far end have already run by then.
        if let Err(e) = out.emit(frame).await {
            eprintln!("echo plane: the frame could not be written: {e}");
        }
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

/// A PEER WRITING FASTER THAN ITS FRAMES ARE READ MUST NOT BE ABLE TO QUEUE THEM ALL HERE. The
/// acceptor's inbound channel is what stands between a socket and this node's memory: with no bound,
/// every frame a client can push through the socket is held in it, so the client alone decides how
/// much a session costs. Bounded, the acceptor's own reader stops taking frames off the socket at the
/// bound and the backlog stays on the client's transport, where TCP already knows how to hold it.
#[tokio::test]
async fn the_acceptor_queues_no_more_inbound_frames_than_its_bound() {
    use std::sync::Mutex;

    type Parked = Arc<Mutex<Option<futures::channel::mpsc::Receiver<Vec<u8>>>>>;

    // The route PARKS the frame stream instead of serving it — a session whose reader is busy. Every
    // frame the client sends then has nowhere to go but the channel, which is the thing under test.
    async fn ws_route(
        axum::extract::State(parked): axum::extract::State<Parked>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        ws_ingress::accept(upgrade, move |stream, sink| async move {
            *parked.lock().unwrap() = Some(stream);
            let _write_side = sink; // held open, so the socket stays up while nothing is read
            std::future::pending::<()>().await;
        })
    }

    let parked: Parked = Arc::new(Mutex::new(None));
    let app = axum::Router::new()
        .route("/", axum::routing::get(ws_route))
        .with_state(parked.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("ws://{addr}/");
    let (_stream, mut sink) = duplex_ws::dial(&url, loopback_policy())
        .await
        .expect("dial the parked acceptor");

    let flood = ws_ingress::MAX_QUEUED_INBOUND_FRAMES * 8;
    for _ in 0..flood {
        sink.send(b"flood".to_vec()).await.ok();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let mut queued = 0usize;
    let mut held = parked.lock().unwrap();
    let stream = held.as_mut().expect("the session parked its frame stream");
    while stream.try_recv().is_ok() {
        queued += 1;
    }
    assert!(
        queued <= ws_ingress::MAX_QUEUED_INBOUND_FRAMES + 1,
        "a flood of {flood} frames left {queued} queued on an unread session"
    );
}

/// AN OVERSIZED INBOUND MESSAGE IS REFUSED, NOT REASSEMBLED. The frame bound and the queue bound
/// above defend against different things and neither covers the other: the queue caps how MANY frames
/// may wait, and a peer that sends ONE enormous message never reaches it — the message is still being
/// assembled, so the counted-frames bound has nothing to count while the socket's reassembly buffer
/// grows to whatever the peer asked for. The acceptor therefore carries the deployment's request-body
/// ceiling onto the upgrade, and a message past it closes the connection instead of being buffered.
/// The small frame first proves the session is live, so the refusal is a refusal and not a dead socket.
#[tokio::test]
async fn the_acceptor_refuses_an_inbound_message_past_the_body_ceiling() {
    // The cap is read from the installed limits per upgrade, so the posture must be live for the dial
    // — and installing a process-global is what the shared lock serializes.
    let _limits_lock = crate::config::limits::LIMITS_TEST_LOCK.lock().await;
    let cap = crate::config::limits::REQUEST_BODY_MAX_BYTES_FLOOR;
    let posture = crate::config::limits::LimitsResolved::with_request_body_max_bytes(cap);
    // Uncommitted, so the previous posture is restored when this test ends whichever way it ends.
    let _installed = crate::config::limits::InstallGuard::install(&posture);

    type Seen = tokio::sync::mpsc::UnboundedSender<Vec<u8>>;

    // The route reports every frame the pump side actually receives, so "refused" is proven by the
    // oversized frame never arriving rather than by the absence of a crash.
    async fn ws_route(
        axum::extract::State(seen): axum::extract::State<Seen>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        ws_ingress::accept(upgrade, move |mut stream, sink| async move {
            let _write_side = sink; // held so the socket stays up for as long as the peer does
            while let Some(frame) = stream.next().await {
                if seen.send(frame).is_err() {
                    break;
                }
            }
        })
    }

    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let app = axum::Router::new()
        .route("/", axum::routing::get(ws_route))
        .with_state(seen_tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("ws://{addr}/");
    let (mut stream, mut sink) = duplex_ws::dial(&url, loopback_policy())
        .await
        .expect("dial the size-capped acceptor");

    // UNDER the ceiling: the session is live and the frame lands, so the refusal below is about size.
    sink.send(vec![b'a'; 1024]).await.ok();
    let under = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx.recv())
        .await
        .expect("an under-cap frame arrives")
        .expect("the session delivered it");
    assert_eq!(under.len(), 1024, "an under-cap frame crosses verbatim");

    // OVER the ceiling: the WS layer refuses it and closes, which the dialing side sees as the session
    // ending rather than as an answer.
    sink.send(vec![b'b'; cap * 4]).await.ok();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await;
    assert!(
        matches!(ended, Ok(None)),
        "an over-cap message must close the connection, not be buffered and served"
    );

    // …and the payload never reached the pump: the session ended with the oversized message unread.
    let delivered = seen_rx.try_recv();
    assert!(
        matches!(
            delivered,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "an over-cap message must never be delivered to the pump, got {:?}",
        delivered.map(|f| f.len())
    );
}

/// THE SAME BOUND ON THE UPSTREAM LEG. An upstream that emits faster than the leg consumes is the
/// mirror image of a flooding client, and the dialer's inbound queue is the same single thing between
/// that socket and the heap. A relay has two legs; a bound on only one of them is not a bound.
#[tokio::test]
async fn the_dialer_queues_no_more_upstream_frames_than_its_bound() {
    use futures::FutureExt;

    let flood = crate::egress::duplex_ws::MAX_QUEUED_UPSTREAM_FRAMES * 8;

    // An upstream that talks unprompted, as a realtime provider does: it pushes its whole output at
    // the socket without waiting to be asked.
    async fn ws_route(
        axum::extract::State(flood): axum::extract::State<usize>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        ws_ingress::accept(upgrade, move |_stream, mut sink| async move {
            for _ in 0..flood {
                if sink.send(b"upstream".to_vec()).await.is_err() {
                    break;
                }
            }
            std::future::pending::<()>().await;
        })
    }
    let app = axum::Router::new()
        .route("/", axum::routing::get(ws_route))
        .with_state(flood);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("ws://{addr}/");
    let (mut stream, _sink) = duplex_ws::dial(&url, loopback_policy())
        .await
        .expect("dial the flooding upstream");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Counted WITHOUT yielding, so the reader task cannot refill behind the count: this is what the
    // queue was holding at the moment the leg first looked at it.
    let mut queued = 0usize;
    while stream.next().now_or_never().flatten().is_some() {
        queued += 1;
    }
    assert!(
        queued <= crate::egress::duplex_ws::MAX_QUEUED_UPSTREAM_FRAMES + 1,
        "a flood of {flood} upstream frames left {queued} queued on an unread leg"
    );
}

/// AN UPSTREAM THAT HAS STOPPED ACCEPTING BYTES: every write pends forever, which is what a wedged
/// provider, a peer that stopped reading, or a socket a middlebox is holding open looks like from this
/// side. Reads pend too, so the session stays up — the stall is the whole point, not a disconnect.
struct StalledUpstreamIo;

impl tokio::io::AsyncRead for StalledUpstreamIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl tokio::io::AsyncWrite for StalledUpstreamIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// THE OTHER DIRECTION IS BOUND TOO. The inbound bounds above hold a fast peer off this node's heap;
/// this holds a fast PLANE off it when the SOCKET is the slow side. With the outbound queue unbounded,
/// a leg whose upstream has wedged goes on accepting frames at whatever rate the producer can write
/// them and the memory one session costs is decided by the producer alone — the stall is invisible to
/// it and paid for here. Bounded, the producer's own `send` stops completing once the queue is full,
/// which is the backpressure that charges the stall back to the side that is causing it. A relay has
/// two legs and two directions; a bound on three of the four is not a bound.
#[tokio::test]
async fn the_dialer_accepts_no_more_outbound_frames_than_its_bound_when_the_upstream_stalls() {
    let bound = crate::egress::duplex_ws::MAX_QUEUED_OUTBOUND_FRAMES;

    // A live client-role WS session over an upstream whose every write pends: the writer task takes
    // the first frame and never completes it, so from there on the queue is the only thing absorbing
    // what the producer writes — exactly the shape the bound exists for.
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        StalledUpstreamIo,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    let (mut sink, _stream) = crate::egress::duplex_ws::split_messages(ws);

    // Write far past the bound, counting only the frames the sink actually TOOK. A send that does not
    // complete promptly is backpressure — the sink refusing to grow — and ends the count.
    let flood = bound * 8;
    let mut accepted = 0usize;
    for _ in 0..flood {
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sink.send(b"outbound".to_vec()),
        )
        .await
        {
            Ok(Ok(())) => accepted += 1,
            // Either the sink pushed back (timeout) or the session ended — neither is unbounded growth.
            _ => break,
        }
    }

    assert!(
        accepted < flood,
        "a stalled upstream must not let the sink take all {flood} frames — that is unbounded growth"
    );
    // The channel's own guaranteed per-sender slot, plus the one frame the writer task pulled before
    // stalling, sit on top of the configured depth; the point is that the total is the BOUND and not
    // the flood.
    assert!(
        accepted <= bound + 4,
        "a stalled upstream left the sink taking {accepted} frames against a bound of {bound}"
    );
}

/// A BRACKETED IPv6 UPSTREAM IS A DIALLABLE TARGET. The authority split has to tell a literal's own
/// colons from a port separator, and the `]` tests are how: a left side ENDING in `]` is a bracketed
/// address followed by a real port, a right side CONTAINING one is the tail of the address itself.
/// Read the other way round, a bracketed host with a port can never be recognised at all — its host
/// comes back with the port still glued to it, which no resolver and no certificate name will match,
/// so the target is unreachable by construction rather than by policy.
#[test]
fn a_bracketed_ipv6_authority_splits_into_host_and_port() {
    // Bracketed literal WITH a port: the port is the port, and the host unbrackets to the address the
    // guard resolves and rustls offers for SNI.
    let (secure, host, port, _url) = super::split_ws_url("wss://[2001:db8::1]:443/x")
        .expect("a bracketed IPv6 host is a target");
    assert!(secure, "wss:// is the TLS scheme");
    assert_eq!(
        host, "2001:db8::1",
        "the host is the literal, without brackets"
    );
    assert_eq!(port, 443, "the trailing :443 after the `]` is the port");

    // Bracketed literal with NO port: every colon belongs to the address, and the scheme's default
    // port stands.
    let (_secure, host, port, _url) = super::split_ws_url("wss://[2001:db8::1]/x")
        .expect("a portless bracketed host is a target");
    assert_eq!(host, "2001:db8::1");
    assert_eq!(port, 443, "an absent port defaults by scheme");

    // The ordinary named host is unchanged by the same test — the split still reads a bare host's
    // trailing `:port` as a port.
    let (_secure, host, port, _url) =
        super::split_ws_url("wss://example.com:8443/x").expect("a named host is a target");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);
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
        // The accept fn takes the newtype BY VALUE — the single-compiled `WsArrival`, never a box — and
        // is ASYNC (returns a `WsAcceptFuture`) so a plane runs its pre-upgrade hooks before the upgrade.
        accept: std::sync::Arc::new(|_a: WsArrival| {
            Box::pin(async move {
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::NOT_IMPLEMENTED)
                    .body(axum::body::Body::empty())
                    .expect("response builds")
            }) as crate::ingress::duplex_ws::WsAcceptFuture
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
