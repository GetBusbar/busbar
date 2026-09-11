// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVING PATH OVER A REAL SOCKET, end to end.
//!
//! The mount's own battery beside this one proves the RULES — ordering, backpressure, which end cut,
//! one close per session — against fakes, because rules that can only be exercised through a socket
//! are rules that get tested for the happy path and reasoned about for the rest. What is left over
//! is everything that is only true of a real one, and that is what is here:
//!
//! * a Ping is answered on this wire and never reaches the pump;
//! * a peer's Close is the orderly end rather than a frame;
//! * the declaration's media type chooses between this wire's two frame kinds;
//! * a close code reaches the peer as this wire spells it;
//! * and the whole accept path — upgrade, address, open, pump, close — runs against a client that
//!   is a WebSocket library rather than a fixture.
//!
//! The declaration and the driver here are nobody's, for the reason the mount's battery states: what
//! is under test is the transport, and a battery that drove a real protocol through it would put a
//! plane's name in this crate's source, which the scan beside this file refuses outright.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use busbar_contract::Transport;
use busbar_contract_transport::driver::Outcome;
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::session::{
    redact_url_credentials, CredentialAt, Cut, DuplexWire, LegCredential, SessionDriver,
    SessionEnd, SessionFrame, SessionHandle, SessionOpen, SessionReply,
};
use busbar_contract_transport::surface::{
    Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};
use busbar_contract_transport::wire::CloseReason;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::conn::{LowerIo, Sock};
use crate::mount::{FrameSink, FrameSource, SessionBudgets};
use crate::session_io::{is_text_media, split};
use crate::WsTransport;
use busbar_contract_transport::session::EgressLease;

// ── a declaration that is nobody's ──────────────────────────────────────────────────────────────

const BINDINGS: &[BindingDecl] = &[BindingDecl {
    name: "duplex",
    transport: "ws",
    mounts: &["/session"],
}];

const OPERATIONS: &[Operation] = &[Operation {
    op: "turn",
    // The DUPLEX kind: a session is addressed by its binding, and after the upgrade there is no
    // document, no method and no target left for any other kind to be read from.
    dispatch: &[Dispatch::Duplex {
        binding: "duplex",
        method: "GET",
        bar: Bar::Credential,
    }],
    answering: Answering::Stream,
    request_media: "application/json",
    response_media: "application/json",
}];

const SURFACE: WireSurface = WireSurface {
    bindings: BINDINGS,
    operations: OPERATIONS,
};

// ── a driver that is nobody's ───────────────────────────────────────────────────────────────────

struct FakeDriver {
    answer: Result<SessionHandle, Outcome>,
    script: Mutex<VecDeque<SessionReply>>,
    opened: Mutex<Vec<(String, Option<String>)>>,
    seen: Mutex<Vec<Vec<u8>>>,
    closed: Mutex<Vec<SessionEnd>>,
}

impl FakeDriver {
    fn new(script: Vec<SessionReply>) -> Self {
        Self {
            answer: Ok(SessionHandle(7)),
            script: Mutex::new(script.into()),
            opened: Mutex::new(Vec::new()),
            seen: Mutex::new(Vec::new()),
            closed: Mutex::new(Vec::new()),
        }
    }

    fn refusing(outcome: Outcome) -> Self {
        Self {
            answer: Err(outcome),
            ..Self::new(Vec::new())
        }
    }
}

impl SessionDriver for FakeDriver {
    fn open(
        &self,
        open: SessionOpen<'_>,
        _surface: &WireSurface,
    ) -> Result<SessionHandle, Outcome> {
        self.opened.lock().expect("the log").push((
            open.fact(tfacts::PATH).unwrap_or_default().to_string(),
            open.fact(tfacts::CREDENTIAL).map(str::to_string),
        ));
        self.answer
    }

    fn drive(&self, _session: SessionHandle, frame: SessionFrame<'_>) -> SessionReply {
        self.seen
            .lock()
            .expect("the log")
            .push(frame.payload.to_vec());
        self.script
            .lock()
            .expect("the script")
            .pop_front()
            .unwrap_or_else(|| SessionReply::quiet(Outcome::Completed))
    }

    fn close(&self, _session: SessionHandle, end: SessionEnd) {
        self.closed.lock().expect("the log").push(end);
    }
}

fn reply(frames: &[&str], media: &str) -> SessionReply {
    SessionReply::frames(
        frames.iter().map(|f| f.as_bytes().to_vec()).collect(),
        media,
        Outcome::Completed,
    )
}

// ── one upgraded socket, both ends of it ────────────────────────────────────────────────────────

/// A connected pair of already-upgraded sockets over an in-memory duplex.
///
/// The server end is this crate's own socket type, which is what [`split`] takes; the client end is
/// the library's, driven directly, so what the assertions read is what a real peer would see rather
/// than what this crate believes it wrote.
async fn upgraded() -> (
    Sock,
    tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
) {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let server = tokio_tungstenite::accept_async(Box::new(a) as Box<dyn LowerIo>);
    let client = tokio_tungstenite::client_async("ws://127.0.0.1:44411/session", b);
    let (server, client) = tokio::join!(server, client);
    (
        server.expect("the server end upgrades"),
        client.expect("the client end upgrades").0,
    )
}

/// A PING IS ANSWERED ON THIS WIRE AND NEVER REACHES THE PUMP.
///
/// Both halves. The peer gets its Pong, which is the obligation; and the source's next answer is the
/// DATA frame that followed it, not the keepalive — a pump handed a Ping would be a pump that had to
/// know what a Ping is, and a plane handed one would be handed a byte the peer never sent it.
#[tokio::test]
async fn a_ping_is_answered_here_and_never_handed_up() {
    let (server, mut client) = upgraded().await;
    let (mut source, _sink) = split(server);

    client
        .send(Message::Ping(b"are you there".to_vec().into()))
        .await
        .expect("the peer pings");
    client
        .send(Message::Text("after the ping".into()))
        .await
        .expect("the peer speaks");

    let frame = source
        .next_frame()
        .await
        .expect("the session did not end")
        .expect("the read did not fail");
    assert_eq!(
        frame,
        b"after the ping".to_vec(),
        "the frame the source yielded is the data one, not the keepalive"
    );

    let answered = client.next().await.expect("the peer is owed a pong");
    assert_eq!(
        answered.expect("the pong arrived"),
        Message::Pong(b"are you there".to_vec().into()),
        "the payload comes back unchanged, which is what a pong is"
    );
}

/// A peer's Close is the ORDERLY end of the session, not a frame of it.
#[tokio::test]
async fn a_peer_that_closes_ends_the_source_rather_than_yielding_a_frame() {
    let (server, mut client) = upgraded().await;
    let (mut source, _sink) = split(server);

    client.close(None).await.expect("the peer closes");

    assert!(
        source.next_frame().await.is_none(),
        "a close is the end of the stream, and handing it up as bytes would hand a plane a byte \
         the peer never sent it"
    );
}

/// THE DECLARATION CHOOSES THE FRAME KIND, and this wire has two.
///
/// A wire with one kind ignores the media type. This one reads it, and nothing else about the bytes
/// is looked at — the payload is the plane's, whole, either way.
#[tokio::test]
async fn the_declared_media_chooses_this_wires_frame_kind() {
    let (server, mut client) = upgraded().await;
    let (_source, mut sink) = split(server);

    sink.write_frame(br#"{"kind":"turn"}"#, "application/json")
        .await
        .expect("the write lands");
    sink.write_frame(b"\x00\x01\x02", "application/octet-stream")
        .await
        .expect("the write lands");

    assert_eq!(
        client.next().await.expect("a frame").expect("no failure"),
        Message::Text(r#"{"kind":"turn"}"#.into()),
        "a declared JSON media type is a text frame on this wire"
    );
    assert_eq!(
        client.next().await.expect("a frame").expect("no failure"),
        Message::Binary(vec![0, 1, 2].into()),
        "anything else is bytes, which is the safe answer for an unstated encoding"
    );
}

/// The media rule is the media registry's own, not a list of protocols.
#[test]
fn the_media_rule_reads_the_registrys_own_shape() {
    for text in [
        "text/plain",
        "text/event-stream",
        "application/json",
        "application/json; charset=utf-8",
        "application/vnd.example+json",
    ] {
        assert!(is_text_media(text), "`{text}` is a text frame on this wire");
    }
    for bytes in [
        "application/octet-stream",
        "audio/pcm",
        "application/grpc",
        "",
    ] {
        assert!(!is_text_media(bytes), "`{bytes}` is a binary frame");
    }
}

/// A payload the declaration called text and that is not valid UTF-8 is DELIVERED, as bytes.
///
/// Sending it as a text frame would put invalid UTF-8 in a frame whose kind promises otherwise,
/// which every conforming peer must fail the connection on. The disagreement is the declaration's to
/// fix; neither answer is this transport's to invent, so it delivers what the plane actually wrote.
#[tokio::test]
async fn text_declared_over_bytes_that_are_not_text_is_still_delivered() {
    let (server, mut client) = upgraded().await;
    let (_source, mut sink) = split(server);

    sink.write_frame(&[0xff, 0xfe], "application/json")
        .await
        .expect("the write lands");

    assert_eq!(
        client.next().await.expect("a frame").expect("no failure"),
        Message::Binary(vec![0xff, 0xfe].into())
    );
}

/// The close code this wire spells reaches the peer as a close code.
#[tokio::test]
async fn the_close_code_reaches_the_peer() {
    let (server, mut client) = upgraded().await;
    let (_source, mut sink) = split(server);

    sink.write_close(1011).await;

    let closed = client.next().await.expect("a frame").expect("no failure");
    let Message::Close(Some(frame)) = closed else {
        panic!("the peer is owed a close frame with a code: {closed:?}");
    };
    assert_eq!(u16::from(frame.code), 1011);
}

// ── the whole accept path, against a client that is a library ───────────────────────────────────

/// The battery beside this one already forges a seal, and there is exactly one in this crate's test
/// tree on purpose: a second implementation of the contract's sealing trait is a second place a
/// forged seal can be written, which is what the construction gate counts.
use crate::battery::test_key_handle;

/// One upgrade request, as a client library builds one.
fn upgrade_request(
    addr: &str,
    target: &str,
    credential: Option<&str>,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(format!("ws://{addr}{target}"))
        .header("Host", addr)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        );
    if let Some(credential) = credential {
        builder = builder.header("Authorization", credential);
    }
    builder.body(()).expect("the upgrade request builds")
}

/// Dial the listener and run the upgrade, from a client that is a library rather than a fixture.
async fn dial(
    addr: &str,
    target: &str,
    credential: Option<&str>,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    tokio_tungstenite::tungstenite::Error,
> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the listener is bound");
    tokio_tungstenite::client_async(upgrade_request(addr, target, credential), tcp)
        .await
        .map(|(client, _response)| client)
}

/// A `ws` over `http` listener, and the address it bound.
async fn listening() -> (Arc<WsTransport>, busbar_contract_transport::wire::Listener) {
    let http = Arc::new(busbar_transport_http::HttpTransport::new(
        busbar_transport_http::ClientSettings::default(),
    ));
    let ws = Arc::new(WsTransport::over(http));
    let listener = ws
        .listen(
            &crate::StaticConfig::bind_to("127.0.0.1:0"),
            &test_key_handle(),
        )
        .await
        .expect("the listener binds");
    (ws, listener)
}

/// THE WHOLE PATH: upgrade, address, open, pump, close — against a real WebSocket client.
///
/// The credential the client presented reaches the driver's `open`, which is the fact that has no
/// second chance: after the upgrade there is no request left to carry one. The frame reaches
/// `drive`, the answer comes back on the wire under the DECLARATION's media type, and the peer's own
/// close is reported as the client's cut with the driver closed exactly once.
#[tokio::test]
async fn the_accept_path_opens_pumps_and_closes_one_session() {
    let (ws, listener) = listening().await;
    let addr = listener.local_addr();
    let driver = Arc::new(FakeDriver::new(vec![reply(
        &[r#"{"kind":"turn"}"#],
        "application/json",
    )]));

    let served = {
        let (ws, driver) = (ws.clone(), driver.clone());
        tokio::spawn(async move {
            ws.serve_accept(
                &listener,
                driver.as_ref(),
                &SURFACE,
                SessionBudgets::default(),
            )
            .await
        })
    };

    let mut client = dial(&addr, "/session", Some("Bearer sk-44401"))
        .await
        .expect("the upgrade is accepted");

    client
        .send(Message::Text(r#"{"kind":"start"}"#.into()))
        .await
        .expect("the client speaks");
    let answered = client.next().await.expect("an answer").expect("no failure");
    assert_eq!(
        answered,
        Message::Text(r#"{"kind":"turn"}"#.into()),
        "the plane's bytes came back under the declaration's own media type"
    );

    client.close(None).await.expect("the client closes");
    let end = served
        .await
        .expect("the served task finished")
        .expect("the session ran");

    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Client,
            reason: CloseReason::PeerClosed
        }
    );
    assert_eq!(
        driver.opened.lock().expect("the log").as_slice(),
        [("/session".to_string(), Some("Bearer sk-44401".to_string()))],
        "the target and the credential the upgrade carried both reached the open"
    );
    assert_eq!(
        driver.seen.lock().expect("the log").as_slice(),
        [br#"{"kind":"start"}"#.to_vec()]
    );
    assert_eq!(
        driver.closed.lock().expect("the log").len(),
        1,
        "one ending, one close"
    );
}

/// A DRIVER THAT WILL NOT OPEN A SESSION IS ANSWERED WITH A STATUS, AND NEVER UPGRADED.
///
/// This is the whole reason the addressing and the open run inside the upgrade callback rather than
/// after it. The caller is refused on the protocol it spoke, in a field that protocol has; a node
/// that upgraded first and then closed would have told the caller yes and then cut it, with a close
/// code arriving after the client library had already reported success.
#[tokio::test]
async fn a_refused_open_is_answered_before_the_protocol_changes() {
    let (ws, listener) = listening().await;
    let addr = listener.local_addr();
    let driver = Arc::new(FakeDriver::refusing(Outcome::Unauthenticated));

    let served = {
        let (ws, driver) = (ws.clone(), driver.clone());
        tokio::spawn(async move {
            ws.serve_accept(
                &listener,
                driver.as_ref(),
                &SURFACE,
                SessionBudgets::default(),
            )
            .await
        })
    };

    let refused = dial(&addr, "/session", None).await.map(|_| ());
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = refused else {
        panic!("the upgrade must be refused with an HTTP status, not accepted: {refused:?}");
    };
    assert_eq!(
        response.status().as_u16(),
        401,
        "the eight words are spelled onto the leg underneath by the same mapping the one-shot \
         mount uses"
    );

    assert!(
        served.await.expect("the served task finished").is_err(),
        "a session that never opened is not a session that ran"
    );
    assert!(
        driver.closed.lock().expect("the log").is_empty(),
        "a session that never opened is never closed"
    );
}

/// A target no binding of this transport declares is answered with the status a mounted surface
/// already uses for one, and never upgraded.
#[tokio::test]
async fn an_unaddressed_target_never_upgrades() {
    let (ws, listener) = listening().await;
    let addr = listener.local_addr();
    let driver = Arc::new(FakeDriver::new(Vec::new()));

    let served = {
        let (ws, driver) = (ws.clone(), driver.clone());
        tokio::spawn(async move {
            ws.serve_accept(
                &listener,
                driver.as_ref(),
                &SURFACE,
                SessionBudgets::default(),
            )
            .await
        })
    };

    let refused = dial(&addr, "/nowhere", None).await.map(|_| ());
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = refused else {
        panic!("an undeclared target must not upgrade: {refused:?}");
    };
    assert_eq!(response.status().as_u16(), 404);
    assert!(
        driver.opened.lock().expect("the log").is_empty(),
        "the driver was never asked about a target no declaration names"
    );
    let _ = served.await;
}

// ── the split, and the drain it is there for ────────────────────────────────────────────────────
//
// An acceptor that has to answer a stop needs to know which of two situations it is in: WAITING, in
// which nothing has been accepted and nobody has been told yes, or MID-SESSION, in which a caller is
// being served and is owed the session they were promised. The cells below prove the transport
// reports the boundary between the two — and it reports it by RETURNING, which is a thing an acceptor
// can hold rather than a flag it has to remember to read.
//
// None of them names a plane. What drains is a session, and every plane's sessions drain the same
// way for the same reason.

/// THE OPEN IS REPORTED BEFORE ONE FRAME IS PUMPED.
///
/// The cell the split exists for. The client has upgraded AND has already sent a frame, and
/// `serve_upgrade` still comes back with the session open and the driver's `drive` never called. An
/// acceptor therefore learns "a session is open" at a moment when nothing about that session has yet
/// happened, which is the only moment at which taking responsibility for finishing it is a promise
/// it can still keep.
#[tokio::test]
async fn the_upgrade_reports_an_open_session_before_the_pump_starts() {
    let (ws, listener) = listening().await;
    let addr = listener.local_addr();
    let driver = Arc::new(FakeDriver::new(vec![reply(
        &[r#"{"kind":"turn"}"#],
        "application/json",
    )]));

    let client = tokio::spawn(async move {
        let mut client = dial(&addr, "/session", Some("Bearer sk-44401"))
            .await
            .expect("the upgrade is accepted");
        client
            .send(Message::Text(r#"{"kind":"start"}"#.into()))
            .await
            .expect("the client speaks");
        client
    });

    let open = ws
        .serve_upgrade(&listener, driver.as_ref(), &SURFACE)
        .await
        .expect("the declared mount opens a session");

    assert_eq!(
        driver.opened.lock().expect("the log").as_slice(),
        [("/session".to_string(), Some("Bearer sk-44401".to_string()))],
        "the session is open by the time the waiting half returns"
    );
    assert!(
        driver.seen.lock().expect("the log").is_empty(),
        "and not one frame has been driven — the pump has not started"
    );
    assert!(
        driver.closed.lock().expect("the log").is_empty(),
        "nor has anything ended"
    );

    // The handle is readable without consuming the value, because an acceptor recording what it has
    // open has to name it before it hands it to the pump — and after the pump has been handed the
    // value there is nothing left to ask.
    assert_eq!(
        open.session(),
        SessionHandle(7),
        "the acceptor can name the session it is now responsible for"
    );

    let mut client = client.await.expect("the client task finished");
    let pumped = {
        let (ws, driver) = (ws.clone(), driver.clone());
        tokio::spawn(async move {
            ws.pump_session(open, driver.as_ref(), SessionBudgets::default())
                .await
        })
    };
    let answered = client.next().await.expect("an answer").expect("no failure");
    assert_eq!(answered, Message::Text(r#"{"kind":"turn"}"#.into()));
    client.close(None).await.expect("the client closes");
    let end = pumped.await.expect("the pump finished");

    assert_eq!(
        driver.seen.lock().expect("the log").as_slice(),
        [br#"{"kind":"start"}"#.to_vec()],
        "the frame the client sent before the pump started is not lost by the split"
    );
    assert_eq!(end.cut, Cut::Client);
    assert_eq!(
        driver.closed.lock().expect("the log").len(),
        1,
        "one ending, one close"
    );
}

/// A STOP WHILE WAITING OPENS NOTHING, AND OWES NOBODY ANYTHING.
///
/// The first half of a drain. The acceptor is racing a stop against the waiting half, no connection
/// arrives, and the stop wins: the `serve_upgrade` future is DROPPED. Everything it held is this
/// node's own — a pending accept, no caller answered — so the drop is a connection not taken rather
/// than a session cut, and the driver is never asked to open anything.
///
/// This is exactly why the cut is where it is. An acceptor holding one accept-upgrade-open-and-pump
/// future would have to cancel a future that MIGHT be mid-session, and could not tell which.
#[tokio::test]
async fn a_stop_while_waiting_drops_the_wait_and_opens_nothing() {
    let (ws, listener) = listening().await;
    let driver = Arc::new(FakeDriver::new(Vec::new()));
    let stop = tokio::sync::Notify::new();

    let raced = tokio::select! {
        // Biased so the cell tests the stop arm rather than the scheduler's mood: nothing is going
        // to connect to this listener, so the other arm would never be ready anyway, and pinning the
        // order is what keeps this from being a race that passes for the wrong reason.
        biased;
        () = async { stop.notify_one(); stop.notified().await } => None,
        opened = ws.serve_upgrade(&listener, driver.as_ref(), &SURFACE) => Some(opened.is_ok()),
    };

    assert!(raced.is_none(), "the stop won, and the wait was dropped");
    assert!(
        driver.opened.lock().expect("the log").is_empty(),
        "no caller was answered, so no session was opened and none is draining"
    );
    assert!(driver.closed.lock().expect("the log").is_empty());
}

/// A STOP MID-SESSION FINISHES THE SESSION IT ALREADY OPENED.
///
/// The other half. The acceptor is holding an [`crate::OpenSession`] — a caller has been told yes —
/// and the stop arrives. Draining means the acceptor refuses to wait for a NEW upgrade and still
/// runs this one to its own ending: the frames the peer sends are answered, the peer's own close
/// ends it, and the driver's `close` is called exactly once.
///
/// The ownership is the whole mechanism. The stop cannot cut this session because the session is a
/// value the acceptor is holding, and there is no way to abandon it that is not visible as a value
/// nobody moved into the pump.
#[tokio::test]
async fn a_stop_mid_session_still_finishes_the_open_session() {
    let (ws, listener) = listening().await;
    let addr = listener.local_addr();
    let driver = Arc::new(FakeDriver::new(vec![reply(
        &[r#"{"kind":"turn"}"#],
        "application/json",
    )]));
    let stop = tokio::sync::Notify::new();

    let client = tokio::spawn(async move {
        dial(&addr, "/session", Some("Bearer sk-44401"))
            .await
            .expect("the upgrade is accepted")
    });
    let open = ws
        .serve_upgrade(&listener, driver.as_ref(), &SURFACE)
        .await
        .expect("the declared mount opens a session");
    let mut client = client.await.expect("the client task finished");

    // THE STOP, arriving with a session already open. An acceptor holding one goes no further round
    // its loop; what it does NOT do is drop what it is holding.
    stop.notify_one();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(0), stop.notified())
            .await
            .is_ok(),
        "the stop is standing before the session is pumped"
    );

    let pumped = {
        let (ws, driver) = (ws.clone(), driver.clone());
        tokio::spawn(async move {
            ws.pump_session(open, driver.as_ref(), SessionBudgets::default())
                .await
        })
    };

    client
        .send(Message::Text(r#"{"kind":"start"}"#.into()))
        .await
        .expect("a draining node still serves the session it opened");
    let answered = client.next().await.expect("an answer").expect("no failure");
    assert_eq!(answered, Message::Text(r#"{"kind":"turn"}"#.into()));
    client.close(None).await.expect("the client closes");

    let end = pumped.await.expect("the pump finished");
    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Client,
            reason: CloseReason::PeerClosed
        },
        "the session ended on its own terms and not on the stop's"
    );
    assert_eq!(
        driver.closed.lock().expect("the log").len(),
        1,
        "one ending, one close, drain or no drain"
    );
}

// ── the face, over a real socket ────────────────────────────────────────────────────────────────

/// An acceptor written against the SEAM and against no wire, in the shape a composition root's is.
///
/// It is generic over the wire and holds none of its vocabulary: not its key, not its type, not what
/// a frame of it is. Everything the cells above proved about this transport's two halves, they prove
/// about a value reached through here — which is the whole content of the claim that the wire
/// implements the face rather than merely resembling it.
async fn accept_one<W: busbar_contract_transport::session::DuplexWire>(
    wire: &W,
    l: &busbar_contract_transport::wire::Listener,
    driver: &dyn SessionDriver,
    surface: &WireSurface,
) -> Result<SessionEnd, busbar_contract_transport::wire::TransportError> {
    let open = wire.serve_upgrade(l, driver, surface).await?;
    Ok(wire
        .pump_session(open, driver, SessionBudgets::default())
        .await)
}

/// THIS WIRE IS A `DuplexWire`, PROVED WHERE IT COSTS: on a real upgrade, over a real socket.
///
/// The generic acceptor above takes this transport, waits for one upgrade off the node's own bound
/// listener, and finishes the session it opens — and never names a WebSocket, a message, a close
/// code or this crate's own types. A composition root written the same way therefore serves this
/// wire without holding it by its concrete type, which is what keeps the wire registered in exactly
/// one place.
///
/// The cell is here rather than at the seam because this is where the socket is. The seam's own
/// battery drives a wire that does not exist, so it can prove what the FACE decides and nothing
/// about what a real upgrade does; this one is the other half, and neither stands alone.
#[tokio::test]
async fn the_generic_acceptor_serves_this_wire_over_a_real_socket() {
    let (ws, listener) = listening().await;
    let addr = listener.local_addr();
    let driver = Arc::new(FakeDriver::new(vec![reply(
        &[r#"{"kind":"turn"}"#],
        "application/json",
    )]));

    let client = tokio::spawn(async move {
        let mut client = dial(&addr, "/session", Some("Bearer sk-44401"))
            .await
            .expect("the upgrade is accepted");
        client
            .send(Message::Text(r#"{"kind":"start"}"#.into()))
            .await
            .expect("the client speaks");
        let answered = client.next().await.expect("an answer").expect("no failure");
        client.close(None).await.expect("the client closes");
        answered
    });

    let end = accept_one(ws.as_ref(), &listener, driver.as_ref(), &SURFACE)
        .await
        .expect("the declared mount opens a session on the face");

    assert_eq!(
        client.await.expect("the client task finished"),
        Message::Text(r#"{"kind":"turn"}"#.into()),
        "the plane's own bytes went back over the real wire"
    );
    assert_eq!(end.cut, Cut::Client);
    assert_eq!(end.reason, CloseReason::PeerClosed);
    assert_eq!(
        driver.seen.lock().expect("the log").as_slice(),
        [br#"{"kind":"start"}"#.to_vec()],
        "one frame in, driven through the seam"
    );
    assert_eq!(
        driver.closed.lock().expect("the log").len(),
        1,
        "one ending, one close"
    );
}

// ── the upstream leg: the bounded lease and the drain that is returned, not spawned ─────────────

/// THE LEASE REFUSES AT DEPTH rather than waiting, and that is the whole reason it is bounded.
///
/// The offering end is reached from a SYNCHRONOUS driver, so there is no answer between "took it"
/// and "did not": a lease that waited would suspend the session's one thread behind an upstream that
/// stopped reading, and a lease that grew would let that upstream decide how much of this node's
/// memory one session costs. So the depth is the ceiling and the refusal is one of the words the
/// session already knows how to answer with.
///
/// The drain is deliberately NOT spawned here — it is a value this test holds and never polls, which
/// is exactly the "upstream that stopped reading" the bound exists for.
#[tokio::test]
async fn the_lease_refuses_at_depth_instead_of_waiting() {
    let (server, _client) = upgraded().await;
    let (_source, sink) = split(server);
    let (mut lease, _drain) = crate::session_io::lease(2, sink, "application/json");

    assert!(
        lease.offer(b"one").is_ok(),
        "a lease with room takes the frame"
    );
    assert!(
        lease.offer(b"two").is_ok(),
        "a lease with room takes the frame"
    );
    assert_eq!(
        lease.offer(b"three"),
        Err(busbar_contract_transport::wire::TransportError::Backpressure),
        "at depth the answer is one of the eight words, not a wait: the session owns the leg and \
         is the only thing with a vocabulary for what to do about it"
    );
}

/// FINISHING THE LEASE ends the leg: the drain writes what it holds, in order, then the close, and
/// every later offer answers `Closed`.
///
/// Both halves matter. The peer is owed the frames already offered — a finish that dropped them
/// would be this node losing a session's tail — and it is owed the close its own protocol defines,
/// because this node opened the leg. And the lease answering `Closed` afterwards is what a driver
/// that offers again learns from; there is no third party to retry against.
#[tokio::test]
async fn finishing_the_lease_drains_what_it_holds_and_closes_the_leg() {
    let (server, mut client) = upgraded().await;
    let (_source, sink) = split(server);
    let (mut lease, drain) = crate::session_io::lease(
        busbar_contract_transport::session::EGRESS_DEPTH,
        sink,
        "application/json",
    );

    lease.offer(br#"{"seq":0}"#).expect("the lease takes it");
    lease.offer(br#"{"seq":1}"#).expect("the lease takes it");
    lease.finish();
    assert_eq!(
        lease.offer(br#"{"seq":2}"#),
        Err(busbar_contract_transport::wire::TransportError::Closed),
        "a finished lease is over, and an offer to it is not a frame anything will ever send"
    );

    // The composition spawns the drain; the transport only handed it back. Awaiting it here is this
    // test standing in for that owner, and it returns because the lease was finished.
    drain.await;

    assert_eq!(
        client.next().await.expect("a frame").expect("no failure"),
        Message::Text(r#"{"seq":0}"#.into()),
        "in order, and in the frame kind the declaration named"
    );
    assert_eq!(
        client.next().await.expect("a frame").expect("no failure"),
        Message::Text(r#"{"seq":1}"#.into()),
        "the frame offered before the finish is still owed to the peer"
    );
    assert!(
        matches!(
            client.next().await.expect("a close").expect("no failure"),
            Message::Close(_)
        ),
        "an upstream this node opened is owed the close its protocol defines"
    );
}

/// THE UPSTREAM LEG, DIALLED: one real socket, three owners, and the ownership move that makes it
/// one.
///
/// What the cell holds the call to is the arrangement rather than the bytes. The dial is the
/// transport's own — the same [`busbar_contract::Transport::dial`] every other caller reaches, so
/// there is no second dialling path and the `wss://`-over-cleartext refusal is not re-implemented
/// here. What is added is that the socket comes out WHOLE: the connection has left the registry, the
/// read half is a `FrameSource` something can pump, the write half is only reachable through the
/// lease, and the drain is a value this test spawns because a transport that spawned it would be
/// choosing the composition's runtime.
#[tokio::test]
async fn dialling_a_session_hands_back_the_source_the_lease_and_an_unspawned_drain() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the upstream binds");
    let addr = upstream.local_addr().expect("the upstream has an address");

    // A provider that speaks WebSocket and nothing else: it echoes the one frame it is offered and
    // then closes, which is all this cell needs from the far end.
    let provider = tokio::spawn(async move {
        let (tcp, _peer) = upstream.accept().await.expect("the leg arrives");
        let mut sock = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("the leg upgrades");
        let offered = sock.next().await.expect("a frame").expect("no failure");
        sock.send(Message::Text(r#"{"kind":"provider"}"#.into()))
            .await
            .expect("the provider answers");
        sock.close(None).await.expect("the provider closes");
        offered
    });

    let ws = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    let host: &'static str = Box::leak(format!("ws://{addr}/leg").into_boxed_str());
    let (mut source, mut lease, drain) = crate::mount::dial_session(
        &ws,
        &crate::battery::verified_upstream(host),
        &test_key_handle(),
        // This destination's dialect declares no credential, so the dial is the one it always was.
        None,
        "application/json",
        busbar_contract_transport::session::EGRESS_DEPTH,
    )
    .await
    .expect("the leg dials");

    // The composition's job, not the transport's: the drain is a value that was handed back.
    let drain = tokio::spawn(drain);

    lease
        .offer(br#"{"kind":"ingress"}"#)
        .expect("the lease takes the frame");
    lease.finish();

    assert_eq!(
        provider.await.expect("the provider finished"),
        Message::Text(r#"{"kind":"ingress"}"#.into()),
        "what the driver offered reached the far end of the leg, in the declared frame kind"
    );
    let answered = source
        .next_frame()
        .await
        .expect("the leg did not end first")
        .expect("the read did not fail");
    assert_eq!(
        answered,
        br#"{"kind":"provider"}"#.to_vec(),
        "the inbound half is a FrameSource, which is the same face the client half is pumped through"
    );
    assert!(
        source.next_frame().await.is_none(),
        "the provider's close is the orderly end of the leg"
    );
    drain.await.expect("the drain finished");
}

/// A DIALECT THAT DECLARES A QUERY CREDENTIAL DIALS WITH IT — and the secret rides the ONE handshake
/// rather than the sealed destination.
///
/// The measurement this stands on is that one duplex vendor's native scheme puts the API key in the
/// URL's query string, and until this face existed the only code that could put it there was a
/// vendor-named `format!` in a plane's own mount. What is asserted is the whole of the arrangement:
/// the far end sees the declared parameter carrying the declared secret on the upgrade's request
/// line; the destination this leg was sealed from still carries only host and port (an
/// `&'static str` authority is interned for the life of the process, so a credential in it would
/// outlive every session that used it); and the one redactor takes it back out of anything about to
/// be logged.
// The upgrade-inspecting callback's refusal arm is `tungstenite`'s own `ErrorResponse`, a whole HTTP
// response by value. Nothing here ever takes that arm — the cell admits every upgrade and only
// RECORDS what arrived — and the size of a foreign crate's error type is not a thing this cell can
// box away without wrapping the callback face it is handed.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn a_declared_query_credential_rides_the_upgrade_and_never_the_sealed_destination() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the upstream binds");
    let addr = upstream.local_addr().expect("the upstream has an address");

    // A provider that reports the request line it was dialled with, then closes.
    let provider = tokio::spawn(async move {
        let (tcp, _peer) = upstream.accept().await.expect("the leg arrives");
        let seen = Arc::new(Mutex::new(String::new()));
        let record = Arc::clone(&seen);
        let mut sock = tokio_tungstenite::accept_hdr_async(
            tcp,
            move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                *record.lock().expect("the recorder is not poisoned") = req.uri().to_string();
                Ok(resp)
            },
        )
        .await
        .expect("the leg upgrades");
        sock.close(None).await.expect("the provider closes");
        let uri = seen.lock().expect("the recorder is not poisoned").clone();
        uri
    });

    let ws = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    let host: &'static str = Box::leak(format!("ws://{addr}/leg").into_boxed_str());
    let dest = crate::battery::verified_upstream(host);
    let (mut source, _lease, drain) = crate::mount::dial_session(
        &ws,
        &dest,
        &test_key_handle(),
        Some(LegCredential {
            at: CredentialAt::Query("key"),
            secret: "s3cr3t-provider-key",
        }),
        "application/json",
        busbar_contract_transport::session::EGRESS_DEPTH,
    )
    .await
    .expect("the leg dials");
    let drain = tokio::spawn(drain);

    let seen = provider.await.expect("the provider finished");
    assert_eq!(
        seen, "/leg?key=s3cr3t-provider-key",
        "the declared parameter carried the declared secret on the upgrade the dialect asked for"
    );
    assert!(
        !format!("{:?}", dest.facts()).contains("s3cr3t-provider-key"),
        "the sealed destination is interned for the life of the process; the credential is built \
         for one handshake and never reaches it"
    );
    assert_eq!(
        redact_url_credentials("ws dial refused: ws://host/leg?key=s3cr3t-provider-key"),
        "ws dial refused: ws://host/leg?key=<redacted>",
        "the one redactor takes the secret back out of anything about to be logged or recorded"
    );

    assert!(
        source.next_frame().await.is_none(),
        "the provider's close is the orderly end of the leg"
    );
    drain.await.expect("the drain finished");
}

/// A DECLARED HEADER CREDENTIAL rides the upgrade's headers, and the URL is untouched.
///
/// The other arm of the same declaration, and it is a cell rather than a comment because the two
/// arms take genuinely different code paths through the handshake: one rewrites a URL, one builds a
/// client request. A dialect that declares the header form and silently dialled with the URL form
/// would reach its provider unauthenticated, which is the failure this whole face exists to close.
// The upgrade-inspecting callback's refusal arm is `tungstenite`'s own `ErrorResponse`, a whole HTTP
// response by value. Nothing here ever takes that arm — the cell admits every upgrade and only
// RECORDS what arrived — and the size of a foreign crate's error type is not a thing this cell can
// box away without wrapping the callback face it is handed.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn a_declared_header_credential_rides_the_upgrade_headers_and_not_the_url() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the upstream binds");
    let addr = upstream.local_addr().expect("the upstream has an address");

    let provider = tokio::spawn(async move {
        let (tcp, _peer) = upstream.accept().await.expect("the leg arrives");
        let seen = Arc::new(Mutex::new((String::new(), String::new())));
        let record = Arc::clone(&seen);
        let mut sock = tokio_tungstenite::accept_hdr_async(
            tcp,
            move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                *record.lock().expect("the recorder is not poisoned") =
                    (req.uri().to_string(), auth);
                Ok(resp)
            },
        )
        .await
        .expect("the leg upgrades");
        sock.close(None).await.expect("the provider closes");
        let pair = seen.lock().expect("the recorder is not poisoned").clone();
        pair
    });

    let ws = WsTransport::over(Arc::new(busbar_transport_tcp::TcpTransport::new()));
    let host: &'static str = Box::leak(format!("ws://{addr}/leg").into_boxed_str());
    let (mut source, _lease, drain) = crate::mount::dial_session(
        &ws,
        &crate::battery::verified_upstream(host),
        &test_key_handle(),
        Some(LegCredential {
            at: CredentialAt::Header("authorization"),
            secret: "Bearer s3cr3t-provider-key",
        }),
        "application/json",
        busbar_contract_transport::session::EGRESS_DEPTH,
    )
    .await
    .expect("the leg dials");
    let drain = tokio::spawn(drain);

    let (uri, auth) = provider.await.expect("the provider finished");
    assert_eq!(
        auth, "Bearer s3cr3t-provider-key",
        "the declared header carried the declared secret"
    );
    assert_eq!(
        uri, "/leg",
        "and the URL is the destination's own — a header credential puts nothing in a query string"
    );

    assert!(
        source.next_frame().await.is_none(),
        "the provider's close is the orderly end of the leg"
    );
    drain.await.expect("the drain finished");
}
