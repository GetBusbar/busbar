// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FULL-DUPLEX WEBSOCKET INGRESS ACCEPTOR — the inbound half of the WS transport: accept an
//! HTTP→WS upgrade and present the upgraded socket as the message [`Stream`]`<Item = Vec<u8>>` +
//! [`Sink`]`<Vec<u8>>` pair that [`crate::ingress::byte_duplex::serve_messages`] consumes.
//!
//! ## THE UPGRADE STAYS AT THE BOUNDARY, OUT OF THE PUMP
//!
//! The HTTP handshake and the router path that carries it are transport concerns, so they live HERE at
//! the acceptor — never in the neutral pump, which names no protocol and reads only `Vec<u8>` frames.
//! [`accept`] takes the axum [`WebSocketUpgrade`] extractor a data route received, and on upgrade hands
//! the plane the split socket as the frame channel. A caller that wants the raw channel (to funnel one socket's
//! write side elsewhere, as a proxy topology does) uses [`channel`] on the already-upgraded socket.
//!
//! Text and binary WS messages both arrive as `Vec<u8>` frames; control frames (ping/pong/close) are
//! answered by the WS layer and never surface as frames. A frame written back is sent as ONE binary WS
//! message — the plane maps its own wire (text or binary) to bytes at this boundary and the pump stays
//! framing-agnostic, exactly as its `serve_messages` header describes.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures::channel::mpsc::{channel as bounded, unbounded, Receiver, UnboundedSender};
use futures::{SinkExt, StreamExt};

/// How many inbound frames one accepted socket may hold for a reader that has not taken them yet. The
/// queue is what stands between a client's write rate and this node's memory: unbounded, every frame a
/// client can push through the socket is held here and the client alone decides what a session costs.
/// At the bound the acceptor's reader stops taking frames off the socket, so the backlog stays on the
/// client's own transport — where TCP already knows how to hold it — instead of on this node's heap.
/// Deep enough that ordinary jitter between a peer's writes and a plane's reads never touches it.
pub(crate) const MAX_QUEUED_INBOUND_FRAMES: usize = 64;

/// The largest inbound WS message (and single frame) this acceptor will take, in bytes.
///
/// A frame bound is a different defence from the queue bound above and neither substitutes for the
/// other: the queue caps how MANY frames may wait, this caps how BIG one of them may be, and without
/// it a peer needs a single message to make the socket's own reassembly buffer as large as it likes —
/// the counted-frames bound never even sees it, because the message is still being assembled. So the
/// cap is the deployment's request-body ceiling, `limits.request_body_max_bytes`, read through the
/// SAME resolved limits every other reader of that knob uses. That is the same reasoning the
/// standalone `ws` transport applies at its own listener: a WebSocket message and an HTTP body are
/// one thing to an operator sizing a limit, and a WS door that buffered more than the HTTP door
/// beside it would be a hole nobody declared. Both the message and the frame ceiling are set,
/// because a message ceiling alone still lets one oversized FRAME be buffered before the message is
/// refused. With nothing installed (boot, or a test process) the historical default stands, exactly
/// as every other accessor of these limits resolves an absent install.
fn max_inbound_message_bytes() -> usize {
    crate::config::limits::installed()
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(crate::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES)
}

/// Bridge an already-upgraded [`WebSocket`] into the neutral `(frame-stream, frame-sink)` the pump
/// speaks, over two mpsc channels (both `Unpin + Send`, the shape `serve_messages` requires): inbound
/// text/binary → one `Vec<u8>` frame; an outbound frame → one binary WS message. Control frames and
/// receive errors are dropped so only data payloads cross; the peer's close ends the inbound stream —
/// the message-duplex analogue of EOF — and dropping the outbound sink closes the socket.
///
/// The INBOUND half is bounded at [`MAX_QUEUED_INBOUND_FRAMES`]: the reader awaits capacity rather
/// than queueing whatever arrives, so a client outrunning its own session is held by TCP and not by
/// this node's memory. The OUTBOUND half stays unbounded — its producer is the plane, whose frames are
/// answers this side has already committed to, and blocking a handler on the socket's write rate would
/// stall the very session it is answering.
pub fn channel(socket: WebSocket) -> (Receiver<Vec<u8>>, UnboundedSender<Vec<u8>>) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut in_tx, in_rx) = bounded::<Vec<u8>>(MAX_QUEUED_INBOUND_FRAMES);
    let (out_tx, mut out_rx) = unbounded::<Vec<u8>>();

    // Reader: inbound WS messages → `Vec<u8>` frames. Ends on close/error; dropping `in_tx` ends the
    // pump's inbound stream. `send` awaits capacity, which is where the backpressure lives.
    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if in_tx.send(b.to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Text(t)) => {
                    if in_tx.send(t.as_bytes().to_vec()).await.is_err() {
                        break;
                    }
                }
                // Control frames carry no plane data; the WS layer answers pings itself.
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Writer: `Vec<u8>` frames from the pump → one binary WS message each. Ends when the pump drops the
    // sink; a close is sent best-effort so the peer sees a clean shutdown.
    tokio::spawn(async move {
        while let Some(frame) = out_rx.next().await {
            if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    (in_rx, out_tx)
}

/// ACCEPT an HTTP→WS upgrade and hand the plane the split socket as the frame channel. The router that
/// received `upgrade` keeps ownership of the HTTP response; `on_socket` runs once the upgrade completes,
/// with the neutral `(frame-stream, frame-sink)` this transport presents — so a plane serves a live WS
/// session without ever naming the HTTP handshake, the routing, or the WS framing.
///
/// The SIZE ceiling is applied HERE, on the upgrade, before any socket exists: a message (and a single
/// frame) larger than [`max_inbound_message_bytes`] is REFUSED by the WS layer and the connection is
/// closed, rather than reassembled into memory and handed on. The upgrade is the only moment that
/// choice can be made — past it the socket is already reading — which is why the cap sits beside the
/// handshake and not in the pump.
pub fn accept<F, Fut>(upgrade: WebSocketUpgrade, on_socket: F) -> Response
where
    F: FnOnce(Receiver<Vec<u8>>, UnboundedSender<Vec<u8>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let cap = max_inbound_message_bytes();
    upgrade
        .max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| async move {
            let (stream, sink) = channel(socket);
            on_socket(stream, sink).await;
        })
}

/// BRIDGE an admitted session route's upgrade onto its [`SessionPipe`](crate::plane_routes::SessionPipe)
/// (TRANSITIONAL with the session routes: deleted when INBOUND-LISTEN's accepted::Caller serves). The
/// same size ceiling as [`accept`] applies at the handshake. Each caller message, text or binary,
/// crosses as its bytes (backpressure: the send awaits the pipe's capacity); each frame toward the
/// caller is one text message when the session said so, else one binary message. Either side ending
/// ends both: the caller's close drops the pipe's sender, and the session dropping its sender closes
/// the socket.
pub fn bridge(upgrade: WebSocketUpgrade, pipe: crate::plane_routes::SessionPipe) -> Response {
    let cap = max_inbound_message_bytes();
    upgrade
        .max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| async move {
            let crate::plane_routes::SessionPipe {
                from_caller,
                mut to_caller,
            } = pipe;
            let (mut ws_tx, mut ws_rx) = socket.split();
            let inbound = async move {
                while let Some(Ok(msg)) = ws_rx.next().await {
                    let bytes = match msg {
                        Message::Binary(b) => b.to_vec(),
                        Message::Text(t) => t.as_bytes().to_vec(),
                        Message::Close(_) => break,
                        // Control frames carry no session data; the WS layer answers pings itself.
                        _ => continue,
                    };
                    if from_caller.send(bytes).await.is_err() {
                        break;
                    }
                }
            };
            let outbound = async move {
                while let Some(out) = to_caller.recv().await {
                    let msg = if out.text {
                        match String::from_utf8(out.bytes) {
                            Ok(text) => Message::Text(text.into()),
                            Err(e) => Message::Binary(e.into_bytes().into()),
                        }
                    } else {
                        Message::Binary(out.bytes.into())
                    };
                    if ws_tx.send(msg).await.is_err() {
                        return;
                    }
                }
                let _ = ws_tx.close().await;
            };
            tokio::select! {
                () = inbound => {}
                () = outbound => {}
            }
        })
}

/// A SESSION ROUTE'S UPGRADE, either way its connection is served: the hyper loop's own upgrade
/// (the axum extractor), or a connection the data listener frames through its framer's accept side
/// ([`crate::plane_routes::FramedSession`], a request extension), where the framer that claims the
/// upgrade answers it. A framed request is taken as an upgrade when it is a `GET` naming a
/// WebSocket key at version 13 (the connection-level lines that ask for it are its framer's); any
/// other request is judged by the axum extractor, and refused as it refuses it.
pub enum SessionUpgrade {
    /// The hyper loop's upgrade.
    Ws(WebSocketUpgrade),
    /// A framed connection's slot for the admitted pipe.
    Framed(crate::plane_routes::FramedSession),
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for SessionUpgrade {
    type Rejection = axum::extract::ws::rejection::WebSocketUpgradeRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(slot) = parts
            .extensions
            .get::<crate::plane_routes::FramedSession>()
            .cloned()
        {
            let named = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .map(axum::http::HeaderValue::as_bytes)
            };
            if parts.method == axum::http::Method::GET
                && named("sec-websocket-key").is_some()
                && named("sec-websocket-version") == Some(b"13".as_slice())
            {
                return Ok(Self::Framed(slot));
            }
        }
        <WebSocketUpgrade as axum::extract::FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(Self::Ws)
    }
}

/// BRIDGE an admitted session onto its pipe, either way ([`SessionUpgrade`]): over the hyper
/// loop's upgrade ([`bridge`]); or, on a framed connection, the pipe left in its slot and the
/// answer a bare `101`, for the listener to hand the connection to the upgrade's framer.
pub fn bridge_either(upgrade: SessionUpgrade, pipe: crate::plane_routes::SessionPipe) -> Response {
    match upgrade {
        SessionUpgrade::Ws(upgrade) => bridge(upgrade, pipe),
        SessionUpgrade::Framed(slot) => {
            slot.put(pipe);
            let mut r = Response::new(axum::body::Body::empty());
            *r.status_mut() = axum::http::StatusCode::SWITCHING_PROTOCOLS;
            r
        }
    }
}
