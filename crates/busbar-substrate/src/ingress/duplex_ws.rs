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
//! the plane the split socket as the frame channel; [`serve`] wires that straight into the pump for a
//! plane that supplies a [`DuplexPlane`]. A caller that wants the raw channel (to funnel one socket's
//! write side elsewhere, as a proxy topology does) uses [`channel`] on the already-upgraded socket.
//!
//! Text and binary WS messages both arrive as `Vec<u8>` frames; control frames (ping/pong/close) are
//! answered by the WS layer and never surface as frames. A frame written back is sent as ONE binary WS
//! message — the plane maps its own wire (text or binary) to bytes at this boundary and the pump stays
//! framing-agnostic, exactly as its `serve_messages` header describes.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{SinkExt, StreamExt};

use crate::ingress::byte_duplex::{serve_messages, DuplexPlane};
use crate::plane_host::{run_gauntlet_session, GauntletPlane, GauntletRequest};

/// Bridge an already-upgraded [`WebSocket`] into the neutral `(frame-stream, frame-sink)` the pump
/// speaks, over two mpsc channels (both `Unpin + Send`, the shape `serve_messages` requires): inbound
/// text/binary → one `Vec<u8>` frame; an outbound frame → one binary WS message. Control frames and
/// receive errors are dropped so only data payloads cross; the peer's close ends the inbound stream —
/// the message-duplex analogue of EOF — and dropping the outbound sink closes the socket.
pub fn channel(socket: WebSocket) -> (UnboundedReceiver<Vec<u8>>, UnboundedSender<Vec<u8>>) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (in_tx, in_rx) = unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = unbounded::<Vec<u8>>();

    // Reader: inbound WS messages → `Vec<u8>` frames. Ends on close/error; dropping `in_tx` ends the
    // pump's inbound stream.
    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if in_tx.unbounded_send(b.to_vec()).is_err() {
                        break;
                    }
                }
                Ok(Message::Text(t)) => {
                    if in_tx.unbounded_send(t.as_bytes().to_vec()).is_err() {
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
pub fn accept<F, Fut>(upgrade: WebSocketUpgrade, on_socket: F) -> Response
where
    F: FnOnce(UnboundedReceiver<Vec<u8>>, UnboundedSender<Vec<u8>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    upgrade.on_upgrade(move |socket| async move {
        let (stream, sink) = channel(socket);
        on_socket(stream, sink).await;
    })
}

/// SERVE one inbound WS session on the neutral pump: accept the upgrade, then drive `plane`'s two
/// callbacks (`classify` + `handle`) over the upgraded socket through
/// [`serve_messages`](crate::ingress::byte_duplex::serve_messages) until the peer closes. The one-call
/// path a plane whose whole socket IS its session uses; the HTTP-upgrade boundary and the pump are wired
/// once, here, so the plane supplies only session logic.
pub fn serve<P>(upgrade: WebSocketUpgrade, plane: Arc<P>) -> Response
where
    P: DuplexPlane,
{
    accept(upgrade, move |stream, sink| async move {
        serve_messages(stream, sink, plane).await;
    })
}

/// ACCEPT a WS-upgrade only AFTER the open-pass gauntlet admits it — the governed sibling of [`accept`].
///
/// A live session must be admitted by [`run_gauntlet_session`] (verify STRICTLY before any charge)
/// BEFORE the socket is bound to anything: the HTTP→WS handshake is the point of no return, so running
/// the destination verify first is what keeps a refused session from ever reaching the pump. This runs
/// the gauntlet SYNCHRONOUSLY (its `verify_destination` is sync) and, on `Refuse`, returns the plane's
/// OWN finished refusal `Response` WITHOUT calling `on_upgrade` — so a refused session upgrades no
/// socket, spawns no task and charges nothing. Only on `Proceed` is the upgrade accepted and the split
/// socket handed to `on_socket`. This is the seam a plane's WS-accept arrival uses instead of a bare
/// `on_upgrade`, which would bind the socket before the gauntlet could reject it.
///
/// (`result_large_err` on the inner gate: the refusal is the plane's own by-value `Response`, carried
/// verbatim so its shaping matches [`run_gauntlet_session`]'s.)
#[allow(clippy::result_large_err)]
pub fn accept_gauntlet<F, Fut>(
    upgrade: WebSocketUpgrade,
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
    on_socket: F,
) -> Response
where
    F: FnOnce(UnboundedReceiver<Vec<u8>>, UnboundedSender<Vec<u8>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    match run_gauntlet_session(req, plane) {
        // The gauntlet refused the destination: return its finished refusal, bind no socket.
        Err(refusal) => refusal,
        // Admitted: only now accept the upgrade and hand the split socket to the plane.
        Ok(_admitted) => accept(upgrade, on_socket),
    }
}

/// SERVE one inbound WS session on the neutral pump, gated by the open-pass gauntlet — the governed
/// sibling of [`serve`]. Runs [`run_gauntlet_session`] (verify STRICTLY before any charge) and, only on
/// `Proceed`, accepts the upgrade and drives `plane` over the socket through
/// [`serve_messages`](crate::ingress::byte_duplex::serve_messages); on `Refuse` it returns the gauntlet
/// plane's finished refusal and never binds the socket. The one-call path a plane whose whole socket IS
/// its session uses when that session must be admitted before it is served.
#[allow(clippy::result_large_err)]
pub fn serve_gauntlet<P>(
    upgrade: WebSocketUpgrade,
    req: GauntletRequest<'_>,
    gate: Box<dyn GauntletPlane + '_>,
    plane: Arc<P>,
) -> Response
where
    P: DuplexPlane,
{
    accept_gauntlet(upgrade, req, gate, move |stream, sink| async move {
        serve_messages(stream, sink, plane).await;
    })
}
