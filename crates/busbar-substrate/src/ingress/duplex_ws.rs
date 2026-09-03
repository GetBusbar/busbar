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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE INBOUND WS-ACCEPT ARRIVAL SEAM — the neutral, substrate-owned vocabulary a plane DECLARES an
// inbound gauntlet-gated WS-accept route through, and the process registry the composition root
// installs those declarations into for the core router to drain. The plane names only this neutral
// seam; the CORE-side `mount_ws_arrivals` (behind `duplex-ws`) mounts a real WS-accept route per
// spec and hands the plane's accept fn a [`WsArrival`] by value. NONE of this is a `PlaneReqCtx` /
// `PlaneRouteSpec` field, so the always-compiled request path names no WS type (money-path byte-
// identity), and the upgrade is a substrate-owned newtype carried BY VALUE (never `Box<dyn Any>`), so
// there is no dual-compile `TypeId` trap.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// THE SUBSTRATE-OWNED NEWTYPE the WS upgrade rides on across the accept boundary — NEVER
/// `Box<dyn Any>`. Single-compiled in substrate, so its type identity is the same in both dual-
/// compiled core instances (no downcast, no `TypeId` to diverge). Carries the upgrade BY VALUE plus
/// the verbatim per-request facts the plane's accept fn needs to build its `GauntletRequest` and open
/// its session — sourced from the SAME extractors the non-WS adapter reads, but assembled by the WS-
/// aware core mount. The only type-erased field is `slot`, the already-proven-safe plane-slot crossing
/// the non-WS `PlaneReqCtx::slot` already uses.
pub struct WsArrival {
    /// The axum WS-upgrade extractor the route received. The ONLY way to consume it into a live socket
    /// is [`serve_gauntlet`] / [`accept_gauntlet`]; a plane's accept fn never calls a bare `on_upgrade`.
    pub upgrade: WebSocketUpgrade,
    /// The middleware-resolved governance request context (`None` on a `RouteAuth::None` route).
    pub gov: Option<busbar_api::PlaneRequestCtx>,
    /// The middleware-resolved auth principal (`None` on a `RouteAuth::None` route).
    pub principal: Option<busbar_api::AuthPrincipal>,
    /// The resolved caller principal id, lifted from `gov` — the identity a plane binds session state to.
    pub caller_principal: Option<String>,
    /// The request path this route was matched at.
    pub path: String,
    /// The full request URI (path + query).
    pub uri: axum::http::Uri,
    /// The request headers.
    pub headers: axum::http::HeaderMap,
    /// Any path-template captures (`{name}` → value), in match order.
    pub path_params: Vec<(String, String)>,
    /// The neutral engine host, minted core-side over the request's live engine snapshot.
    pub host: Arc<dyn crate::plane_host::EngineHost>,
    /// The plane's own per-generation runtime slot (the same `Arc<dyn Any>` the plane's `build` produced),
    /// captured by the core mount from the router's `plane_slots` and cloned into every arrival.
    pub slot: Arc<dyn std::any::Any + Send + Sync>,
}

/// ONE PLANE'S WS-ACCEPT HANDLER: a neutral fn that receives a [`WsArrival`] BY VALUE and returns a
/// finished axum [`Response`]. It MUST reach [`serve_gauntlet`] / [`accept_gauntlet`] internally (the
/// only path that consumes the upgrade into a live socket); it never sees a bare `on_upgrade`. `Arc`
/// so the core mount clones it into the per-request axum closure it wires.
pub type WsAcceptFn = Arc<dyn Fn(WsArrival) -> Response + Send + Sync>;

/// ONE WS-ACCEPT ARRIVAL a plane DECLARES: the exact path, the admission bar recorded VERBATIM in the
/// `CoreRouteTable` (identical shape to `PlaneRouteSpec::auth`, so the auth middleware enforces it
/// BEFORE the accept fn), the neutral accept fn, and the plane's registry `slot_key` so the core mount
/// resolves the live per-generation slot to carry on each [`WsArrival`] (exactly as the non-WS adapter
/// resolves it from `plane_slots`). Names only `axum`, `busbar_api`, `busbar_plugin` and this crate —
/// no plane token, so adding a duplex plane is a new-crate-only diff.
#[derive(Clone)]
pub struct WsArrivalSpec {
    /// The exact axum path pattern this WS-accept route is mounted at.
    pub path: String,
    /// The admission bar the core auth middleware enforces BEFORE the accept fn runs.
    pub auth: busbar_plugin::cold::http_endpoint::RouteAuth,
    /// The plane's registry decl key — the core mount looks the live runtime slot up under it and,
    /// when absent (the plane is unconfigured this generation), mounts nothing, exactly as the non-WS
    /// route loop skips a plane with no slot.
    pub slot_key: &'static str,
    /// The neutral accept fn the core mount hands a [`WsArrival`], returning the finished response.
    pub accept: WsAcceptFn,
}

/// THE PROCESS-WIDE INSTALLED WS ARRIVALS — set once by the composition root
/// ([`install_ws_arrivals`]), read (cloned) by the core router at build ([`take_ws_arrivals`]). A
/// `OnceLock<Vec<_>>`, mirroring `ingress::arrival::install_path_ingress`: the composition root
/// ASSEMBLES it from whichever duplex-plane crates are linked, install-once + read-many so a test that
/// builds several routers each mounts the same arrivals.
static INSTALLED_WS_ARRIVALS: std::sync::OnceLock<Vec<WsArrivalSpec>> = std::sync::OnceLock::new();

/// INSTALL THE INBOUND WS-ACCEPT ARRIVALS — the composition root's one write, mirroring
/// [`crate::ingress::arrival::install_path_ingress`]. First-writer-wins (idempotent): a second call is
/// ignored rather than panicking, so a test harness that composes twice does not abort. Only the
/// composition root (or a test) calls this; a build with no duplex plane never does, and
/// [`take_ws_arrivals`] then yields nothing.
pub fn install_ws_arrivals(arrivals: Vec<WsArrivalSpec>) {
    let _ = INSTALLED_WS_ARRIVALS.set(arrivals);
}

/// DRAIN (by clone) THE INSTALLED WS-ACCEPT ARRIVALS — the core router's one read at build. Returns an
/// empty vec when no duplex plane installed any, so the router mounts no WS-accept route (byte-
/// identical assembly). Cloning (not taking) keeps it read-many so repeated router builds are stable.
#[must_use]
pub fn take_ws_arrivals() -> Vec<WsArrivalSpec> {
    INSTALLED_WS_ARRIVALS.get().cloned().unwrap_or_default()
}
