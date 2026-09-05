// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::{Stream, StreamExt};

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::unit::Refusal;
use busbar_contract::wire::Frame;
use busbar_contract::{
    grammar::SelectorForm, ArenaBytes, Fut, Kind, Plugin, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportKeyHandle, TransportMeta,
};
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::wire::ArrivalRecord;
use busbar_contract_transport::wire::CloseReason;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::Listener;
use busbar_contract_transport::wire::TransportError;
use busbar_contract_transport::wire::Unit0Trigger;
use busbar_contract_transport::AbiVersion;
use tokio_tungstenite::tungstenite::Message;

use crate::conn::{ConnState, LowerIo, Sock, WsConnHandle};

type FrameStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// One `ws://`/`wss://` URL, hand-parsed into `(secure, host, port, path)`. Deliberately strict
/// rather than permissive: this is an operator/runtime target, not free text.
fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err(TransportError::AddressRefused);
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(TransportError::AddressRefused);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') && !p.contains(']') => {
            let port: u16 = p.parse().map_err(|_| TransportError::AddressRefused)?;
            (h.to_string(), port)
        }
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(str::to_string)
        .unwrap_or(host);
    if host.is_empty() {
        return Err(TransportError::AddressRefused);
    }
    Ok((secure, host, port, path.to_string()))
}

/// The WebSocket transport. In-tree, inside the trusted computing base — see the architecture
/// doc's transport and transports-table sections.
///
/// It opens no socket of its own. Every byte reaches it through the layer it composes over: the
/// lower transport binds, accepts and dials, and this one takes the stream that layer gives up and
/// runs the WebSocket handshake on it. That is what makes the composed chain real rather than
/// declared, and it is what puts the network guard, the transport-key unit and the frame-honesty
/// tests in ONE place for the whole stack instead of one place per transport.
pub struct WsTransport {
    next_id: AtomicU64,
    conns: SyncMutex<HashMap<u64, Arc<ConnState>>>,
    /// The layer this one composes over. `None` for an instance used only through
    /// [`WsTransport::adopt`] or the in-memory handshake seam, which are handed a stream directly.
    lower: Option<Arc<dyn Transport>>,
}

impl Default for WsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl WsTransport {
    /// A transport with no layer under it: it can adopt a stream a caller hands it, and nothing
    /// else. `listen`, `accept` and `dial` all need a lower layer, because this one owns no socket.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            lower: None,
        }
    }

    /// A transport composed over `lower` — the layer that binds, accepts and dials on its behalf.
    ///
    /// The design's own stack is `tcp → tls → http → ws`: `http` is what an inbound upgrade arrives
    /// on, and `tcp`/`tls` are what an outbound one is dialled through. Which of them a given
    /// instance stands on is the composition root's declaration, and the boot check is what holds
    /// that declaration to the transports actually registered.
    #[must_use]
    pub fn over(lower: Arc<dyn Transport>) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            lower: Some(lower),
        }
    }

    fn lower(&self) -> Result<&Arc<dyn Transport>, TransportError> {
        // A ws transport with nothing under it has no socket to reach for, and inventing one is the
        // exact thing this composition exists to stop.
        self.lower.as_ref().ok_or(TransportError::HandoffMismatch)
    }

    fn mint_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn insert(&self, id: u64, state: Arc<ConnState>) {
        self.conns.lock().unwrap().insert(id, state);
    }

    pub(crate) fn state_of(&self, id: u64) -> Option<Arc<ConnState>> {
        self.conns.lock().unwrap().get(&id).cloned()
    }

    /// Wrap an already-established, already-upgraded WS socket as a live connection. `Sock` is
    /// generic over the boxed duplex, so the battery drives this over an in-memory pair through
    /// the identical path a real TCP/TLS accept uses.
    fn hold(&self, sock: crate::conn::Sock, peer: &str, chain: Vec<&'static str>) -> Conn {
        let id = self.mint_id();
        self.insert(id, ConnState::new(sock, chain));
        Conn::new(Arc::new(WsConnHandle {
            id,
            peer: peer.to_string(),
        }))
    }

    /// Run the WebSocket handshake, in the given role, over a stream some layer already
    /// established, and hold what comes out.
    ///
    /// This is the whole of what this transport does with a socket: it never opens one. An embedder
    /// that already owns a duplex pair drives the identical path a composed accept or dial does.
    pub async fn handshake_over<S>(
        &self,
        stream: S,
        is_server: bool,
        peer: &str,
    ) -> Result<Conn, TransportError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        self.handshake(
            Box::new(stream),
            is_server,
            "ws://localhost/",
            peer,
            vec!["ws"],
        )
        .await
    }

    /// The one place a WebSocket connection is made, whichever direction it came from.
    async fn handshake(
        &self,
        stream: Box<dyn LowerIo>,
        is_server: bool,
        url: &str,
        peer: &str,
        chain: Vec<&'static str>,
    ) -> Result<Conn, TransportError> {
        let sock: Sock = if is_server {
            tokio_tungstenite::accept_async(stream)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?
        } else {
            let (sock, _resp) = tokio_tungstenite::client_async(url, stream)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            sock
        };
        Ok(self.hold(sock, peer, chain))
    }
}

impl Plugin for WsTransport {
    fn key(&self) -> &'static str {
        <Self as TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract_transport::registry::TRANSPORT_ABI
    }
}

impl TransportMeta for WsTransport {
    const KEY: &'static str = "ws";
    // ws IS the top transport of its stack (composed over `http`), and the architecture states the
    // TOP transport owns claims — including the ones that, before the upgrade, are read off the
    // HTTP request carrying it. So this declares the request-shaped forms rather than none; a
    // genuine open question (flagged in the crate's report) is whether that reading is what the
    // design intends, since `http`'s own row would otherwise carry the identical set unused.
    const SELECTOR_FORMS: &'static [SelectorForm] = &[
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::PathPattern,
        SelectorForm::PathSuffix,
        SelectorForm::PathContains,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::Sni,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[];
    // The layers this one is actually built over, and the Cargo edges say the same: an inbound
    // upgrade arrives on `http`, an outbound one is dialled through `tcp`. `tls` sits under those
    // two rather than under this one, which is why it is not named here.
    const COMPOSES_OVER: &'static [&'static str] = &["http", "tcp"];
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::Upgrade);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::PATH, tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    // "frames after the upgrade carry no status leg" — the transports table's own words for this
    // row.
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> = None;
}

impl Transport for WsTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            // The chain the layer below reported, plus this one. An adopted connection knows
            // what it was handed; one this transport opened itself knows what it opened.
            transport_chain: self
                .state_of(conn.id())
                .map_or_else(|| vec!["ws"], |s| s.chain.clone()),
        }
    }

    /// The listener is the layer below's. This transport binds nothing.
    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move { self.lower()?.listen(cfg, keys).await })
    }

    /// Take the next connection off the layer below, then upgrade it — which is
    /// `Unit0Trigger::Upgrade`: the session opens at the handshake, and the handshake runs on the
    /// stream that layer gives up.
    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let lower = self.lower()?;
            let conn = lower.accept(l).await?;
            self.adopt(lower.as_ref(), conn, &NO_KEYS).await
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let DestinationFacts::Upstream { address, .. } = dest.facts() else {
                return Err(TransportError::AddressRefused);
            };
            let url = address.authority().ok_or(TransportError::AddressRefused)?;
            let (secure, host_name, port, path) = split_ws_url(url)?;
            let authority: &'static str = Box::leak(format!("{host_name}:{port}").into_boxed_str());

            // The socket is the layer below's, dialled against the address this destination already
            // carries — no name is resolved here, which is what puts the network guard in front of
            // the dial instead of inside it. Re-addressing narrows the sealed destination to what
            // that layer reads; it does not re-seal it, and it cannot widen where the unit may go.
            let lower = self.lower()?;
            let beneath = dest
                .beneath(
                    lower.key(),
                    busbar_contract_transport::dest::UpstreamAddress::Socket {
                        authority,
                        sni: address.sni().or(if secure {
                            Some(Box::leak(host_name.clone().into_boxed_str()) as &'static str)
                        } else {
                            None
                        }),
                    },
                )
                .ok_or(TransportError::AddressRefused)?;
            let conn = lower.dial(&beneath, keys).await?;
            let mut chain = lower.arrival(&conn).transport_chain;
            let raw = lower.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(<Self as TransportMeta>::KEY);

            let request_url = format!(
                "{}://{host_name}:{port}{path}",
                if secure { "wss" } else { "ws" }
            );
            let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(raw.into_io());
            self.handshake(Box::new(stream), false, &request_url, authority, chain)
                .await
        })
    }

    fn frames(&self, conn: Conn) -> FrameStream {
        let id = conn.id();
        let Some(state) = self.state_of(id) else {
            return Box::pin(futures::stream::once(async {
                Err::<(StreamId, Frame), TransportError>(TransportError::Closed)
            }));
        };
        Box::pin(futures::stream::unfold(
            (state, false),
            move |(state, done)| async move {
                if done || state.is_poisoned() {
                    return None;
                }
                let mut guard = state.reader.lock().await;
                let mut reader = guard.take()?;
                drop(guard);
                let item = loop {
                    match reader.next().await {
                        None => break None, // the peer closed the socket
                        Some(Ok(Message::Binary(b))) => {
                            let bytes = SlabBytes::new(Arc::<[u8]>::from(b.to_vec()));
                            let meta = FrameMeta {
                                bytes: bytes.len() as u64,
                                transport_units: None,
                                status: None,
                            };
                            break Some(Ok((
                                StreamId(0),
                                Frame {
                                    direction: Direction::Inbound,
                                    stream: StreamId(0),
                                    bytes,
                                    meta,
                                },
                            )));
                        }
                        Some(Ok(Message::Text(t))) => {
                            let raw = t.as_bytes().to_vec();
                            let bytes = SlabBytes::new(Arc::<[u8]>::from(raw));
                            let meta = FrameMeta {
                                bytes: bytes.len() as u64,
                                transport_units: None,
                                status: None,
                            };
                            break Some(Ok((
                                StreamId(0),
                                Frame {
                                    direction: Direction::Inbound,
                                    stream: StreamId(0),
                                    bytes,
                                    meta,
                                },
                            )));
                        }
                        Some(Ok(Message::Close(_))) => break None,
                        // Ping/Pong carry no plane data; tungstenite does not auto-answer a Ping
                        // on a raw split stream, so this transport answers it itself and keeps
                        // reading — a protocol-blind, byte-level obligation, not plane meaning.
                        Some(Ok(Message::Ping(payload))) => {
                            let mut w = state.writer.lock().await;
                            let _ = futures::SinkExt::send(&mut *w, Message::Pong(payload)).await;
                            continue;
                        }
                        Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => continue,
                        Some(Err(_)) => break Some(Err(TransportError::Reset)),
                    }
                };
                *state.reader.lock().await = Some(reader);
                match item {
                    None => None,
                    Some(result) => {
                        let done_next = result.is_err();
                        Some((result, (state, done_next)))
                    }
                }
            },
        ))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        let id = conn.id();
        Box::pin(async move {
            let Some(state) = self.state_of(id) else {
                return Err(TransportError::Closed);
            };
            if state.is_poisoned() {
                return Err(TransportError::Framing);
            }
            let payload = bytes.as_slice().to_vec();
            let n = payload.len();
            let mut guard = PoisonGuard {
                state: &state,
                armed: true,
            };
            let mut w = state.writer.lock().await;
            futures::SinkExt::send(&mut *w, Message::Binary(payload.into()))
                .await
                .map_err(|_| TransportError::Reset)?;
            drop(w);
            guard.armed = false;
            Ok(n)
        })
    }

    /// A WebSocket message is its payload. The envelope's fields belonged to the HTTP request that
    /// carried the upgrade, and that request is long over by the time a message is written.
    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::Arena,
    ) -> Result<ArenaBytes<'a>, busbar_contract_transport::wire::Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| busbar_contract_transport::wire::Encode::ArenaExhausted)
    }

    /// The `http` → `ws` upgrade, from the side that owns what comes out.
    ///
    /// `http` gives up the accepted socket without having read the upgrade request, because the
    /// layer that speaks the upgrade is the one that answers it: this transport runs the handshake
    /// itself and the 101 goes back over the same stream. The composed chain travels with the
    /// handoff, so the connection reports `tcp → http → ws` rather than naming only itself.
    fn adopt<'a>(
        &'a self,
        from: &'a dyn Transport,
        conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            if !<Self as TransportMeta>::COMPOSES_OVER.contains(&from.key()) {
                return Err(TransportError::HandoffMismatch);
            }
            let mut chain = from.arrival(&conn).transport_chain;
            let raw = from.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(<Self as TransportMeta>::KEY);
            let peer = raw.peer().to_string();
            let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(raw.into_io());
            self.handshake(Box::new(stream), true, "", &peer, chain)
                .await
        })
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract_transport::wire::RawStream> {
        // Nothing upgrades in-band over `ws` (`UPGRADES_TO` is empty), so there is no raw stream
        // this layer ever hands up.
        let _ = conn;
        None
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.lower.as_ref().map(|l| l.key())
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        let id = conn.id();
        if let Some(state) = self.conns.lock().unwrap().remove(&id) {
            tokio::spawn(async move {
                let mut w = state.writer.lock().await;
                let _ = futures::SinkExt::send(&mut *w, Message::Close(None)).await;
            });
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        // A WebSocket connection carries one message stream; refusing it refuses all of it.
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let id = conn.id();
            if let Some(state) = self.state_of(id) {
                if !state.is_poisoned() {
                    let payload = bytes.as_slice().to_vec();
                    let mut w = state.writer.lock().await;
                    let _ = futures::SinkExt::send(&mut *w, Message::Binary(payload.into())).await;
                }
            }
            self.close(conn, CloseReason::Normal);
            Ok(())
        })
    }
}

/// See `busbar-transport-stdio`'s identical guard: a write that does not reach a clean completion
/// — an error, or this future being dropped mid-send — fences the connection rather than risk a
/// half-written WS frame being resumed later.
struct PoisonGuard<'a> {
    state: &'a ConnState,
    armed: bool,
}

impl Drop for PoisonGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.poisoned.store(true, Ordering::Release);
        }
    }
}

/// The keys an accept-side upgrade is adopted under.
///
/// The WebSocket handshake needs no key material of its own: whatever secured the bytes was
/// resolved by the layer underneath, at its own `listen`, through the transport-key unit. A handle
/// naming no slot is the honest way to say that rather than passing one this layer never reads.
static NO_KEYS: std::sync::LazyLock<TransportKeyHandle> = std::sync::LazyLock::new(|| {
    struct NoKeySeal;
    impl busbar_contract::KernelSeal for NoKeySeal {
        fn seal_origin(&self) -> &'static str {
            "busbar-transport-ws: an upgrade reads no key of its own"
        }
    }
    TransportKeyHandle::issue(&NoKeySeal, 0, "none")
});
