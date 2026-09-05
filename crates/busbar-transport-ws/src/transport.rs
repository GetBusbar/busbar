// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::{Stream, StreamExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::unit::Refusal;
use busbar_contract::wire::{
    ArrivalRecord, CloseReason, Conn, Direction, Frame, FrameMeta, Listener, ListenerHandle,
    TransportError, Unit0Trigger,
};
use busbar_contract::{
    grammar::SelectorForm, AbiVersion, ArenaBytes, Fut, Kind, Plugin, SlabBytes, StreamId,
    Transport, TransportConfigView, TransportKeyHandle, TransportMeta,
};
use tokio_tungstenite::tungstenite::Message;

use crate::conn::{ConnState, WsConnHandle};
use crate::rw::BoxedRw;

type FrameStream = std::pin::Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

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

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// The WebSocket transport. In-tree, inside the trusted computing base — see the architecture
/// doc's transport and transports-table sections.
pub struct WsTransport {
    next_id: AtomicU64,
    conns: SyncMutex<HashMap<u64, Arc<ConnState>>>,
    /// Keyed by the listener's rendered `local_addr()` — see the module's own report note: a real
    /// [`busbar_contract::wire::Listener`] carries no id of its own, only an address string, so
    /// this is the best key available on the opaque handle without widening the contract.
    listeners: SyncMutex<HashMap<String, Arc<TokioTcpListener>>>,
}

impl Default for WsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl WsTransport {
    /// A fresh transport instance with no live connections.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            listeners: SyncMutex::new(HashMap::new()),
        }
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

    /// TEST-ONLY (also usable by an embedder that already owns a socket pair): perform a WS
    /// handshake in the given role over an arbitrary duplex stream and adopt the result.
    pub async fn handshake_over<S>(&self, stream: S, is_server: bool, peer: &str) -> Result<Conn, TransportError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let boxed = BoxedRw(Box::new(stream));
        let sock = if is_server {
            tokio_tungstenite::accept_async(boxed)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?
        } else {
            let (sock, _resp) = tokio_tungstenite::client_async("ws://localhost/", boxed)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            sock
        };
        Ok(self.hold(sock, peer, vec!["tcp", "http", "ws"]))
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
        // See `busbar-transport-stdio`'s identical note: no transport-kind ABI constant is
        // declared in `busbar-contract` today.
        AbiVersion(1)
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
    const COMPOSES_OVER: &'static [&'static str] = &["http"];
    const HANDOFF: Option<busbar_contract::wire::Handoff> = None;
    const FRAMING: busbar_contract::Framing = busbar_contract::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::Upgrade);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    // "frames after the upgrade carry no status leg" — the transports table's own words for this
    // row.
    const STATUS_CLASS: Option<busbar_contract::wire::StatusAt> = None;
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

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
            let addr = cfg.bind().ok_or(TransportError::AddressRefused)?;
            let listener = TokioTcpListener::bind(addr)
                .await
                .map_err(|_| TransportError::AddressRefused)?;
            let local = listener
                .local_addr()
                .map_err(|_| TransportError::AddressRefused)?
                .to_string();
            self.listeners
                .lock()
                .unwrap()
                .insert(local.clone(), Arc::new(listener));
            Ok(Listener::new(Arc::new(WsListenerHandle { addr: local })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let listener = self
                .listeners
                .lock()
                .unwrap()
                .get(&l.local_addr())
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (tcp, peer) = listener.accept().await.map_err(|_| TransportError::Closed)?;
            // THE UPGRADE ITSELF — `Unit0Trigger::Upgrade`. `accept_async` parses the HTTP upgrade
            // request and answers the 101 over the raw stream; no separate `http` transport is
            // consulted (see the lower-layer boundary note in the module header).
            let sock = tokio_tungstenite::accept_async(BoxedRw(Box::new(tcp)))
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.hold(sock, &peer.to_string(), vec!["tcp", "http", "ws"]))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let DestinationFacts::Upstream { address, .. } = dest.facts() else {
                return Err(TransportError::AddressRefused);
            };
            let url = address
                .authority()
                .ok_or(TransportError::AddressRefused)?;
            let (secure, host_name, port, path) = split_ws_url(url)?;
            // NOT resolve-then-pin: see the module header. A real deployment dials through the
            // tcp/tls transport crates once they exist; this crate resolves the name directly,
            // which is the placeholder this report flags rather than silently narrows.
            let tcp = TcpStream::connect((host_name.as_str(), port))
                .await
                .map_err(|_| TransportError::Refused)?;
            let request_url = format!(
                "{}://{host_name}:{port}{path}",
                if secure { "wss" } else { "ws" }
            );
            let sock = if secure {
                let server_name = rustls::pki_types::ServerName::try_from(host_name.clone())
                    .map_err(|_| TransportError::HandshakeFailed)?;
                let tls = tokio_rustls::TlsConnector::from(tls_config())
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| TransportError::HandshakeFailed)?;
                let (sock, _resp) =
                    tokio_tungstenite::client_async(&request_url, BoxedRw(Box::new(tls)))
                        .await
                        .map_err(|_| TransportError::HandshakeFailed)?;
                sock
            } else {
                let (sock, _resp) =
                    tokio_tungstenite::client_async(&request_url, BoxedRw(Box::new(tcp)))
                        .await
                        .map_err(|_| TransportError::HandshakeFailed)?;
                sock
            };
            Ok(self.hold(sock, &format!("{host_name}:{port}"), vec!["tcp", "http", "ws"]))
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
            let sock = tokio_tungstenite::accept_async(BoxedRw(Box::new(stream)))
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.hold(sock, &peer, chain))
        })
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

struct WsListenerHandle {
    addr: String,
}

impl ListenerHandle for WsListenerHandle {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}
