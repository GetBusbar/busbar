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

use crate::conn::{ConnState, LowerFacts, LowerIo, Sock, WsConnHandle};

/// How long a courtesy Close frame may take to reach the peer before this transport gives up on
/// it. A peer whose receive window is full can never accept one, and a send with no bound would
/// hold the writer lock — and the socket — for the process's lifetime, because `close` has already
/// dropped the only handle that could cancel it.
pub(crate) const CLOSE_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// How long the WebSocket opening handshake may take before this transport gives the socket up.
///
/// The handshake IS this connection's Unit 0 (`Unit0Trigger::Upgrade`), and until it completes the
/// socket answers to nobody: no unit owns it, no admission decision has been made about it, and
/// nothing else in the stack is watching it. An unbounded handshake therefore lets a peer that
/// connects and then says nothing hold a slot — and the task upgrading it — for the lifetime of the
/// process, which is the cheapest exhaustion there is. One round trip over a stream the layer below
/// has already established is the whole of the work, so the budget is generous rather than tight
/// and still bounds it.
pub(crate) const HANDSHAKE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// The configuration key naming the largest message this transport will accept.
///
/// It is the deployment's request-body cap, read through the same name the rest of the stack knows
/// it by: a WebSocket message and an HTTP body are the same thing to an operator sizing a limit,
/// and a `ws` listener that buffered more than the `http` one beside it would be a hole nobody
/// declared. Absent, the library's own default stands.
///
/// Public because two sides read it and a literal spelled twice is a seam that drifts: this crate
/// asks for it at `listen`, and the composition root answers it from the listener view it builds.
pub const MESSAGE_MAX_BYTES_KEY: &str = "limits.request_body_max_bytes";

/// The `'static` view of a dial address, allocated at most once per distinct string.
///
/// The sealed destination's address shape is already `'static`, but a `ws://` dial target is a URL:
/// the `host:port` this transport hands the layer below, and the certificate name it offers, are
/// derived from it and may name a port the URL never spelled, so neither is a slice of anything
/// that already lives forever. Allocating one per dial would grow the process without bound against
/// a flapping upstream; interning makes it leak-once, the same posture the boot-time lane names
/// take, so a redial reuses what the first dial allocated.
pub(crate) fn intern(s: &str) -> &'static str {
    static INTERNED: std::sync::LazyLock<SyncMutex<std::collections::HashSet<&'static str>>> =
        std::sync::LazyLock::new(|| SyncMutex::new(std::collections::HashSet::new()));
    let mut table = INTERNED.lock().expect("ws address intern table poisoned");
    if let Some(already) = table.get(s) {
        return already;
    }
    let once: &'static str = Box::leak(s.to_string().into_boxed_str());
    table.insert(once);
    once
}

type FrameStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// One `ws://`/`wss://` URL, hand-parsed into `(secure, host, port, path)`. Deliberately strict
/// rather than permissive: this is an operator/runtime target, not free text.
pub(crate) fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
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
        // The last colon separates a port only when nothing after it is inside the brackets: that
        // one condition tells `[::1]:8080` (a port) from `[::1]` (an address whose own colons the
        // brackets are there to hide). A rule that also demanded the host not end in `]` rejected
        // exactly the bracketed-with-a-port case the brackets exist for.
        Some((h, p)) if !p.contains(']') => {
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
    /// The largest message this transport will read. Zero means nothing was declared and the
    /// library's default stands.
    ///
    /// One field, two routes in, because there are two lifecycles and each reaches only one of
    /// them. A served instance learns the number at `listen`, from the configuration view it is
    /// handed there — the seam a deployment's limits actually arrive through. A dial-only instance
    /// is never bound and so never sees that view, and its composition root names the number at
    /// construction instead. A `listen` on an instance that was constructed with one overrides it,
    /// which is the right precedence: the view is the deployment speaking later and more locally.
    max_message_bytes: std::sync::atomic::AtomicUsize,
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
            max_message_bytes: std::sync::atomic::AtomicUsize::new(0),
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
            max_message_bytes: std::sync::atomic::AtomicUsize::new(0),
            lower: Some(lower),
        }
    }

    /// The same composition, with the message ceiling named at construction.
    ///
    /// [`Transport::listen`] is the seam a served instance learns the ceiling through, and it is
    /// the right one: a listener is handed the deployment's configuration and reads it there. A
    /// DIAL-ONLY instance never reaches that seam — nothing binds it, so nothing hands it a view —
    /// and the composition root that built it is the only thing that holds the number. So the cap
    /// arrives twice by two different routes for two different lifecycles, and both end at the same
    /// field: this constructor seeds it, and a later `listen` on the same instance overrides it.
    #[must_use]
    pub fn over_with_max_message_bytes(lower: Arc<dyn Transport>, max: usize) -> Self {
        let t = Self::over(lower);
        t.max_message_bytes.store(max, Ordering::Relaxed);
        t
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
    fn hold(
        &self,
        sock: crate::conn::Sock,
        peer: &str,
        chain: Vec<&'static str>,
        lower: LowerFacts,
    ) -> Conn {
        let id = self.mint_id();
        self.insert(id, ConnState::new(sock, chain, lower));
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
    ///
    /// `url` is the target the client role names in its upgrade request; the server role ignores
    /// it. It is the caller's, not a `ws://localhost/` this seam invents — an embedder driving a
    /// real upstream would otherwise have had its request line rewritten to name a host it was
    /// never talking to.
    pub async fn handshake_over<S>(
        &self,
        stream: S,
        is_server: bool,
        url: &str,
        peer: &str,
    ) -> Result<Conn, TransportError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        self.handshake(
            Box::new(stream),
            is_server,
            url,
            peer,
            vec!["ws"],
            LowerFacts::default(),
        )
        .await
    }

    /// The WebSocket settings every connection this transport makes is built with.
    ///
    /// The only one it sets is the message ceiling, and it sets it only when the deployment named
    /// one: the alternative was tungstenite's 64 MiB default, which is a number this project never
    /// chose and four orders of magnitude above a typical body cap. Both the message and the frame
    /// ceiling are set, because a message ceiling alone still lets a single oversized frame be
    /// buffered before the message is refused.
    fn ws_config(&self) -> Option<tokio_tungstenite::tungstenite::protocol::WebSocketConfig> {
        let cap = self.max_message_bytes.load(Ordering::Relaxed);
        (cap > 0).then(|| {
            tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(cap))
                .max_frame_size(Some(cap))
        })
    }

    /// The one place a WebSocket connection is made, whichever direction it came from.
    async fn handshake(
        &self,
        stream: Box<dyn LowerIo>,
        is_server: bool,
        url: &str,
        peer: &str,
        chain: Vec<&'static str>,
        lower: LowerFacts,
    ) -> Result<Conn, TransportError> {
        // Both roles are bounded by the same budget: a peer that never answers is the same
        // unbounded wait whichever side opened the stream.
        let ws_cfg = self.ws_config();
        let upgraded = tokio::time::timeout(HANDSHAKE_BUDGET, async {
            let sock: Sock = if is_server {
                tokio_tungstenite::accept_async_with_config(stream, ws_cfg)
                    .await
                    .map_err(|_| TransportError::HandshakeFailed)?
            } else {
                let (sock, _resp) =
                    tokio_tungstenite::client_async_with_config(url, stream, ws_cfg)
                        .await
                        .map_err(|_| TransportError::HandshakeFailed)?;
                sock
            };
            Ok::<Sock, TransportError>(sock)
        })
        .await;
        let sock = match upgraded {
            Ok(result) => result?,
            Err(_) => return Err(TransportError::Timeout),
        };
        Ok(self.hold(sock, peer, chain, lower))
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
    // The layers this one is actually built over: an inbound upgrade arrives on `http`, an
    // outbound one is dialled through `tcp` for a `ws://` target and through `tls` for a `wss://`
    // one. `tls` is named because a secure target is dialled ON it directly — this transport adds
    // no encryption of its own, so that is the only composition under which `wss` is honest, and
    // `dial` refuses a secure target over any other lower layer.
    const COMPOSES_OVER: &'static [&'static str] = &["http", "tcp", "tls"];
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
    /// What this connection arrived on, which is what the layers below it established plus the
    /// upgrade this one ran.
    ///
    /// The upgrade replaces the layer the record describes; it does not undo the handshake beneath
    /// it. This transport declares Sni, Alpn and Port among its selector forms, and the only place
    /// those facts ever existed is the record the lower layer reported before it gave the stream
    /// up — answering zero and `None` made every location resolving on them unresolvable against a
    /// connection that really did have a port, a name and a negotiated protocol.
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let state = self.state_of(conn.id());
        let lower = state.as_ref().map(|s| &s.lower);
        ArrivalRecord {
            source: conn.peer(),
            port: lower.map_or(0, |l| l.port),
            alpn: lower.and_then(|l| l.alpn.clone()),
            sni: lower.and_then(|l| l.sni.clone()),
            peer_cert: lower.and_then(|l| l.peer_cert.clone()),
            // The chain the layer below reported, plus this one. An adopted connection knows
            // what it was handed; one this transport opened itself knows what it opened.
            transport_chain: state.map_or_else(|| vec!["ws"], |s| s.chain.clone()),
        }
    }

    /// The listener is the layer below's. This transport binds nothing.
    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
            // `listen` is the one call that carries the deployment's configuration into this
            // transport, so it is where the message cap is read. A dial made from the same instance
            // reads the same number, which is the intent: the cap is the node's, not the listener's.
            if let Some(cap) = cfg.get_int(MESSAGE_MAX_BYTES_KEY) {
                if let Ok(cap) = usize::try_from(cap) {
                    self.max_message_bytes.store(cap, Ordering::Relaxed);
                }
            }
            self.lower()?.listen(cfg, keys).await
        })
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
            let authority: &'static str = intern(&format!("{host_name}:{port}"));

            // The socket is the layer below's, dialled against the address this destination already
            // carries — no name is resolved here, which is what puts the network guard in front of
            // the dial instead of inside it. Re-addressing narrows the sealed destination to what
            // that layer reads; it does not re-seal it, and it cannot widen where the unit may go.
            let lower = self.lower()?;
            // A `wss://` target says the bytes are encrypted before they leave this process, and
            // this transport encrypts nothing of its own: it upgrades whatever stream the layer
            // below gives up. So the secure claim is the lower layer's to keep, and over a
            // cleartext one the handshake would go out as a plain GET with no certificate ever
            // validated — a downgrade the destination never asked for. The dial is refused before
            // a socket is opened, which is the only answer that does not put cleartext on a wire
            // the caller was told was secure. Wrapping the stream here instead was the alternative
            // and is the wrong seam: the trust roots a node accepts upstream are the deployment's
            // statement, held by the `tls` layer's client config, not a root store this crate
            // would invent per dial.
            if secure && lower.key() != "tls" {
                return Err(TransportError::AddressRefused);
            }
            let beneath = dest
                .beneath(
                    lower.key(),
                    busbar_contract_transport::dest::UpstreamAddress::Socket {
                        authority,
                        sni: address.sni().or(if secure {
                            Some(intern(&host_name))
                        } else {
                            None
                        }),
                    },
                )
                .ok_or(TransportError::AddressRefused)?;
            let conn = lower.dial(&beneath, keys).await?;
            // The whole record, not only the chain: the layer below is about to give the stream
            // up and will never be able to answer for this connection again.
            let below = lower.arrival(&conn);
            let facts = LowerFacts::of(&below);
            let mut chain = below.transport_chain;
            let raw = lower.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(<Self as TransportMeta>::KEY);

            let request_url = format!(
                "{}://{host_name}:{port}{path}",
                if secure { "wss" } else { "ws" }
            );
            let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(raw.into_io());
            self.handshake(
                Box::new(stream),
                false,
                &request_url,
                authority,
                chain,
                facts,
            )
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
                if done || state.is_poisoned() || state.is_closed() {
                    return None;
                }
                let mut slot = state.reader.lock().await;
                let taken = slot.take()?;
                drop(slot);
                // The reader belongs to the connection, not to this future. Holding it in a guard
                // is what makes a cancelled read the same non-event a cancelled poll of any other
                // stream is: the guard's `Drop` runs whether this future completes or is dropped
                // mid-read, so the next pump reads on rather than seeing a reader-shaped hole it
                // would report as a clean end of session.
                let mut held = ReaderGuard {
                    state: state.clone(),
                    reader: Some(taken),
                };
                let reader = held.reader.as_mut().expect("held for the guard's lifetime");
                let item = loop {
                    match reader.next().await {
                        None => break None, // the peer closed the socket
                        Some(Ok(Message::Binary(b))) => {
                            // One copy, straight into the slab: `to_vec` then `Arc::from` copied the payload
                            // twice, on the hot path, for every inbound message.
                            let bytes = SlabBytes::new(Arc::<[u8]>::from(&b[..]));
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
                            let bytes = SlabBytes::new(Arc::<[u8]>::from(t.as_bytes()));
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
                        Some(Err(e)) => break Some(Err(read_error(&e))),
                    }
                };
                drop(held);
                // Checked again on the way out, not only on the way in: this pump was already
                // suspended in the read when the close was decided, and a frame that arrived
                // afterwards belongs to a session the layer above has been told is over.
                if state.is_closed() {
                    return None;
                }
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
            // The lock first, the fence second. A write dropped while still QUEUED on the writer
            // put no bytes on the socket, so there is no half-written frame to fence — arming
            // before the lock condemned a healthy connection permanently on nothing but
            // contention. From here on the send is the only thing that can be interrupted, which
            // is exactly what the fence is for.
            let mut w = state.writer.lock().await;
            let mut guard = PoisonGuard {
                state: &state,
                armed: true,
            };
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
            // Read before the detach, for the same reason: after it, `from` knows nothing about
            // this connection, and the port, name, protocol and certificate it established are
            // facts about the connection rather than about the layer that observed them.
            let below = from.arrival(&conn);
            let facts = LowerFacts::of(&below);
            let mut chain = below.transport_chain;
            let raw = from.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(<Self as TransportMeta>::KEY);
            let peer = raw.peer().to_string();
            let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(raw.into_io());
            self.handshake(Box::new(stream), true, "", &peer, chain, facts)
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
            // The fence goes up before anything is spawned, and before the courtesy frame goes
            // out: leaving the registry is invisible to a pump that already holds this state, and
            // a frame delivered after the close is one nothing upstream still owns.
            state.closed.store(true, Ordering::Release);
            // The Close frame is a courtesy, and the connection is already finalised: the state has
            // left the registry, so nothing can cancel the task that sends it. It therefore cancels
            // itself. A peer whose receive window is full never accepts the frame, and without this
            // budget the task, the writer lock and the socket would outlive the connection.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(CLOSE_BUDGET, async {
                    let mut w = state.writer.lock().await;
                    let _ = futures::SinkExt::send(&mut *w, Message::Close(None)).await;
                })
                .await;
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
            // The refusal is the only answer the far side will ever get about these bytes, so a
            // send that did not happen is reported rather than swallowed. A connection this
            // transport no longer holds, or one already fenced, cannot carry one at all — both are
            // `Closed`, because the session is over either way and the caller's next move is the
            // same. A send that reached the socket and failed is a `Reset`: the connection was
            // live and the peer is what went away.
            let outcome = match self.state_of(id) {
                None => Err(TransportError::Closed),
                Some(state) if state.is_poisoned() => Err(TransportError::Closed),
                Some(state) => {
                    let payload = bytes.as_slice().to_vec();
                    let mut w = state.writer.lock().await;
                    let sent = futures::SinkExt::send(&mut *w, Message::Binary(payload.into()))
                        .await
                        .map_err(|_| TransportError::Reset);
                    drop(w);
                    sent
                }
            };
            // Finalised on every path, including the failures: a refusal ends the connection, and
            // one that could not be written ends it no less than one that could.
            self.close(conn, CloseReason::Normal);
            outcome
        })
    }
}

/// What a failed read of the WebSocket stream means to the layer above.
///
/// Reporting all of them as `Reset` told a network story about protocol events, and the two get
/// different answers upstream: a reset is a connection that broke and may be worth redialling, a
/// framing failure is a peer whose bytes were wrong and redialling changes nothing. A close the
/// peer already completed is neither — it is the session ending, and the only error shape for that
/// is `Closed`.
fn read_error(e: &tokio_tungstenite::tungstenite::Error) -> TransportError {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match e {
        // The bytes were not WebSocket: a reserved opcode, a message past the cap, a text frame
        // that was not UTF-8. Nothing happened to the connection.
        WsError::Protocol(_) | WsError::Capacity(_) | WsError::Utf8(_) => TransportError::Framing,
        // The closing handshake is finished, or something asked for a read after it was.
        WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::Closed,
        // Everything else — IO, TLS, a full write buffer — really is the connection going away
        // underneath this layer.
        _ => TransportError::Reset,
    }
}

/// The read-side counterpart of [`PoisonGuard`]: the reader is put back where the connection keeps
/// it however this future ends, including a drop mid-read.
///
/// Without it a cancelled read left the slot empty and the next `frames()` call read that hole as a
/// clean end of session — on a session transport, the same answer as the peer closing. The slot's
/// lock is free by construction here (the guard is built after the lock is released and the reader
/// is put back before anything else can take it), so a `try_lock` that somehow failed would mean a
/// second pump held the connection, and fencing is the honest answer to that rather than dropping
/// the reader on the floor.
struct ReaderGuard {
    state: Arc<ConnState>,
    reader: Option<futures::stream::SplitStream<Sock>>,
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            match self.state.reader.try_lock() {
                Ok(mut slot) => *slot = Some(reader),
                Err(_) => self.state.poisoned.store(true, Ordering::Release),
            }
        }
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
    impl busbar_contract::plugin::KernelSeal for NoKeySeal {
        fn seal_origin(&self) -> &'static str {
            "busbar-transport-ws: an upgrade reads no key of its own"
        }
    }
    TransportKeyHandle::issue(&NoKeySeal, 0, "none")
});
