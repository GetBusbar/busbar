// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::{Stream, StreamExt};

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::transport::wire::ArrivalRecord;
use busbar_contract::transport::wire::CloseReason;
use busbar_contract::transport::wire::Conn;
use busbar_contract::transport::wire::Direction;
use busbar_contract::transport::wire::FrameMeta;
use busbar_contract::transport::wire::Listener;
use busbar_contract::transport::wire::TransportError;
use busbar_contract::unit::Refusal;
use busbar_contract::wire::Frame;
use busbar_contract::{
    Fut, ScratchBytes, SlabBytes, StreamId, Transport, TransportConfigView, TransportKeyHandle,
    TransportMeta,
};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

use crate::conn::{ConnState, LowerFacts, LowerIo, Sock, WsConnHandle};

/// How long a courtesy Close frame may take to reach the peer before this transport gives up on
/// it. A peer whose receive window is full can never accept one, and a send with no bound would
/// hold the writer lock — and the socket — for the process's lifetime, because `close` has already
/// dropped the only handle that could cancel it.
pub(crate) const CLOSE_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// The RFC 6455 close code a [`CloseReason`] puts on the wire.
///
/// `close` used to send a bare `Message::Close(None)` regardless of why: a peer that gets no code
/// cannot tell an orderly shutdown from a policy revocation from a capacity limit, and one that
/// gets 1009 (Message Too Big) can act on the specific cause — back off, split the payload, log it
/// — where a bare close leaves it guessing. Every arm below is a code [`CloseCode::is_allowed`]
/// accepts for sending: the reserved codes (1005 Status, 1006 Abnormal, 1015 Tls) describe a
/// condition to a *local* API caller and must never appear in a frame an endpoint actually sends, so
/// none of `busbar`'s own reasons are routed to them. Kept a distinct code per reason rather than
/// folding several onto the closest match: a caller that later wants to distinguish, say, `Revoked`
/// from `CapacityExhausted` on the wire should not find both already spent on the same number.
fn close_code_for(reason: CloseReason) -> CloseCode {
    match reason {
        // "An orderly close" is exactly what 1000 means.
        CloseReason::Normal => CloseCode::Normal,
        // For an explicit `Transport::close(conn, PeerClosed)` call: THIS endpoint is closing
        // `conn` because it learned, some way other than a Close frame arriving ON `conn` itself,
        // that its counterpart is gone (e.g. a multiplexing layer tearing down a related
        // connection). "Going away" is 1001's own definition.
        //
        // NOT the code for replying to a Close frame this transport reads directly off `conn`'s
        // own wire — that reply is tungstenite's, not this function's: `frames()` below drives it
        // out with a flush rather than building one, and it echoes the PEER's own code (1000 in
        // the ordinary case), never a hardcoded 1001.
        CloseReason::PeerClosed => CloseCode::Away,
        // Node draining is a deliberate, orderly shutdown for maintenance/redeploy — "the server is
        // restarting" is 1012's own definition, reconnect-elsewhere guidance included.
        CloseReason::Drain => CloseCode::Restart,
        // A panic mid-codec is this endpoint's own unexpected condition, not the peer's fault or the
        // wire's: 1011 is the generic internal-error code the RFC reserves for exactly that.
        CloseReason::Poisoned => CloseCode::Error,
        // Authority withdrawn is an access-control decision, and 1008 is the RFC's policy-violation
        // code for a termination with no more specific status to give.
        CloseReason::Revoked => CloseCode::Policy,
        // No RFC 6455 code names "a deadline expired"; 1013 ("Try Again Later") is the closest
        // registered meaning — it tells the peer the same thing a timeout implies, that a retry may
        // succeed where this attempt did not.
        CloseReason::Timeout => CloseCode::Again,
        // The transport layer failing is, from the wire's perspective, a protocol-level error.
        CloseReason::TransportFailed => CloseCode::Protocol,
        // No RFC 6455 code names "a spend/budget cap was hit" either; 1009 (Message Too Big) is the
        // closest registered meaning — a resource ceiling was exceeded — of the codes left unclaimed
        // by every other reason above.
        CloseReason::CapacityExhausted => CloseCode::Size,
    }
}

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

/// How long the Pong answering a peer's Ping may take to reach that peer before this transport gives
/// the session up.
///
/// The frame pump sends it while suspended in its own read, so unlike every other write in this
/// crate there is no handle anywhere that could cancel it: a peer that pings and then stops reading
/// would park the pump in the send for as long as it liked. Generous rather than tight — a peer
/// whose receive window is briefly full is not a peer that has gone away — and still bounded.
pub(crate) const PONG_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Every string [`intern`] has made `'static`, each exactly once.
static INTERNED: std::sync::LazyLock<SyncMutex<std::collections::HashSet<&'static str>>> =
    std::sync::LazyLock::new(|| SyncMutex::new(std::collections::HashSet::new()));

/// The `'static` view of a derived dial address, allocated at most once per distinct string, and
/// only ever at registration ([`WsTransport::register_target`]) — never by `dial` (CG-06: a
/// config-derived key is leaked exactly once, at the registration that reads it).
///
/// The sealed destination's address shape is already `'static`, but a `ws://` dial target is a URL:
/// the `host:port` this transport hands the layer below is derived from it, and where the URL
/// leaves the port implicit or brackets the host that string is not a slice of anything that
/// already lives forever. Interning makes the registration of such a target leak-once, the same
/// posture the boot-time lane names take, so a reload that registers it again reuses what the
/// first registration allocated.
pub(crate) fn intern(s: &str) -> &'static str {
    let mut table = INTERNED.lock().expect("ws address intern table poisoned");
    if let Some(already) = table.get(s) {
        return already;
    }
    let once: &'static str = Box::leak(s.to_string().into_boxed_str());
    table.insert(once);
    once
}

/// Whether `s` has been interned — the battery's view of what this process has leaked.
#[cfg(test)]
pub(crate) fn is_interned(s: &str) -> bool {
    INTERNED
        .lock()
        .expect("ws address intern table poisoned")
        .contains(s)
}

/// The `host:port` a `ws://` URL spells, as a slice of the URL itself, when the URL spells exactly
/// the authority `dial` hands the layer below: an explicit port and an unbracketed host. The URL a
/// sealed destination carries is `'static` already (leaked once where it was registered), so this
/// view costs nothing. `None` where the authority is derived rather than spelled — an implicit
/// port, a bracketed host — which is the shape [`WsTransport::register_target`] interns.
fn spelled_authority(url: &str) -> Option<&str> {
    let (_, host, port, _) = split_ws_url(url).ok()?;
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"))?;
    let authority = rest.find('/').map_or(rest, |i| &rest[..i]);
    let (h, p) = authority.rsplit_once(':')?;
    (h == host && p == port.to_string()).then_some(authority)
}

type FrameStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// One `ws://`/`wss://` URL, read into `(secure, host, port, path)`. Strict over the scheme, with
/// the authority read by the contract's one URL reader ([`busbar_contract::net::parse_url`], WHATWG
/// rules): it ends at `/`, `?`, `#` or `\` exactly where the handshake's parser ends it, the host
/// comes back unbracketed, and a userinfo is refused. The path always opens with `/`.
pub(crate) fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let secure = if url.starts_with("wss://") {
        true
    } else if url.starts_with("ws://") {
        false
    } else {
        return Err(TransportError::AddressRefused);
    };
    let parts = busbar_contract::net::parse_url(url).map_err(|_| TransportError::AddressRefused)?;
    if parts.userinfo {
        return Err(TransportError::AddressRefused);
    }
    let port = parts.port.unwrap_or(if secure { 443 } else { 80 });
    Ok((secure, parts.host, port, parts.path))
}

/// The WebSocket transport. In-tree, inside the trusted computing base — see the architecture
/// doc's transport and transports-table sections.
///
/// It opens no socket of its own. Every byte reaches it through the layer it composes over: the
/// lower transport binds, accepts and dials, and this one takes the stream that layer gives up and
/// runs the WebSocket handshake on it. That is what makes the composed chain real rather than
/// declared, and it is what puts the network guard and the frame-honesty
/// tests in ONE place for the whole stack instead of one place per transport.
pub struct WsTransport {
    next_id: AtomicU64,
    // `Arc`-wrapped so `frames()` — which only ever gets `&self`, not `Arc<Self>` — can clone a
    // handle to the SAME registry into its (`'static`) pump future. That handle is what lets the
    // pump deregister a connection when it finishes a peer-initiated close, which is what actually
    // drops the socket: see the Close arm in `frames()`.
    conns: Arc<SyncMutex<HashMap<u64, Arc<ConnState>>>>,
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
    /// The dial targets registered on this instance whose `host:port` is derived rather than
    /// spelled, each mapped to its interned authority. `dial` reads this and never interns: a
    /// target that is neither spelled nor registered is refused, not leaked (CG-06).
    targets: SyncMutex<HashMap<String, &'static str>>,
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
            conns: Arc::new(SyncMutex::new(HashMap::new())),
            max_message_bytes: std::sync::atomic::AtomicUsize::new(0),
            lower: None,
            targets: SyncMutex::new(HashMap::new()),
        }
    }

    /// A transport with no layer under it, carrying the message ceiling its embedder named.
    ///
    /// The no-lower twin of [`WsTransport::over_with_max_message_bytes`]. An instance driven only
    /// through [`WsTransport::handshake_over`] or [`WsTransport::adopt`] never reaches
    /// [`Transport::listen`] — nothing binds it, so nothing hands it a configuration view — so the
    /// one place its message ceiling can arrive is the embedder that constructs it. The plain
    /// [`WsTransport::new`] leaves the number zero and tungstenite's own default stands, which is the
    /// behaviour that constructor keeps.
    #[must_use]
    pub fn with_max_message_bytes(max: usize) -> Self {
        let t = Self::new();
        t.max_message_bytes.store(max, Ordering::Relaxed);
        t
    }

    /// A transport composed over `lower` — the layer that binds, accepts and dials on its behalf.
    ///
    /// The design's own stack is `tcp → http → ws`, with core's connection security wrapped around
    /// the carrier host-side: `http` is what an inbound upgrade arrives on, and `tcp` is what an
    /// outbound one is dialled through. Which of them a given
    /// instance stands on is the composition root's declaration, and the boot check is what holds
    /// that declaration to the transports actually registered.
    #[must_use]
    pub fn over(lower: Arc<dyn Transport>) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: Arc::new(SyncMutex::new(HashMap::new())),
            max_message_bytes: std::sync::atomic::AtomicUsize::new(0),
            lower: Some(lower),
            targets: SyncMutex::new(HashMap::new()),
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

    /// Register a configured dial target: the one point at which this transport may allocate a
    /// `'static` view of the address it derives from the URL (CG-06). A target whose URL spells its
    /// `host:port` needs nothing and stores nothing; one whose port is implicit or whose host is
    /// bracketed has its authority interned here, once per distinct string across every instance,
    /// so a reload that registers it again allocates nothing new. `dial` only looks targets up.
    ///
    /// # Errors
    ///
    /// [`TransportError::AddressRefused`] for a target that is not a `ws://`/`wss://` URL.
    pub fn register_target(&self, url: &str) -> Result<(), TransportError> {
        let (_, host, port, _) = split_ws_url(url)?;
        if spelled_authority(url).is_none() {
            let authority = intern(&format!("{host}:{port}"));
            self.targets
                .lock()
                .expect("ws target table poisoned")
                .insert(url.to_string(), authority);
        }
        Ok(())
    }

    /// The authority `dial` hands the layer below for `url`: spelled in the URL, or registered.
    pub(crate) fn dial_authority(&self, url: &'static str) -> Option<&'static str> {
        spelled_authority(url).or_else(|| {
            self.targets
                .lock()
                .expect("ws target table poisoned")
                .get(url)
                .copied()
        })
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

            // The socket is the layer below's, dialled against the address this destination already
            // carries — no name is resolved here, which is what puts the network guard in front of
            // the dial instead of inside it. Re-addressing narrows the sealed destination to what
            // that layer reads; it does not re-seal it, and it cannot widen where the unit may go.
            let lower = self.lower()?;
            // A `wss://` target says the bytes are encrypted before they leave this process, and
            // this transport encrypts nothing of its own: it upgrades whatever stream the layer
            // below gives up, and no transport below it encrypts either — TLS is core's connection
            // security, never a transport layer. Over a cleartext layer the
            // handshake would go out as a plain GET with no certificate ever validated — a
            // downgrade the destination never asked for. The dial is refused before a socket is
            // opened, which is the only answer that does not put cleartext on a wire the caller
            // was told was secure. Wrapping the stream here instead is the wrong seam: the trust
            // roots a node accepts upstream are the deployment's statement, held host-side, not a
            // root store this crate would invent per dial.
            if secure {
                return Err(TransportError::AddressRefused);
            }
            // The authority was made `'static` where the target was registered, or is a slice of the
            // URL the destination already carries; `dial` allocates nothing that outlives it (CG-06).
            let authority = self
                .dial_authority(url)
                .ok_or(TransportError::AddressRefused)?;
            let beneath = dest
                .beneath(
                    lower.key(),
                    busbar_contract::transport::dest::UpstreamAddress::Socket {
                        authority,
                        sni: address.sni(),
                        extras: &[],
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
            chain.push(<crate::WsFramer as TransportMeta>::KEY);

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
        let conns = self.conns.clone();
        Box::pin(futures::stream::unfold(
            (state, false),
            move |(state, done)| {
                let conns = conns.clone();
                async move {
                    if done || state.is_poisoned() || state.is_closed() {
                        return None;
                    }
                    let mut slot = state.reader.lock().await;
                    let Some(taken) = slot.take() else {
                        drop(slot);
                        // The reader is gone. A connection that was closed or fenced put it back before
                        // this poll and is a clean end — the checks above already caught those, but the
                        // window between them and this lock is a real one, so re-read the fences here and
                        // end quietly if either fired. What is left is the reader being HELD by another
                        // live `frames()` stream on a clone of this `Conn`: a WebSocket carries one
                        // message stream and it has exactly one reader, so a second consumer cannot get
                        // frames. Returning `None` here would report it as a peer that cleanly closed —
                        // indistinguishable from a real close, and a silent lie about a session that is
                        // still running for the first consumer. It is a caller-side contract violation,
                        // and the honest answer is to say so loudly rather than fake an end of stream.
                        if state.is_poisoned() || state.is_closed() {
                            return None;
                        }
                        panic!(
                        "busbar-transport-ws: frames() called concurrently on the same connection; \
                         a WebSocket carries one message stream with one reader and admits exactly \
                         one consumer — the second silently terminating as a clean close would be a \
                         session cut nothing could see"
                    );
                    };
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
                    // Set only by THIS iteration's own violation handling below, never by a
                    // `close()` racing in from elsewhere: the late-close check just past the loop
                    // exists for that external race ("a frame that arrived afterwards belongs to a
                    // session already told closed") and must keep discarding for it. But `closed`
                    // is the one fence both that race and a violation THIS pump just answered set,
                    // so without a separate flag the check could not tell "an external close beat
                    // me to it" from "I am the reason `closed` just became true" -- and would
                    // discard the very violation error this arm exists to report, turning a real
                    // protocol failure into a silent, indistinguishable clean end of session.
                    let mut closed_by_this_violation = false;
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
                                    status_code: None,
                                    retry_after_secs: None,
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
                                    status_code: None,
                                    retry_after_secs: None,
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
                            // RFC 6455 §5.5.1/§7.1.5: an endpoint that receives a Close frame and has
                            // not already sent one MUST send a Close frame in response before the
                            // underlying connection ends. NO REPLY IS BUILT HERE: tungstenite parses
                            // the incoming Close and already QUEUES the reply the moment `reader.next()`
                            // (above) returns it -- echoing the peer's own code and reason, as RFC 6455 §5.5.1
                            // recommends -- the prebuilt library owns that decision, not this crate. Its
                            // own docs are explicit that the queued reply needs a caller to keep driving
                            // read/write/flush to actually reach the wire (tungstenite
                            // `protocol/mod.rs`: "You should continue calling read, write or flush to
                            // drive the reply to the close frame... until Error::ConnectionClosed").
                            // This pump was doing none of those after a Close, so the queued reply sat
                            // in the write buffer forever and every peer-initiated close timed out
                            // waiting for one — on every single connection this transport ever served.
                            // The fix is the flush the docs ask for, budget-bound like every other
                            // write this pump answers unprompted.
                            //
                            // `closed` is the SAME fence `close()` sets, tested and set here with one
                            // atomic op: whichever of the two call sites gets there first drives the
                            // reply out, and the other finds it already sent and stays quiet -- a
                            // concurrent explicit `close()` and a peer-initiated close racing here can
                            // otherwise both try to write, which is a second frame after a close no peer
                            // is still parsing.
                            //
                            // DEREGISTERING is not optional either. Flushing the reply satisfies the
                            // *frame* layer, but RFC 6455 §7.1.1 also puts the underlying connection's
                            // teardown on this (server) side, and a peer's WebSocket library — the far
                            // side's own stack, browsers, every one Autobahn drives — waits for the
                            // SOCKET to end, not merely for the reply frame, before it calls the
                            // handshake closed. `self.conns` is the only other owner of this
                            // connection's `Arc<ConnState>` ("the fence goes up before anything is
                            // spawned" doc on `close()`, above); removing this id from it drops the
                            // last reference once this pump's own local `state` clone goes out of
                            // scope, which drops `reader`/`writer` and, with them, the socket — the end
                            // the peer is waiting for. Left registered, the reply frame answers the
                            // frame-level handshake and the connection leaks for the rest of the
                            // process, which every peer sees as a hang, not a close.
                            Some(Ok(Message::Close(_))) => {
                                if state
                                    .closed
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                                {
                                    let _ = tokio::time::timeout(CLOSE_BUDGET, async {
                                        let mut w = state.writer.lock().await;
                                        futures::SinkExt::flush(&mut *w).await
                                    })
                                    .await;
                                    conns.lock().unwrap().remove(&id);
                                }
                                break None;
                            }
                            // Ping/Pong carry no plane data; tungstenite does not auto-answer a Ping
                            // on a raw split stream, so this transport answers it itself and keeps
                            // reading — a protocol-blind, byte-level obligation, not plane meaning.
                            //
                            // The answer is still a write, and it is the one write in this crate that
                            // nothing above it can cancel: the pump is suspended INSIDE it, so a peer
                            // that pings and then stops reading parks the pump in the send forever,
                            // holds the connection state the pump carries, and keeps the socket alive
                            // for the life of the process. The budget is what ends that, and a failure
                            // is reported rather than swallowed — the layer above is otherwise told the
                            // session is healthy by a pump that will never yield another frame. The
                            // fence goes with it, because a send abandoned at the budget is a send
                            // interrupted mid-frame, which is what every other write here fences for.
                            Some(Ok(Message::Ping(payload))) => {
                                let answered = tokio::time::timeout(PONG_BUDGET, async {
                                    let mut w = state.writer.lock().await;
                                    futures::SinkExt::send(&mut *w, Message::Pong(payload)).await
                                })
                                .await;
                                match answered {
                                    Ok(Ok(())) => continue,
                                    Ok(Err(e)) => break Some(Err(read_error(&e))),
                                    Err(_) => {
                                        state.poisoned.store(true, Ordering::Release);
                                        break Some(Err(TransportError::Backpressure));
                                    }
                                }
                            }
                            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => continue,
                            // RFC 6455 §7.1.7 "Fail the WebSocket Connection": a locally-detected
                            // protocol violation (a reserved opcode, a message over the cap, a text
                            // frame that is not UTF-8) obliges this endpoint to fail the connection,
                            // and SHOULD send a Close frame naming why first. UNLIKE the peer-Close
                            // arm above, tungstenite queues nothing here on its own -- there is no
                            // peer code to echo, because the peer never sent a valid Close; the code
                            // is this endpoint's OWN finding, so it is built from the same
                            // reason→code table `close()` already uses (not new protocol logic, the
                            // crate's one existing table), picking `CapacityExhausted` for a message
                            // over the cap and `TransportFailed` (Protocol, 1002) for everything
                            // else `read_error` calls `Framing`. Best-effort and budget-bound, same
                            // as every other write this pump answers unprompted -- and the SAME
                            // deregister the peer-Close arm does, for the SAME reason: without it the
                            // socket leaks past this failed session for the rest of the process.
                            Some(Err(e)) => {
                                let terr = read_error(&e);
                                if terr == TransportError::Framing
                                    && state
                                        .closed
                                        .compare_exchange(
                                            false,
                                            true,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        )
                                        .is_ok()
                                {
                                    closed_by_this_violation = true;
                                    let reason = if matches!(
                                        e,
                                        tokio_tungstenite::tungstenite::Error::Capacity(_)
                                    ) {
                                        CloseReason::CapacityExhausted
                                    } else {
                                        CloseReason::TransportFailed
                                    };
                                    let close_frame = CloseFrame {
                                        code: close_code_for(reason),
                                        reason: "".into(),
                                    };
                                    let _ = tokio::time::timeout(CLOSE_BUDGET, async {
                                        let mut w = state.writer.lock().await;
                                        futures::SinkExt::send(
                                            &mut *w,
                                            Message::Close(Some(close_frame)),
                                        )
                                        .await
                                    })
                                    .await;
                                    conns.lock().unwrap().remove(&id);
                                }
                                break Some(Err(terr));
                            }
                        }
                    };
                    drop(held);
                    // Checked again on the way out, not only on the way in: this pump was already
                    // suspended in the read when the close was decided, and a frame that arrived
                    // afterwards belongs to a session the layer above has been told is over. NOT
                    // when THIS iteration is the one that just closed it (a violation answered
                    // above) — that item is the whole reason this pump has anything to report.
                    if state.is_closed() && !closed_by_this_violation {
                        return None;
                    }
                    match item {
                        None => None,
                        Some(result) => {
                            let done_next = result.is_err();
                            Some((result, (state, done_next)))
                        }
                    }
                }
            },
        ))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        let id = conn.id();
        Box::pin(async move {
            let Some(state) = self.state_of(id) else {
                return Err(TransportError::Closed);
            };
            if state.is_poisoned() {
                return Err(TransportError::Framing);
            }
            // ONE copy, and it is the floor. `bytes` is an `ScratchBytes<'a>` — a borrow into the
            // caller's arena, which owns the storage and outlives nothing here — and tungstenite's
            // `Message::Binary` takes owned `Bytes` it holds until the frame is flushed. `Vec ->
            // Bytes` is itself zero-copy (the allocation is reused), so this `to_vec` is the single
            // unavoidable copy. Removing it would mean handing the sink an `Arc`-backed `Bytes` that
            // shares the payload's storage, which the borrowed `ScratchBytes` cannot supply without
            // widening `Transport::write`'s ABI to pass owned/shared bytes — a change to the one
            // contract every transport implements, out of proportion to one memcpy. Left as is.
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
        arena: &'a dyn busbar_contract::PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, busbar_contract::transport::wire::Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| busbar_contract::transport::wire::Encode::ScratchExhausted)
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
            if !<crate::WsFramer as TransportMeta>::COMPOSES_OVER.contains(&from.key()) {
                return Err(TransportError::HandoffMismatch);
            }
            // Read before the detach, for the same reason: after it, `from` knows nothing about
            // this connection, and the port, name, protocol and certificate it established are
            // facts about the connection rather than about the layer that observed them.
            let below = from.arrival(&conn);
            let facts = LowerFacts::of(&below);
            let mut chain = below.transport_chain;
            let raw = from.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(<crate::WsFramer as TransportMeta>::KEY);
            let peer = raw.peer().to_string();
            let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(raw.into_io());
            self.handshake(Box::new(stream), true, "", &peer, chain, facts)
                .await
        })
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract::transport::wire::RawStream> {
        // Nothing upgrades in-band over `ws` (`UPGRADES_TO` is empty), so there is no raw stream
        // this layer ever hands up.
        let _ = conn;
        None
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.lower.as_ref().map(|l| l.key())
    }

    fn close(&self, conn: Conn, reason: CloseReason) {
        let id = conn.id();
        if let Some(state) = self.conns.lock().unwrap().remove(&id) {
            // The fence goes up before anything is spawned, and before the courtesy frame goes
            // out: leaving the registry is invisible to a pump that already holds this state, and
            // a frame delivered after the close is one nothing upstream still owns.
            //
            // TESTED, not just set: the frame pump (`frames()`, above) answers a peer-initiated
            // Close through this SAME fence, so a caller that closes a connection just as the peer
            // is closing it can race the pump here. `compare_exchange` makes only the winner send
            // the courtesy frame; the loser finds it already sent and skips a second one a peer
            // that already got its close reply is no longer parsing.
            if state
                .closed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
            // The code this peer is told, not a bare close: a peer that gets 1009 can act on the
            // specific cause where a bare close leaves it guessing.
            let close_frame = CloseFrame {
                code: close_code_for(reason),
                reason: "".into(),
            };
            // The Close frame is a courtesy, and the connection is already finalised: the state has
            // left the registry, so nothing can cancel the task that sends it. It therefore cancels
            // itself. A peer whose receive window is full never accepts the frame, and without this
            // budget the task, the writer lock and the socket would outlive the connection.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(CLOSE_BUDGET, async {
                    let mut w = state.writer.lock().await;
                    let _ =
                        futures::SinkExt::send(&mut *w, Message::Close(Some(close_frame))).await;
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
        bytes: ScratchBytes<'a>,
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
                    // The lock first, the fence second — the identical discipline `write` and the
                    // Ping-answer path hold, and for the identical reason: a send interrupted
                    // mid-frame (this future dropped, or the send erroring) has put a partial WS
                    // frame on the wire, and a later write that resumed on that socket would splice
                    // its bytes onto the tail of a torn one. Arming only after the lock is held keeps
                    // a send still QUEUED on the writer — which put no bytes out — from condemning a
                    // healthy connection. The refusal finalises the connection right below, but the
                    // fence is what makes the send honest in the window a cancellation opens before
                    // that.
                    let mut w = state.writer.lock().await;
                    let mut guard = PoisonGuard {
                        state: &state,
                        armed: true,
                    };
                    let sent =
                        futures::SinkExt::send(&mut *w, Message::Binary(payload.into())).await;
                    // Disarm only on a clean completion: a send that erred left the same
                    // possibly-torn frame a dropped one does, so both fence — exactly as `write`
                    // returns through its own `?` with the guard still armed.
                    if sent.is_ok() {
                        guard.armed = false;
                    }
                    drop(w);
                    sent.map_err(|_| TransportError::Reset)
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
/// resolved host-side, by core's connection security, never by a transport. A handle
/// naming no slot is the honest way to say that rather than passing one this layer never reads.
static NO_KEYS: std::sync::LazyLock<TransportKeyHandle> =
    std::sync::LazyLock::new(TransportKeyHandle::keyless);
