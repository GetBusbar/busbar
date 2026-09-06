// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tls` transport: frames over TLS, composed over `tcp`.
//!
//! `tls` inherits `tcp`'s session shape (`SESSION = true`) and adds session binding
//! (`SESSION_BOUND = true`): once a TLS handshake completes, the session's principal is cached
//! rather than re-derived per unit. Key material never lives in this crate's own state as bytes a
//! caller can read: [`busbar_contract::TransportKeyHandle`] is opaque, so this crate keeps a
//! slot-keyed registry of already-built `rustls` configs and looks one up by the handle's slot. The
//! transport-key unit is what fills that registry, through
//! [`busbar_unit_transport_key::TlsConfigSink`], at the moment it resolves the material and writes
//! the `Access` entry the design requires — so a production listener has a key for the same reason
//! a test one does, and nothing in this crate ever resolves a `SecretRef` or sees a byte of one.
//!
//! ## Composition
//!
//! `listen`/`accept`/`dial` bind and connect their own TCP sockets directly (self-contained)
//! rather than routing every byte through a `TcpTransport` instance, because a session transport
//! owns its own accept loop. The place this crate composes over `busbar-transport-tcp` is the
//! in-band upgrade path, and it is a trait method rather than a free function: `tls` ADOPTS a
//! connection `tcp` gives up, because the connection that comes out belongs to this transport's
//! registry and only this transport can put it there. The composed chain travels with the handoff,
//! so an adopted connection reports the stack it actually stands on rather than a guess.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::{
    ArenaBytes, Frame, Fut, Kind, Plugin, Refusal, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportKeyHandle, TransportMeta,
};
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::wire::ArrivalRecord;
use busbar_contract_transport::wire::CertFacts;
use busbar_contract_transport::wire::CloseReason;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::ConnHandle;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::Listener;
use busbar_contract_transport::wire::ListenerHandle;
use busbar_contract_transport::wire::TransportError;
use futures::Stream;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Re-exported so a caller building [`rustls::ServerConfig`]/[`rustls::ClientConfig`] values to
/// hand to [`TlsTransport::register_server_config`]/`register_client_config` names one crate for
/// both the transport and the crypto library it is built on.
pub use rustls;

/// How many bytes one read syscall may fill a frame with.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// How long an inbound TLS handshake has to complete before the connection is dropped.
///
/// `accept` runs the handshake inline, so without a budget one peer that opens a TCP connection and
/// then sends nothing holds the accept loop for as long as it likes — a listener taken out of
/// service by a client that never spent a byte. Ten seconds is the same budget the egress
/// connector's own connect timeout is set to, so the two ends of this crate's tolerance for a peer
/// that will not talk are one number rather than two.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the courtesy `close_notify` alert may take to reach the peer before this transport gives
/// the session up.
///
/// The alert is a write, and the first thing it waits for is the writer lock — held, in production,
/// by whatever write is already in flight. A peer that has stopped reading never lets that write
/// finish, so without a bound the alert waits forever: `close` has already dropped the only handle
/// that could cancel its task, so that task, the writer lock, the rustls session and the socket
/// under it outlive the connection for the life of the process, and `unit0_refusal` — which sends
/// the alert inline — never answers its caller at all. Generous rather than tight: a peer whose
/// receive window is briefly full is not a peer that has gone away.
pub const CLOSE_NOTIFY_BUDGET: Duration = Duration::from_millis(250);

/// Any duplex byte stream this transport can run a handshake over: the socket it opened itself, or
/// the one a lower layer handed up. Boxing it is what lets one connection type cover both, so an
/// adopted connection is not a second shape with a second set of methods.
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Io for T {}

type BoxedIo = Box<dyn Io>;
type ServerStream = tokio_rustls::server::TlsStream<BoxedIo>;
type ClientStream = tokio_rustls::client::TlsStream<BoxedIo>;

struct Inner {
    /// The local port this connection stands on: the listener's for an accepted connection, the
    /// ephemeral one the dial went out on for a dialled one, and the layer below's for an adopted
    /// one — which is the only case where this transport did not open the socket itself.
    local_port: u16,
    sni: Option<String>,
    alpn: Option<String>,
    peer_cert: Option<CertFacts>,
    /// The composed stack this connection actually stands on, bottom layer first. A connection this
    /// transport opened itself stands on its own socket; an adopted one stands on whatever the
    /// layer below it was already standing on, which is why this is carried rather than assumed.
    chain: Vec<&'static str>,
    read: AsyncMutex<ReadSide>,
    write: AsyncMutex<InnerWrite>,
    /// Set once the kernel has finalised this connection. A frame stream captured its own clone of
    /// this state before the close, so the registry removal alone would not reach it; this is the
    /// flag that stream checks so it ends at the next poll and the TLS stream actually drops.
    closed: AtomicBool,
    /// The wakeup that goes with the flag.
    ///
    /// A pump parked in `read` has no next poll to check the flag at: on a peer that completed the
    /// handshake and then said nothing, the read is outstanding until a record arrives, and none
    /// ever does. The flag alone would leave that pump — and the rustls session and socket it holds
    /// the last clone of — alive for the life of the process. The close notifies this, the read is
    /// raced against it, and the stream ends where it was parked.
    closing: tokio::sync::Notify,
}

impl Inner {
    /// Mark this connection finalised and wake whatever is parked on it.
    ///
    /// The order matters: the flag is stored FIRST, so a pump that arms its wait and then re-reads
    /// the flag can never miss both the store and the notification.
    fn finalise(&self) {
        self.closed.store(true, Ordering::Release);
        self.closing.notify_waiters();
    }
}

enum InnerRead {
    Server(ReadHalf<ServerStream>),
    Client(ReadHalf<ClientStream>),
}

/// A connection's read half and the buffer every read on it fills.
///
/// The buffer is allocated once, when the connection is registered, and reused for the life of the
/// connection: a fresh `READ_CHUNK_BYTES` `Vec` per read is an allocation and a zero-fill on the
/// frame path, for every read, for the life of every streaming connection. Keeping it behind the
/// same lock as the read half is what makes the reuse sound — a connection is read by one pump at
/// a time, so there is never a second reader to see a half-filled buffer.
struct ReadSide {
    half: InnerRead,
    scratch: Vec<u8>,
}

enum InnerWrite {
    Server(WriteHalf<ServerStream>),
    Client(WriteHalf<ClientStream>),
}

struct TlsConnHandle {
    id: u64,
    peer: String,
}

impl ConnHandle for TlsConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

struct TlsListenerHandle {
    addr: String,
}

impl ListenerHandle for TlsListenerHandle {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

/// The `tls` transport.
pub struct TlsTransport {
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<Inner>>>,
    /// Keyed by the bound address; the value carries the slot the listener was provisioned with,
    /// so `accept` uses the same config `listen` validated rather than a fixed slot of its own.
    listeners: Mutex<HashMap<String, (Arc<TcpListener>, u64)>>,
    server_configs: Mutex<HashMap<u64, Arc<rustls::ServerConfig>>>,
    client_configs: Mutex<HashMap<u64, Arc<rustls::ClientConfig>>>,
    /// How long an inbound handshake has to complete; [`HANDSHAKE_TIMEOUT`] unless a caller said
    /// otherwise.
    handshake_timeout: Duration,
}

impl Default for TlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport").finish_non_exhaustive()
    }
}

impl TlsTransport {
    /// A transport with an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            server_configs: Mutex::new(HashMap::new()),
            client_configs: Mutex::new(HashMap::new()),
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }

    /// Set the budget an inbound handshake has to complete in, for a deployment — or a battery cell
    /// — whose tolerance is not the default ten seconds.
    #[must_use]
    pub fn with_handshake_timeout(mut self, budget: Duration) -> Self {
        self.handshake_timeout = budget;
        self
    }

    /// Register the server-side rustls config a [`TransportKeyHandle`]'s slot resolves to.
    ///
    /// The transport-key unit is what calls this, through [`busbar_unit_transport_key::TlsConfigSink`],
    /// at the moment it resolves the material and journals the access. Nothing here reads a secret;
    /// this end of the seam only ever sees an already-built config and a slot number.
    pub fn register_server_config(&self, slot: u64, cfg: Arc<rustls::ServerConfig>) {
        self.server_configs
            .lock()
            .expect("poisoned")
            .insert(slot, cfg);
    }

    /// Register the client-side rustls config a [`TransportKeyHandle`]'s slot resolves to.
    pub fn register_client_config(&self, slot: u64, cfg: Arc<rustls::ClientConfig>) {
        self.client_configs
            .lock()
            .expect("poisoned")
            .insert(slot, cfg);
    }

    fn inner(&self, id: u64) -> Option<Arc<Inner>> {
        self.conns.lock().expect("poisoned").get(&id).cloned()
    }

    fn insert_server(
        &self,
        stream: ServerStream,
        peer: SocketAddr,
        chain: Vec<&'static str>,
        local_port: u16,
    ) -> Conn {
        let (_, server_conn) = stream.get_ref();
        let alpn = server_conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        let sni = server_conn.server_name().map(str::to_string);
        let peer_cert = server_conn.peer_certificates().and_then(|certs| {
            certs.first().map(|c| CertFacts {
                // Not parsed: see the SELECTOR_FORMS note. The fingerprint below is the fact this
                // transport really does read off the presented certificate.
                subject: "peer".to_string(),
                issuer: "peer".to_string(),
                fingerprint: hex_lower(&ring_fingerprint(c.as_ref())),
            })
        });
        let (read, write) = tokio::io::split(stream);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(Inner {
            local_port,
            sni,
            alpn,
            peer_cert,
            chain,
            read: AsyncMutex::new(ReadSide {
                half: InnerRead::Server(read),
                scratch: vec![0_u8; READ_CHUNK_BYTES],
            }),
            write: AsyncMutex::new(InnerWrite::Server(write)),
            closed: AtomicBool::new(false),
            closing: tokio::sync::Notify::new(),
        });
        self.conns.lock().expect("poisoned").insert(id, inner);
        Conn::new(Arc::new(TlsConnHandle {
            id,
            peer: peer.to_string(),
        }))
    }

    fn insert_client(
        &self,
        stream: ClientStream,
        peer: SocketAddr,
        chain: Vec<&'static str>,
        local_port: u16,
    ) -> Conn {
        let (_, client_conn) = stream.get_ref();
        let alpn = client_conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        // From the dialling side, "peer" certificates are the server's own chain — this is how a
        // test (or a caller) can confirm which cert a listener actually served, independent of
        // which slot it was supposed to serve.
        let peer_cert = client_conn.peer_certificates().and_then(|certs| {
            certs.first().map(|c| CertFacts {
                // Not parsed: see the SELECTOR_FORMS note. The fingerprint below is the fact this
                // transport really does read off the presented certificate.
                subject: "peer".to_string(),
                issuer: "peer".to_string(),
                fingerprint: hex_lower(&ring_fingerprint(c.as_ref())),
            })
        });
        let (read, write) = tokio::io::split(stream);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(Inner {
            local_port,
            sni: None,
            alpn,
            peer_cert,
            chain,
            read: AsyncMutex::new(ReadSide {
                half: InnerRead::Client(read),
                scratch: vec![0_u8; READ_CHUNK_BYTES],
            }),
            write: AsyncMutex::new(InnerWrite::Client(write)),
            closed: AtomicBool::new(false),
            closing: tokio::sync::Notify::new(),
        });
        self.conns.lock().expect("poisoned").insert(id, inner);
        Conn::new(Arc::new(TlsConnHandle {
            id,
            peer: peer.to_string(),
        }))
    }

    /// The address of the buffer a connection reads through, for the test that pins one buffer per
    /// connection rather than one per read.
    #[cfg(test)]
    pub(crate) async fn scratch_addr(&self, id: u64) -> Option<usize> {
        let inner = self.inner(id)?;
        let guard = inner.read.lock().await;
        Some(guard.scratch.as_ptr() as usize)
    }

    fn map_io_err(e: &io::Error) -> TransportError {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => TransportError::Refused,
            io::ErrorKind::TimedOut => TransportError::Timeout,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                TransportError::Reset
            }
            io::ErrorKind::InvalidData => TransportError::HandshakeFailed,
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::InvalidInput => {
                TransportError::AddressRefused
            }
            _ => TransportError::Closed,
        }
    }
}

impl busbar_unit_transport_key::TlsConfigSink for TlsTransport {
    fn register_server_config(&self, slot: u64, cfg: Arc<rustls::ServerConfig>) {
        TlsTransport::register_server_config(self, slot, cfg);
    }

    fn register_client_config(&self, slot: u64, cfg: Arc<rustls::ClientConfig>) {
        TlsTransport::register_client_config(self, slot, cfg);
    }
}

/// A stand-in fingerprint: the SHA-256 of the DER bytes, formatted for [`CertFacts`]. Not a trust
/// decision — the trust decision already happened inside the rustls handshake; this is evidence
/// carried alongside it.
fn ring_fingerprint(der: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, der).as_ref().to_vec()
}

/// A digest rendered the way every other tool renders one: lowercase hex, two characters per byte.
///
/// The debug formatter this used to go through prints a Rust slice — brackets, commas, spaces, and
/// single-digit bytes with no leading zero. Nothing an operator has can compare that to the output
/// of `openssl x509 -fingerprint`, and the missing zeroes mean it is not even a stable rendering of
/// the digest: `0a` and `a` are the same byte spelled two different ways.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl Plugin for TlsTransport {
    fn key(&self) -> &'static str {
        Self::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract_transport::AbiVersion {
        busbar_contract_transport::registry::TRANSPORT_ABI
    }
}

impl TransportMeta for TlsTransport {
    const KEY: &'static str = "tls";
    // `ClientCertSubject` is deliberately absent. The form reads a distinguished name off the
    // presented certificate, and this transport does not parse one: what it records is the
    // certificate's fingerprint, a real fact the handshake already established. Advertising the
    // form on a constant subject would mean every client certificate compares equal, so a
    // cert-subject distinction would collapse silently rather than fail — the form goes back on
    // this row the day the DN is parsed, and not before.
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[
        busbar_contract::SelectorForm::Sni,
        busbar_contract::SelectorForm::Alpn,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &["tcp"];
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<busbar_contract_transport::wire::Unit0Trigger> =
        Some(busbar_contract_transport::wire::Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[tfacts::SNI, tfacts::ALPN, tfacts::PEER];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> = None;
}

impl Transport for TlsTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let inner = self.inner(conn.id());
        ArrivalRecord {
            source: conn.peer(),
            port: inner.as_ref().map_or(0, |i| i.local_port),
            alpn: inner.as_ref().and_then(|i| i.alpn.clone()),
            sni: inner.as_ref().and_then(|i| i.sni.clone()),
            peer_cert: inner.as_ref().and_then(|i| i.peer_cert.clone()),
            transport_chain: inner
                .as_ref()
                .map_or_else(|| vec!["tcp", "tls"], |i| i.chain.clone()),
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
            let server_cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&keys.slot())
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            let bind = cfg.bind().unwrap_or("127.0.0.1:0");
            let listener = TcpListener::bind(bind)
                .await
                .map_err(|_| TransportError::AddressRefused)?;
            let addr = listener
                .local_addr()
                .map_err(|_| TransportError::AddressRefused)?
                .to_string();
            self.listeners
                .lock()
                .expect("poisoned")
                .insert(addr.clone(), (Arc::new(listener), keys.slot()));
            let _ = server_cfg; // resolved once here to fail fast; re-resolved per-accept by slot
            Ok(Listener::new(Arc::new(TlsListenerHandle { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let addr = l.local_addr();
            let (listener, slot) = self
                .listeners
                .lock()
                .expect("poisoned")
                .get(&addr)
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|_| TransportError::Closed)?;
            stream.set_nodelay(true).ok();
            let local_port = stream.local_addr().map_or(0, |a| a.port());
            // Every accepted connection on this listener uses the config registered for the slot
            // this listener was provisioned with in `listen` — not a fixed slot of accept's own —
            // because the listener has no per-connection SNI to route on before the handshake
            // completes. A deployment that needs SNI-routed certs resolves that at the
            // transport-key unit, not here.
            let cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&slot)
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            let acceptor = TlsAcceptor::from(cfg);
            // The handshake runs inline, so it is also this accept loop's exposure: a peer that
            // completes the TCP connection and then says nothing costs itself nothing and holds the
            // listener indefinitely. The budget ends that — on expiry the future is dropped, and
            // with it the half-open stream, and the loop is free for the next caller.
            let tls_stream = tokio::time::timeout(
                self.handshake_timeout,
                acceptor.accept(Box::new(stream) as BoxedIo),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer, vec!["tcp", "tls"], local_port))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let address = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { address, .. } => address,
                _ => return Err(TransportError::AddressRefused),
            };
            let (name, addr) = split_address(&address)?;
            let cfg = self
                .client_configs
                .lock()
                .expect("poisoned")
                .get(&keys.slot())
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|e| Self::map_io_err(&e))?;
            stream.set_nodelay(true).ok();
            let local_port = stream.local_addr().map_or(0, |a| a.port());
            let connector = TlsConnector::from(cfg);
            let server_name = ServerName::try_from(name)
                .map_err(|_| TransportError::AddressRefused)?
                .to_owned();
            let tls_stream = connector
                .connect(server_name, Box::new(stream) as BoxedIo)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_client(tls_stream, addr, vec!["tcp", "tls"], local_port))
        })
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        Box::pin(futures::stream::unfold(inner, move |inner| async move {
            let inner = inner?;
            if inner.closed.load(Ordering::Acquire) {
                return None;
            }
            let mut guard = inner.read.lock().await;
            let side = &mut *guard;
            // Arm the wait BEFORE re-reading the flag: a close that lands between the two is seen
            // as the flag, and one that lands after it is seen as the notification. Neither order
            // leaves this parked.
            let mut closing = Box::pin(inner.closing.notified());
            closing.as_mut().enable();
            if inner.closed.load(Ordering::Acquire) {
                return None;
            }
            let reading = std::pin::pin!(async {
                match &mut side.half {
                    InnerRead::Server(r) => r.read(&mut side.scratch).await,
                    InnerRead::Client(r) => r.read(&mut side.scratch).await,
                }
            });
            let result = match futures::future::select(reading, closing).await {
                futures::future::Either::Left((r, _)) => r,
                // The close won: the read is dropped where it stood and the stream ends.
                futures::future::Either::Right(((), _)) => return None,
            };
            match result {
                Ok(0) => None,
                Ok(n) => {
                    // Copied out to exactly this frame's length; the scratch keeps whatever the
                    // read left in it, which nothing else ever looks at.
                    let bytes: Arc<[u8]> = Arc::from(&side.scratch[..n]);
                    drop(guard);
                    let frame = Frame {
                        direction: Direction::Inbound,
                        stream: StreamId(0),
                        bytes: SlabBytes::new(bytes),
                        meta: FrameMeta {
                            bytes: n as u64,
                            transport_units: None,
                            status: None,
                            status_code: None,
                            retry_after_secs: None,
                        },
                    };
                    Some((Ok((StreamId(0), frame)), Some(inner)))
                }
                Err(e) => {
                    drop(guard);
                    Some((Err(TlsTransport::map_io_err(&e)), None))
                }
            }
        }))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let mut guard = inner.write.lock().await;
            match &mut *guard {
                InnerWrite::Server(w) => {
                    w.write_all(bytes.as_slice())
                        .await
                        .map_err(|e| Self::map_io_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_io_err(&e))?;
                }
                InnerWrite::Client(w) => {
                    w.write_all(bytes.as_slice())
                        .await
                        .map_err(|e| Self::map_io_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_io_err(&e))?;
                }
            }
            Ok(bytes.len())
        })
    }

    /// A byte stream carries no envelope of its own: the bytes are the body, and a field written
    /// beside them would be bytes the peer never asked for. A transport that named one anyway would
    /// be inventing a framing this wire does not have.
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

    /// The in-band upgrade, from this side: the STARTTLS-shaped handoff the transports table names.
    ///
    /// `tcp` gives up its stream and `tls` takes it, and the connection that comes out is one this
    /// transport's own registry holds — which is precisely what the source could never have
    /// returned. The facts of the new layer are derived from the completed handshake and nothing
    /// is carried over from the layer below: after this returns, the source knows nothing about the
    /// connection and this transport knows everything.
    fn adopt<'a>(
        &'a self,
        from: &'a dyn Transport,
        conn: Conn,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            if !Self::COMPOSES_OVER.contains(&from.key()) {
                return Err(TransportError::HandoffMismatch);
            }
            // Read before the stream is taken: once the source has given the connection up it
            // knows nothing about it, and the port the bytes arrived on is the lower layer's to
            // report — this transport never opened that socket.
            let below = from.arrival(&conn);
            let mut chain = below.transport_chain;
            let local_port = below.port;
            let raw = from.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(Self::KEY);
            let peer: SocketAddr = raw
                .peer()
                .parse()
                .map_err(|_| TransportError::HandoffMismatch)?;
            let stream: BoxedIo = Box::new(FuturesAsyncReadCompatExt::compat(raw.into_io()));
            let cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&keys.slot())
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            // Same budget as `accept`, for the same reason: the peer whose stream was just handed
            // up is under no obligation to send a ClientHello, and this await is otherwise unbounded.
            let tls_stream = tokio::time::timeout(
                self.handshake_timeout,
                TlsAcceptor::from(cfg).accept(stream),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer, chain, local_port))
        })
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract_transport::wire::RawStream> {
        // Checked BEFORE the removal, under the same lock: see the sibling `tcp` note. Removing
        // first and then failing to unwrap loses the connection — no stream up, no entry left.
        let mut registry = self.conns.lock().expect("poisoned");
        if Arc::strong_count(registry.get(&conn.id())?) != 1 {
            return None;
        }
        let inner = registry.remove(&conn.id())?;
        drop(registry);
        let peer = conn.peer();
        let inner = Arc::try_unwrap(inner).ok()?;
        let stream: BoxedIo = match (inner.read.into_inner().half, inner.write.into_inner()) {
            (InnerRead::Server(r), InnerWrite::Server(w)) => Box::new(r.unsplit(w)),
            (InnerRead::Client(r), InnerWrite::Client(w)) => Box::new(r.unsplit(w)),
            // The halves of one connection are always the same side; a mismatch would mean the
            // registry had been torn, and there is no stream to hand up in that case.
            _ => return None,
        };
        Some(busbar_contract_transport::wire::RawStream::new(
            Self::KEY,
            peer,
            Box::new(TokioAsyncReadCompatExt::compat(stream)),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        // `tls` opens its own socket at `listen`/`dial` (a direct TLS listener over the raw TCP it
        // binds itself); the STARTTLS handoff `adopt` answers is a per-connection upgrade, not a
        // property of this instance, so there is no lower-layer instance to name here.
        None
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        // A frame stream holds its own clone of the state, so removing the registry entry is not
        // enough to drop the TLS stream: the flag is what ends that stream at its next poll, after
        // which the last clone goes and the socket really does close.
        let inner = self.conns.lock().expect("poisoned").remove(&conn.id());
        if let Some(inner) = inner {
            inner.finalise();
            shut_down_session(inner);
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        // `tls` inherits `tcp`'s single stream; the connection is the whole of what can be refused.
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let delivered = {
                let mut guard = inner.write.lock().await;
                match &mut *guard {
                    InnerWrite::Server(w) => deliver_refusal(w, bytes.as_slice()).await,
                    InnerWrite::Client(w) => deliver_refusal(w, bytes.as_slice()).await,
                }
            };
            // A refusal finalises the connection, so it ends it the way `close` does: dropping the
            // registry's clone is not enough, because a frame stream that started before the
            // refusal holds its own clone and would stay parked on the socket forever, keeping the
            // rustls session alive with it. The flag is what ends that stream, after which the last
            // clone goes and the session and its socket really close.
            //
            // This runs on every path out, delivered or not. A refusal whose bytes never reached
            // the peer is still a finalised connection — returning the write's error first would
            // leave the entry registered and that pump parked, which is the leak this ends, on the
            // one path where the peer is already gone.
            let removed = self.conns.lock().expect("poisoned").remove(&conn.id());
            if let Some(removed) = removed {
                removed.finalise();
                // Inline here: this path is already async, so the alert goes out before the refusal
                // reports done rather than on a task the caller cannot wait for.
                send_close_notify(&removed).await;
            }
            delivered
        })
    }
}

/// The pinned socket to connect to, and the name to offer as SNI.
///
/// The destination carries both: the address the trust unit pinned, and — separately — the name a
/// deployment says a certificate was issued for. Where a name is declared, that is what is offered,
/// so a certificate issued for a DNS name matches. Where none is declared the address itself stands
/// in, which is only ever right for an IP-addressed upstream, and there is nothing else honest to
/// offer. Nothing is leaked per dial: both halves are already `'static`, which is what the closed
/// address shape bought.
fn split_address(
    address: &busbar_contract_transport::dest::UpstreamAddress,
) -> Result<(&'static str, SocketAddr), TransportError> {
    let authority = address.authority().ok_or(TransportError::AddressRefused)?;
    let addr: SocketAddr = authority
        .parse()
        .map_err(|_| TransportError::AddressRefused)?;
    match address.sni() {
        Some(name) => Ok((name, addr)),
        None => {
            // No name declared: the literal the authority already spells, without its port, is the
            // only name this transport can offer without inventing one. There is no other arm to
            // take — a `SocketAddr` is v4 or v6 and nothing else, so the guard this used to carry
            // asked a question with one answer, and the refusal behind it was unreachable. The
            // parse above is what refuses an authority that names no address.
            let host_part = authority
                .rsplit_once(':')
                .map_or(authority, |(h, _)| h)
                .trim_start_matches('[')
                .trim_end_matches(']');
            Ok((host_part, addr))
        }
    }
}

/// Send the TLS `close_notify` alert this session's peer is owed, then let the halves drop.
///
/// Dropping a rustls stream without the alert is an ABRUPT close: the peer's own rustls reports
/// `UnexpectedEof` rather than a clean end of stream, because that is exactly what a truncation
/// attack looks like from the inside — and a peer that cannot tell a deliberate close from a
/// truncated one has to treat every close as suspect. This transport knows which one this is, so
/// it says so.
///
/// Bounded by [`CLOSE_NOTIFY_BUDGET`], because the alert is a courtesy and the session is already
/// finalised: the lock it waits for is held by whatever write is in flight, and a peer that stopped
/// reading never lets that finish. An unbounded wait here is a task, a writer lock, a rustls session
/// and a socket that outlive the connection — and on the refusal path, a caller that is never
/// answered. A peer that would not take the alert in time gets the abrupt close instead, which is
/// the same close it would have got had this transport never sent one.
async fn send_close_notify(inner: &Inner) {
    let _ = tokio::time::timeout(CLOSE_NOTIFY_BUDGET, async {
        let mut guard = inner.write.lock().await;
        match &mut *guard {
            InnerWrite::Server(w) => {
                let _ = w.shutdown().await;
            }
            InnerWrite::Client(w) => {
                let _ = w.shutdown().await;
            }
        }
    })
    .await;
}

/// [`send_close_notify`] from `close`, which the trait makes synchronous.
///
/// The alert is a write, and a write is async; the only place to put it is a task. Where there is
/// no runtime to spawn one on — a caller closing outside an async context — the halves drop as they
/// did before, which is the abrupt close rather than a panic.
fn shut_down_session(inner: Arc<Inner>) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move { send_close_notify(&inner).await });
    }
}

/// Put a Unit 0 refusal's bytes on the wire and report whether they actually left.
///
/// `write_all` on a TLS stream only proves the plaintext reached rustls's own buffer; the ciphertext
/// may never have reached the socket. The kernel is told a refusal was delivered, and a refusal is
/// the client-visible answer to an authentication failure, so the flush is the evidence — the same
/// evidence the ordinary write path already takes — and its failure is reported rather than
/// swallowed.
async fn deliver_refusal<W>(w: &mut W, bytes: &[u8]) -> Result<(), TransportError>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    w.write_all(bytes)
        .await
        .map_err(|e| TlsTransport::map_io_err(&e))?;
    w.flush().await.map_err(|e| TlsTransport::map_io_err(&e))
}

#[cfg(test)]
mod tests;
