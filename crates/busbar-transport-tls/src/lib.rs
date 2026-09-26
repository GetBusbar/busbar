// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tls` transport: frames over TLS, composed over `tcp`.
//!
//! `tls` inherits `tcp`'s session shape (`SESSION = true`) and adds session binding
//! (`SESSION_BOUND = true`): once a TLS handshake completes, the session's principal is cached
//! rather than re-derived per unit. Key material never lives in this crate's own state as bytes a
//! caller can read: [`busbar_contract::TransportKeyHandle`] is opaque, so this crate keeps a
//! slot-keyed registry of already-built `rustls` configs and looks one up by the handle's slot. The
//! kernel side fills that registry through the contract's [`TransportConfigSink`] — an opaque
//! [`TransportConfigHandle`] per slot and role, #40(b) — at the moment the material is resolved and
//! the `Access` entry the design requires is written, so a production listener has a key for the
//! same reason a test one does, and nothing in this crate ever resolves a `SecretRef` or sees a
//! byte of one.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::transport::wire::CertFacts;
use busbar_contract::transport::wire::Conn;
use busbar_contract::transport::wire::ConnHandle;
use busbar_contract::transport::wire::ListenerHandle;
use busbar_contract::transport::wire::TransportError;
use busbar_contract::transport::{ConfigRole, TransportConfigHandle, TransportConfigSink};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

mod claims;
mod meta;
mod transport;

/// Re-exported so a caller building [`rustls::ServerConfig`]/[`rustls::ClientConfig`] values to
/// hand to [`TlsTransport::register_server_config`]/`register_client_config` names one crate for
/// both the transport and the crypto library it is built on.
pub use rustls;

/// How many bytes one read syscall may fill a frame with.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// How long a TLS handshake has to complete before the connection is dropped — the same budget on
/// both directions.
///
/// `accept`/`adopt` run the handshake inline, so without a budget one peer that opens a TCP
/// connection and then sends nothing holds the accept loop for as long as it likes — a listener
/// taken out of service by a client that never spent a byte. `dial` runs its handshake inline too,
/// with the mirror-image exposure: a completed TCP connect proves nothing about whether the upstream
/// will ever send a ServerHello, and an unbounded handshake there parks the dial task and its
/// socket. Ten seconds is one number for both ends of this crate's tolerance for a peer that will
/// not talk, rather than two.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the courtesy `close_notify` alert may take to reach the peer — including the wait for
/// the connection's writer lock — before this transport gives up on it.
///
/// The alert is a write, and every write on a connection passes through one lock: a `close` that
/// races an in-flight write, or a peer whose receive window is full, can leave `close_notify`
/// waiting on that lock or on the socket for as long as either lasts. On the `close` path the alert
/// goes out on a detached task, so an unbounded wait there is a task, a rustls session and a socket
/// pinned for the life of the process; on the `unit0_refusal` path the alert is awaited inline, so
/// the same unbounded wait means the caller is NEVER answered. The alert is a courtesy the peer is
/// owed, not a delivery this connection blocks on — a quarter second is long enough for a peer that
/// is still reading and short enough that one that has stopped cannot hold anything. `ws` bounds its
/// own courtesy Close frame the same way.
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
    /// How long a handshake — inbound (`accept`/`adopt`) or outbound (`dial`) — has to complete;
    /// [`HANDSHAKE_TIMEOUT`] unless a caller said otherwise.
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

    /// Set the budget a handshake — inbound or outbound — has to complete in, for a deployment — or
    /// a battery cell — whose tolerance is not the default ten seconds.
    #[must_use]
    pub fn with_handshake_timeout(mut self, budget: Duration) -> Self {
        self.handshake_timeout = budget;
        self
    }

    /// Register the server-side rustls config a
    /// [`TransportKeyHandle`](busbar_contract::TransportKeyHandle)'s slot resolves to.
    ///
    /// The kernel side reaches this through [`TransportConfigSink`], at the moment the material is
    /// resolved and the access journaled. Nothing here reads a secret; this end of the seam only
    /// ever sees an already-built config and a slot number.
    pub fn register_server_config(&self, slot: u64, cfg: Arc<rustls::ServerConfig>) {
        self.server_configs
            .lock()
            .expect("poisoned")
            .insert(slot, cfg);
    }

    /// Register the client-side rustls config a
    /// [`TransportKeyHandle`](busbar_contract::TransportKeyHandle)'s slot resolves to.
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

    /// Map an IO error that arose on an ALREADY-ESTABLISHED session — a read or write after the
    /// handshake has completed — rather than during the handshake itself.
    ///
    /// It differs from [`map_io_err`](Self::map_io_err) on two kinds. During the handshake,
    /// `io::ErrorKind::InvalidData` is rustls saying the peer could not be authenticated, which is a
    /// `HandshakeFailed`. On a live session the handshake already succeeded — the peer WAS
    /// authenticated — and an `InvalidData` is instead a corrupted or tampered TLS record arriving
    /// mid-stream: the record's authentication tag did not verify, or its length framing was wrong.
    /// Reporting that as `HandshakeFailed` would tell an operator the identity check failed when it
    /// did not; it is the transport's own framing that a record violated, so it maps to
    /// [`TransportError::Framing`].
    ///
    /// `io::ErrorKind::UnexpectedEof` is the other: rustls's own defence against a truncation
    /// attack. A peer that sends the `close_notify` alert this session is owed produces a clean
    /// `Ok(0)` read, never an `Err` — see [`send_close_notify`]'s own doc. `UnexpectedEof` is what
    /// rustls reports instead, deliberately, when the underlying stream just ends with no alert:
    /// exactly what a peer that dropped the connection, or an attacker who cut it, looks like from
    /// the inside. Falling to [`map_io_err`](Self::map_io_err)'s catch-all reported it as
    /// `TransportError::Closed` — the value a caller reads as "the exchange finished", the same
    /// category a legitimate post-close write failure (`BrokenPipe`, `NotConnected`) still reports.
    /// That erased the one signal separating an honest close from a cut one, so it is named here
    /// instead and mapped to [`TransportError::Reset`] — "the connection was reset mid-stream" is
    /// this closed set's own words for it, and the value every other transport in this workspace
    /// already uses for a session that ended abnormally rather than one that simply ended.
    ///
    /// Every other kind carries the same meaning in both phases and is deferred to
    /// [`map_io_err`](Self::map_io_err).
    fn map_session_err(e: &io::Error) -> TransportError {
        match e.kind() {
            io::ErrorKind::InvalidData => TransportError::Framing,
            io::ErrorKind::UnexpectedEof => TransportError::Reset,
            _ => Self::map_io_err(e),
        }
    }
}

/// The contract's seam (#40(b)): the kernel side hands over an OPAQUE handle per slot and role, and
/// this end uses it as the `rustls` config it was built as. A [`ConfigRole::Listen`] handle carries
/// a [`rustls::ServerConfig`], a [`ConfigRole::Dial`] one a [`rustls::ClientConfig`]; a handle built
/// as anything else registers nothing, so the slot stays empty and `listen`/`dial` refuse it exactly
/// as they refuse a slot nobody provisioned.
impl TransportConfigSink for TlsTransport {
    fn register_config(&self, handle: TransportConfigHandle) {
        match handle.role() {
            ConfigRole::Listen => {
                if let Some(cfg) = handle.config::<rustls::ServerConfig>() {
                    TlsTransport::register_server_config(self, handle.slot(), cfg);
                }
            }
            ConfigRole::Dial => {
                if let Some(cfg) = handle.config::<rustls::ClientConfig>() {
                    TlsTransport::register_client_config(self, handle.slot(), cfg);
                }
            }
        }
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

/// The pinned socket to connect to, and the name to offer as SNI.
///
/// The destination carries both: the address the trust unit pinned, and — separately — the name a
/// deployment says a certificate was issued for. Where a name is declared, that is what is offered,
/// so a certificate issued for a DNS name matches. Where none is declared the address itself stands
/// in, which is only ever right for an IP-addressed upstream, and there is nothing else honest to
/// offer. Nothing is leaked per dial: both halves are already `'static`, which is what the closed
/// address shape bought.
fn split_address(
    address: &busbar_contract::transport::dest::UpstreamAddress,
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
async fn send_close_notify(inner: &Inner) {
    // Bounded, and the budget covers the writer lock as well as the shutdown itself: the alert is a
    // courtesy owed to a peer that is still there, never a delivery this connection parks on. A
    // `close` racing an in-flight write, or a peer that has stopped reading, would otherwise pin the
    // lock — and the task, rustls session and socket behind it — with no one left to cancel it, and
    // on the `unit0_refusal` path would leave the caller awaiting an answer that never comes. When
    // the budget elapses the halves drop unshut, which is the same abrupt close a caller off a
    // runtime already gets.
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
        .map_err(|e| TlsTransport::map_session_err(&e))?;
    w.flush()
        .await
        .map_err(|e| TlsTransport::map_session_err(&e))
}

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for this wire — its key, the
/// layers it declares, and how it is built. The root names none of them.
pub mod linked {
    use std::sync::Arc;

    use busbar_contract::transport::{Transport, TransportMeta, TransportSettings};

    use crate::TlsTransport;

    /// The row's registry key.
    pub const KEY: &str = <TlsTransport as TransportMeta>::KEY;
    /// The layers this wire declares it can be built over.
    pub const COMPOSES_OVER: &[&str] = <TlsTransport as TransportMeta>::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = <TlsTransport as TransportMeta>::SESSION;

    /// It opens its own socket, so it takes no lower layer and reads no setting.
    #[must_use]
    pub fn build(_: Option<Arc<dyn Transport>>, _: &TransportSettings) -> Arc<dyn Transport> {
        Arc::new(TlsTransport::new())
    }
}

#[cfg(test)]
mod tests;
