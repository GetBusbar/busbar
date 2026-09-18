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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::{Kind, Plugin, TransportMeta};
use busbar_contract_transport::wire::CertFacts;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::ConnHandle;
use busbar_contract_transport::wire::ListenerHandle;
use busbar_contract_transport::wire::TransportError;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

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

pub mod claims;
pub mod meta;
mod transport;

#[cfg(test)]
mod tests;
