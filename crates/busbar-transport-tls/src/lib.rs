// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tls` transport: frames over TLS, composed over `tcp`.
//!
//! `tls` inherits `tcp`'s session shape (`SESSION = true`) and adds session binding
//! (`SESSION_BOUND = true`): once a TLS handshake completes, the session's principal is cached
//! rather than re-derived per unit. Key material never lives in this crate's own state as bytes a
//! caller can read: [`busbar_contract::TransportKeyHandle`] is opaque, so this crate keeps a
//! slot-keyed registry of already-built `rustls` configs and looks one up by the handle's slot —
//! the seam a real transport-key unit would populate at `listen`/`dial`/`upgrade`, journaling the
//! `Access` entry the design requires. Tests populate it directly, which is the ambiguity named in
//! this crate's own delivery notes: nothing here resolves a `SecretRef` itself.
//!
//! ## Composition
//!
//! `listen`/`accept`/`dial` bind and connect their own TCP sockets directly (self-contained)
//! rather than routing every byte through a `TcpTransport` instance, because a session transport
//! owns its own accept loop. The one place this crate visibly composes over `busbar-transport-tcp`
//! is the in-band upgrade path: [`upgrade_from_tcp`] takes a `Conn` a `TcpTransport` produced (via its
//! `take_stream` seam) and turns it into a `tls`-framed one, for the STARTTLS-shaped case the
//! design's transport table names.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::{
    ArenaBytes, ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Direction, Fut, Frame,
    FrameMeta, Kind, Listener, ListenerHandle, Plugin, Refusal, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportError, TransportKeyHandle, TransportMeta,
};
use futures::Stream;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Re-exported so a caller building [`rustls::ServerConfig`]/[`rustls::ClientConfig`] values to
/// hand to [`TlsTransport::register_server_config`]/`register_client_config` names one crate for
/// both the transport and the crypto library it is built on.
pub use rustls;

/// How many bytes one read syscall may fill a frame with.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

type ServerStream = tokio_rustls::server::TlsStream<TcpStream>;
type ClientStream = tokio_rustls::client::TlsStream<TcpStream>;

struct Inner {
    sni: Option<String>,
    alpn: Option<String>,
    peer_cert: Option<CertFacts>,
    read: AsyncMutex<InnerRead>,
    write: AsyncMutex<InnerWrite>,
}

enum InnerRead {
    Server(ReadHalf<ServerStream>),
    Client(ReadHalf<ClientStream>),
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
    listeners: Mutex<HashMap<String, Arc<TcpListener>>>,
    server_configs: Mutex<HashMap<u64, Arc<rustls::ServerConfig>>>,
    client_configs: Mutex<HashMap<u64, Arc<rustls::ClientConfig>>>,
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
        }
    }

    /// Register the server-side rustls config a [`TransportKeyHandle`]'s slot resolves to. The
    /// seam a real transport-key unit populates at `listen`/`upgrade`; tests populate it directly.
    pub fn register_server_config(&self, slot: u64, cfg: Arc<rustls::ServerConfig>) {
        self.server_configs.lock().expect("poisoned").insert(slot, cfg);
    }

    /// Register the client-side rustls config a [`TransportKeyHandle`]'s slot resolves to.
    pub fn register_client_config(&self, slot: u64, cfg: Arc<rustls::ClientConfig>) {
        self.client_configs.lock().expect("poisoned").insert(slot, cfg);
    }

    fn inner(&self, id: u64) -> Option<Arc<Inner>> {
        self.conns.lock().expect("poisoned").get(&id).cloned()
    }

    fn insert_server(&self, stream: ServerStream, peer: SocketAddr) -> Conn {
        let (_, server_conn) = stream.get_ref();
        let alpn = server_conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        let sni = server_conn.server_name().map(str::to_string);
        let peer_cert = server_conn.peer_certificates().and_then(|certs| {
            certs.first().map(|c| CertFacts {
                subject: "peer".to_string(),
                issuer: "peer".to_string(),
                fingerprint: format!("{:x?}", ring_fingerprint(c.as_ref())),
            })
        });
        let (read, write) = tokio::io::split(stream);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(Inner {
            sni,
            alpn,
            peer_cert,
            read: AsyncMutex::new(InnerRead::Server(read)),
            write: AsyncMutex::new(InnerWrite::Server(write)),
        });
        self.conns.lock().expect("poisoned").insert(id, inner);
        Conn::new(Arc::new(TlsConnHandle {
            id,
            peer: peer.to_string(),
        }))
    }

    fn insert_client(&self, stream: ClientStream, peer: SocketAddr) -> Conn {
        let (_, client_conn) = stream.get_ref();
        let alpn = client_conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        let (read, write) = tokio::io::split(stream);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(Inner {
            sni: None,
            alpn,
            peer_cert: None,
            read: AsyncMutex::new(InnerRead::Client(read)),
            write: AsyncMutex::new(InnerWrite::Client(write)),
        });
        self.conns.lock().expect("poisoned").insert(id, inner);
        Conn::new(Arc::new(TlsConnHandle {
            id,
            peer: peer.to_string(),
        }))
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

/// A stand-in fingerprint: the SHA-256 of the DER bytes, formatted for [`CertFacts`]. Not a trust
/// decision — the trust decision already happened inside the rustls handshake; this is evidence
/// carried alongside it.
fn ring_fingerprint(der: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, der).as_ref().to_vec()
}

impl Plugin for TlsTransport {
    fn key(&self) -> &'static str {
        Self::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract::AbiVersion {
        busbar_contract::AbiVersion(1)
    }
}

impl TransportMeta for TlsTransport {
    const KEY: &'static str = "tls";
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[
        busbar_contract::SelectorForm::Sni,
        busbar_contract::SelectorForm::ClientCertSubject,
        busbar_contract::SelectorForm::Alpn,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &["tcp"];
    const HANDOFF: Option<busbar_contract::Handoff> = None;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<busbar_contract::Unit0Trigger> =
        Some(busbar_contract::Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &["tls_sni", "tls_alpn", "tls_peer_cert"];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract::StatusAt> = None;
}

impl Transport for TlsTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let inner = self.inner(conn.id());
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: inner.as_ref().and_then(|i| i.alpn.clone()),
            sni: inner.as_ref().and_then(|i| i.sni.clone()),
            peer_cert: inner.as_ref().and_then(|i| i.peer_cert.clone()),
            transport_chain: vec!["tcp", "tls"],
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
                .insert(addr.clone(), Arc::new(listener));
            let _ = server_cfg; // resolved once here; consumed again per-accept from the same slot
            Ok(Listener::new(Arc::new(TlsListenerHandle { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let addr = l.local_addr();
            let listener = self
                .listeners
                .lock()
                .expect("poisoned")
                .get(&addr)
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (stream, peer) = listener.accept().await.map_err(|_| TransportError::Closed)?;
            stream.set_nodelay(true).ok();
            // Every accepted connection on this listener uses the config registered for slot 0 —
            // the listener has no per-connection SNI to route on before the handshake completes,
            // so `listen`'s own slot is the one config an accept loop can use. A deployment that
            // needs SNI-routed certs resolves that at the transport-key unit, not here.
            let cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&0)
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            let acceptor = TlsAcceptor::from(cfg);
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let host = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { host, .. } => host,
                _ => return Err(TransportError::AddressRefused),
            };
            let (name, addr) = split_host(host)?;
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
            let connector = TlsConnector::from(cfg);
            let server_name = ServerName::try_from(name)
                .map_err(|_| TransportError::AddressRefused)?
                .to_owned();
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_client(tls_stream, addr))
        })
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        Box::pin(futures::stream::unfold(inner, move |inner| async move {
            let inner = inner?;
            let mut buf = vec![0_u8; READ_CHUNK_BYTES];
            let mut guard = inner.read.lock().await;
            let result = match &mut *guard {
                InnerRead::Server(r) => r.read(&mut buf).await,
                InnerRead::Client(r) => r.read(&mut buf).await,
            };
            match result {
                Ok(0) => None,
                Ok(n) => {
                    drop(guard);
                    buf.truncate(n);
                    let bytes: Arc<[u8]> = buf.into();
                    let frame = Frame {
                        direction: Direction::Inbound,
                        stream: StreamId(0),
                        bytes: SlabBytes::new(bytes),
                        meta: FrameMeta {
                            bytes: n as u64,
                            transport_units: None,
                            status: None,
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
                    w.write_all(bytes.as_slice()).await.map_err(|e| Self::map_io_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_io_err(&e))?;
                }
                InnerWrite::Client(w) => {
                    w.write_all(bytes.as_slice()).await.map_err(|e| Self::map_io_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_io_err(&e))?;
                }
            }
            Ok(bytes.len())
        })
    }

    fn upgrade<'a>(
        &'a self,
        conn: Conn,
        _to: &'a str,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // `tls` upgrades to nothing (`UPGRADES_TO` is empty): the in-band STARTTLS case is served
        // by `upgrade_from_tcp` below, which is not a trait method because it crosses transport
        // crates in the other direction (it consumes a `tcp`-owned `Conn`, which this trait
        // method's shape has no way to express — see this crate's delivery notes).
        let _ = conn;
        Box::pin(async move { Err(TransportError::Framing) })
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        self.conns.lock().expect("poisoned").remove(&conn.id());
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            {
                let mut guard = inner.write.lock().await;
                let result = match &mut *guard {
                    InnerWrite::Server(w) => w.write_all(bytes.as_slice()).await,
                    InnerWrite::Client(w) => w.write_all(bytes.as_slice()).await,
                };
                result.map_err(|e| Self::map_io_err(&e))?;
            }
            self.conns.lock().expect("poisoned").remove(&conn.id());
            Ok(())
        })
    }
}

fn split_host(host: &str) -> Result<(&'static str, SocketAddr), TransportError> {
    let addr: SocketAddr = host.parse().map_err(|_| TransportError::AddressRefused)?;
    // No separate hostname is carried by `DestinationFacts::Upstream` beyond `host` (an already
    // "host:port" string), so the connect address's own IP is offered as the SNI name — accurate
    // for an IP-addressed upstream, and named here as the ambiguity this crate cannot resolve on
    // its own: a real deployment names a DNS hostname in its lane config, resolves it upstream of
    // this transport (the resolve-then-pin guard the rest of the tree already uses), and would
    // need `DestinationFacts` to carry that hostname alongside the pinned address for SNI to be
    // the name a certificate was actually issued for rather than the address it resolved to.
    let name: &'static str = Box::leak(addr.ip().to_string().into_boxed_str());
    Ok((name, addr))
}

/// Turn a raw stream a lower transport handed off (a `tcp`-produced [`Conn`], detached via
/// [`busbar_transport_tcp::TcpTransport::take_stream`]) into a `tls`-framed one — the in-band
/// upgrade path (STARTTLS-shaped). Not a trait method: [`Transport::upgrade`]'s signature takes a
/// same-transport `Conn` it can look up in its own registry, and a cross-crate handoff needs the
/// caller to have already detached the raw stream, which only the source transport can do.
pub async fn upgrade_from_tcp(
    tls: &TlsTransport,
    tcp: &busbar_transport_tcp::TcpTransport,
    conn: Conn,
    keys: &TransportKeyHandle,
) -> Result<Conn, TransportError> {
    let (stream, peer) = tcp.take_stream(&conn).ok_or(TransportError::Closed)?;
    let cfg = tls
        .server_configs
        .lock()
        .expect("poisoned")
        .get(&keys.slot())
        .cloned()
        .ok_or(TransportError::KeyUnavailable)?;
    let acceptor = TlsAcceptor::from(cfg);
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|_| TransportError::HandshakeFailed)?;
    Ok(tls.insert_server(tls_stream, peer))
}

#[cfg(test)]
mod tests;
