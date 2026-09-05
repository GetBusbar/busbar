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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::transport::facts as tfacts;
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
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Re-exported so a caller building [`rustls::ServerConfig`]/[`rustls::ClientConfig`] values to
/// hand to [`TlsTransport::register_server_config`]/`register_client_config` names one crate for
/// both the transport and the crypto library it is built on.
pub use rustls;

/// How many bytes one read syscall may fill a frame with.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// Any duplex byte stream this transport can run a handshake over: the socket it opened itself, or
/// the one a lower layer handed up. Boxing it is what lets one connection type cover both, so an
/// adopted connection is not a second shape with a second set of methods.
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Io for T {}

type BoxedIo = Box<dyn Io>;
type ServerStream = tokio_rustls::server::TlsStream<BoxedIo>;
type ClientStream = tokio_rustls::client::TlsStream<BoxedIo>;

struct Inner {
    sni: Option<String>,
    alpn: Option<String>,
    peer_cert: Option<CertFacts>,
    /// The composed stack this connection actually stands on, bottom layer first. A connection this
    /// transport opened itself stands on its own socket; an adopted one stands on whatever the
    /// layer below it was already standing on, which is why this is carried rather than assumed.
    chain: Vec<&'static str>,
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
    /// Keyed by the bound address; the value carries the slot the listener was provisioned with,
    /// so `accept` uses the same config `listen` validated rather than a fixed slot of its own.
    listeners: Mutex<HashMap<String, (Arc<TcpListener>, u64)>>,
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

    /// Register the server-side rustls config a [`TransportKeyHandle`]'s slot resolves to.
    ///
    /// The transport-key unit is what calls this, through [`busbar_unit_transport_key::TlsConfigSink`],
    /// at the moment it resolves the material and journals the access. Nothing here reads a secret;
    /// this end of the seam only ever sees an already-built config and a slot number.
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

    fn insert_server(
        &self,
        stream: ServerStream,
        peer: SocketAddr,
        chain: Vec<&'static str>,
    ) -> Conn {
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
            chain,
            read: AsyncMutex::new(InnerRead::Server(read)),
            write: AsyncMutex::new(InnerWrite::Server(write)),
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
                subject: "peer".to_string(),
                issuer: "peer".to_string(),
                fingerprint: format!("{:x?}", ring_fingerprint(c.as_ref())),
            })
        });
        let (read, write) = tokio::io::split(stream);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(Inner {
            sni: None,
            alpn,
            peer_cert,
            chain,
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
impl busbar_unit_transport_key::TlsConfigSink for TlsTransport {
    fn register_server_config(&self, slot: u64, cfg: Arc<rustls::ServerConfig>) {
        TlsTransport::register_server_config(self, slot, cfg);
    }

    fn register_client_config(&self, slot: u64, cfg: Arc<rustls::ClientConfig>) {
        TlsTransport::register_client_config(self, slot, cfg);
    }
}

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
        busbar_contract::TRANSPORT_ABI
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
    const FRAMING: busbar_contract::Framing = busbar_contract::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<busbar_contract::Unit0Trigger> =
        Some(busbar_contract::Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] =
        &[tfacts::SNI, tfacts::ALPN, tfacts::PEER];
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
            let (stream, peer) = listener.accept().await.map_err(|_| TransportError::Closed)?;
            stream.set_nodelay(true).ok();
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
            let tls_stream = acceptor
                .accept(Box::new(stream) as BoxedIo)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer, vec!["tcp", "tls"]))
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
            let connector = TlsConnector::from(cfg);
            let server_name = ServerName::try_from(name)
                .map_err(|_| TransportError::AddressRefused)?
                .to_owned();
            let tls_stream = connector
                .connect(server_name, Box::new(stream) as BoxedIo)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_client(tls_stream, addr, vec!["tcp", "tls"]))
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

    /// A byte stream carries no envelope of its own: the bytes are the body, and a field written
    /// beside them would be bytes the peer never asked for. A transport that named one anyway would
    /// be inventing a framing this wire does not have.
    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::Arena,
    ) -> Result<ArenaBytes<'a>, busbar_contract::Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| busbar_contract::Encode::ArenaExhausted)
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
            let mut chain = from.arrival(&conn).transport_chain;
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
            let tls_stream = TlsAcceptor::from(cfg)
                .accept(stream)
                .await
                .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer, chain))
        })
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract::RawStream> {
        let inner = self.conns.lock().expect("poisoned").remove(&conn.id())?;
        let peer = conn.peer();
        let inner = Arc::try_unwrap(inner).ok()?;
        let stream: BoxedIo = match (inner.read.into_inner(), inner.write.into_inner()) {
            (InnerRead::Server(r), InnerWrite::Server(w)) => Box::new(r.unsplit(w)),
            (InnerRead::Client(r), InnerWrite::Client(w)) => Box::new(r.unsplit(w)),
            // The halves of one connection are always the same side; a mismatch would mean the
            // registry had been torn, and there is no stream to hand up in that case.
            _ => return None,
        };
        Some(busbar_contract::RawStream::new(
            Self::KEY,
            peer,
            Box::new(TokioAsyncReadCompatExt::compat(stream)),
        ))
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        self.conns.lock().expect("poisoned").remove(&conn.id());
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

/// The pinned socket to connect to, and the name to offer as SNI.
///
/// The destination carries both: the address the trust unit pinned, and — separately — the name a
/// deployment says a certificate was issued for. Where a name is declared, that is what is offered,
/// so a certificate issued for a DNS name matches. Where none is declared the address itself stands
/// in, which is only ever right for an IP-addressed upstream, and there is nothing else honest to
/// offer. Nothing is leaked per dial: both halves are already `'static`, which is what the closed
/// address shape bought.
fn split_address(
    address: &busbar_contract::UpstreamAddress,
) -> Result<(&'static str, SocketAddr), TransportError> {
    let authority = address
        .authority()
        .ok_or(TransportError::AddressRefused)?;
    let addr: SocketAddr = authority
        .parse()
        .map_err(|_| TransportError::AddressRefused)?;
    match address.sni() {
        Some(name) => Ok((name, addr)),
        None if addr.is_ipv4() || addr.is_ipv6() => {
            // No name declared: the literal the authority already spells, without its port, is the
            // only name this transport can offer without inventing one.
            let host_part = authority
                .rsplit_once(':')
                .map_or(authority, |(h, _)| h)
                .trim_start_matches('[')
                .trim_end_matches(']');
            Ok((host_part, addr))
        }
        None => Err(TransportError::AddressRefused),
    }
}

#[cfg(test)]
mod tests;
