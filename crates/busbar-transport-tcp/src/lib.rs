// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.
//!
//! This is the base every session transport in the design composes over (`tls` frames over it,
//! `http` dials through `tls`, `sse` composes over `http`). It cannot name a plane and cannot
//! name a unit: it yields and writes frames, and it knows no protocol and no principal. Its own
//! `KEY` is `"tcp"`, it carries no per-frame status leg (`STATUS_CLASS = None`), and it is a
//! session transport whose Unit 0 opens on the first bytes off the wire.
//!
//! ## Composition seam
//!
//! A connection this transport accepted or dialled is tracked in an internal registry keyed by
//! the connection's opaque id, because [`busbar_contract::ConnHandle`] only exposes `id()` and
//! `peer()` to the kernel — the concrete socket lives here, never behind the trait object. This is
//! also what makes an in-band upgrade possible: [`TcpTransport::take_stream`] hands the raw
//! `TcpStream` to whichever upper layer is upgrading the connection (the `tls` transport calls it
//! when a plane triggers `UNIT0_TRIGGER: Upgrade`-shaped STARTTLS handoff), removing it from this
//! registry so it is never read from or written to twice.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::{
    ArenaBytes, ArrivalRecord, CloseReason, Conn, ConnHandle, Direction, Fut, Frame, FrameMeta,
    Kind, Listener, ListenerHandle, Plugin, Refusal, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportError, TransportMeta,
};
use futures::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;

/// How many bytes one read syscall may fill a frame with.
///
/// This is the bound on the per-unit frame buffer the backpressure battery cell exercises: the
/// stream never has more than one outstanding read of this size in flight, because the next read
/// does not start until the previous frame has been consumed by whatever is polling the stream.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// One connection's live state. Never reachable from the opaque [`Conn`] handle directly; only
/// through this transport's own registry, keyed by [`ConnHandle::id`].
struct Inner {
    peer: SocketAddr,
    local_port: u16,
    read: AsyncMutex<OwnedReadHalf>,
    write: AsyncMutex<OwnedWriteHalf>,
}

/// The opaque handle the kernel is actually given. Carries nothing but what
/// [`busbar_contract::ConnHandle`] requires; the real state lives in the transport's registry.
struct TcpConnHandle {
    id: u64,
    peer: String,
}

impl ConnHandle for TcpConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// The opaque listener handle. Listeners are looked up by their bound local address, which is
/// exactly what [`ListenerHandle::local_addr`] exposes.
struct TcpListenerHandle {
    addr: String,
}

impl ListenerHandle for TcpListenerHandle {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

/// The `tcp` transport.
pub struct TcpTransport {
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<Inner>>>,
    listeners: Mutex<HashMap<String, Arc<TcpListener>>>,
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport").finish_non_exhaustive()
    }
}

impl TcpTransport {
    /// A transport with an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
        }
    }

    fn register(&self, stream: TcpStream, peer: SocketAddr) -> io::Result<Conn> {
        stream.set_nodelay(true)?;
        let local_port = stream.local_addr()?.port();
        let (read, write) = stream.into_split();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(Inner {
            peer,
            local_port,
            read: AsyncMutex::new(read),
            write: AsyncMutex::new(write),
        });
        self.conns.lock().expect("conn registry poisoned").insert(id, inner);
        Ok(Conn::new(Arc::new(TcpConnHandle {
            id,
            peer: peer.to_string(),
        })))
    }

    fn inner(&self, id: u64) -> Option<Arc<Inner>> {
        self.conns.lock().expect("conn registry poisoned").get(&id).cloned()
    }

    /// Detach the underlying stream from a connection this transport produced, for an upper layer
    /// composing over `tcp` (the in-band upgrade case: STARTTLS-shaped handoffs). Removes the
    /// connection from this transport's own registry, so it is never read from or written to here
    /// again once detached.
    ///
    /// Returns `None` when the connection is unknown, or when a concurrent frame reader still
    /// holds a clone of its state (an upgrade never races an in-flight read, by the design's own
    /// "at most one upgrade in flight" rule; a caller that violates that ordering sees `None`
    /// rather than a torn stream).
    pub fn take_stream(&self, conn: &Conn) -> Option<(TcpStream, SocketAddr)> {
        let inner = self
            .conns
            .lock()
            .expect("conn registry poisoned")
            .remove(&conn.id())?;
        let inner = Arc::try_unwrap(inner).ok()?;
        let read = inner.read.into_inner();
        let write = inner.write.into_inner();
        let stream = read.reunite(write).ok()?;
        Some((stream, inner.peer))
    }

    fn map_connect_err(e: &io::Error) -> TransportError {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => TransportError::Refused,
            io::ErrorKind::TimedOut => TransportError::Timeout,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                TransportError::Reset
            }
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::InvalidInput => {
                TransportError::AddressRefused
            }
            _ => TransportError::Closed,
        }
    }
}

impl Plugin for TcpTransport {
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

impl TransportMeta for TcpTransport {
    const KEY: &'static str = "tcp";
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] =
        &[busbar_contract::SelectorForm::Port];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &[];
    const HANDOFF: Option<busbar_contract::Handoff> = None;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract::Unit0Trigger> =
        Some(busbar_contract::Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &["tls"];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract::StatusAt> = None;
}

impl Transport for TcpTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let port = self.inner(conn.id()).map_or(0, |i| i.local_port);
        ArrivalRecord {
            source: conn.peer(),
            port,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["tcp"],
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
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
                .expect("listener registry poisoned")
                .insert(addr.clone(), Arc::new(listener));
            Ok(Listener::new(Arc::new(TcpListenerHandle { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let addr = l.local_addr();
            let listener = self
                .listeners
                .lock()
                .expect("listener registry poisoned")
                .get(&addr)
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (stream, peer) = listener.accept().await.map_err(|_| TransportError::Closed)?;
            self.register(stream, peer)
                .map_err(|e| Self::map_connect_err(&e))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let host = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { host, .. } => host,
                _ => return Err(TransportError::AddressRefused),
            };
            let addr: SocketAddr = host.parse().map_err(|_| TransportError::AddressRefused)?;
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|e| Self::map_connect_err(&e))?;
            self.register(stream, addr)
                .map_err(|e| Self::map_connect_err(&e))
        })
    }

    fn frames(&self, conn: Conn) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        Box::pin(futures::stream::unfold(inner, move |inner| async move {
            let inner = inner?;
            let mut buf = vec![0_u8; READ_CHUNK_BYTES];
            let mut guard = inner.read.lock().await;
            match guard.read(&mut buf).await {
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
                    Some((Err(TcpTransport::map_connect_err(&e)), None))
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
            guard
                .write_all(bytes.as_slice())
                .await
                .map_err(|e| Self::map_connect_err(&e))?;
            guard.flush().await.map_err(|e| Self::map_connect_err(&e))?;
            Ok(bytes.len())
        })
    }

    fn upgrade<'a>(
        &'a self,
        conn: Conn,
        _to: &'a str,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // `tcp` has no in-band upgrade of its own frame shape; an upper layer (`tls`) upgrades by
        // calling `take_stream` on this transport directly rather than through the trait, because
        // the resulting connection belongs to a different transport's registry.
        let _ = conn;
        Box::pin(async move { Err(TransportError::Framing) })
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        // Dropping the halves closes the socket (sends FIN); nothing here is fallible in a way
        // the caller can act on, so this stays synchronous per the trait's own shape.
        self.conns.lock().expect("conn registry poisoned").remove(&conn.id());
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
                guard
                    .write_all(bytes.as_slice())
                    .await
                    .map_err(|e| Self::map_connect_err(&e))?;
                let _ = guard.flush().await;
            }
            self.conns.lock().expect("conn registry poisoned").remove(&conn.id());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
