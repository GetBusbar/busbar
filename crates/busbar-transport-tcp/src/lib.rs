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
//! the connection's opaque id, because [`busbar_contract::transport::wire::ConnHandle`] only exposes `id()` and
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::transport::wire::Conn;
use busbar_contract::transport::wire::ConnHandle;
use busbar_contract::transport::wire::ListenerHandle;
use busbar_contract::transport::wire::TransportError;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;

mod claims;
pub mod hot;
mod meta;
mod transport;

/// How many bytes one read syscall may fill a frame with.
///
/// This is the bound on the per-unit frame buffer the backpressure battery cell exercises: the
/// stream never has more than one outstanding read of this size in flight, because the next read
/// does not start until the previous frame has been consumed by whatever is polling the stream.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// How long a `dial` may spend waiting for the TCP handshake to complete before the connection is
/// given up.
///
/// `TcpStream::connect` carries no bound of its own: a SYN sent to an upstream that never answers it
/// — a black-holed address, a host behind a firewall that drops rather than rejects — leaves the OS
/// retransmitting for minutes before it surfaces an error, and until it does the dial task and the
/// half-open socket it holds are pinned. A completed connect is the whole of what this budget
/// covers; ten seconds is generous for a handshake that is a single round trip when the peer is
/// there at all, and still bounds the wait when it is not. The sibling `tls` crate bounds its own
/// handshake the same way.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// One connection's live state. Never reachable from the opaque [`Conn`] handle directly; only
/// through this transport's own registry, keyed by [`ConnHandle::id`].
/// A connection's read half and the buffer every read on it fills.
///
/// The buffer is allocated once, when the connection is registered, and reused for the life of the
/// connection: a fresh `READ_CHUNK_BYTES` `Vec` per read syscall is an allocation and a zero-fill
/// on the frame path, for every read, for the life of every streaming connection. Keeping it behind
/// the same lock as the read half is what makes the reuse sound — a connection is read by one pump
/// at a time, so there is never a second reader to see a half-filled buffer.
struct ReadSide {
    half: OwnedReadHalf,
    scratch: Vec<u8>,
}

struct Inner {
    peer: SocketAddr,
    local_port: u16,
    read: AsyncMutex<ReadSide>,
    write: AsyncMutex<OwnedWriteHalf>,
    /// Set once the kernel has finalised this connection. A frame stream captured its own clone of
    /// this state before the close, so the registry removal alone would not reach it; this is the
    /// flag that stream checks so it ends at the next poll and the socket halves actually drop.
    closed: AtomicBool,
    /// The wakeup that goes with the flag.
    ///
    /// A pump parked in `read` has no next poll to check the flag at: on a peer that opened the
    /// connection and then said nothing, the read is outstanding until a byte arrives, and no byte
    /// ever does. The flag alone would leave that pump — and the socket it holds the last clone of
    /// — alive for the life of the process. The close notifies this, the read is raced against it,
    /// and the stream ends where it was parked.
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

/// The opaque handle the kernel is actually given. Carries nothing but what
/// [`busbar_contract::transport::wire::ConnHandle`] requires; the real state lives in the transport's registry.
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
    /// Behind an `Arc` because the frame pump `frames` returns is `'static` — it cannot borrow the
    /// transport — yet it must be able to deregister its own connection when a read ends in an
    /// error (the same cleanup `close` does), so it holds its own clone of this map rather than a
    /// reference to `self`.
    conns: Arc<Mutex<HashMap<u64, Arc<Inner>>>>,
    listeners: Mutex<HashMap<String, Arc<TcpListener>>>,
    /// How long a `dial` waits for the TCP handshake before giving the socket up;
    /// [`DIAL_TIMEOUT`] unless a caller — or a battery cell — said otherwise.
    dial_timeout: Duration,
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
            conns: Arc::new(Mutex::new(HashMap::new())),
            listeners: Mutex::new(HashMap::new()),
            dial_timeout: DIAL_TIMEOUT,
        }
    }

    /// Set the budget a `dial` has to complete the TCP handshake in, for a deployment — or a
    /// battery cell — whose tolerance is not the default ten seconds.
    #[must_use]
    pub fn with_dial_timeout(mut self, budget: Duration) -> Self {
        self.dial_timeout = budget;
        self
    }

    fn register(&self, stream: TcpStream, peer: SocketAddr) -> io::Result<Conn> {
        self.register_as(self.next_conn_id(), stream, peer)
    }

    /// A connection identity no connection of this transport holds — for a connection whose handle
    /// is handed out before its socket exists (the HOT door's `connect`, which answers at once).
    fn next_conn_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// [`Self::register`], under an identity [`Self::next_conn_id`] already minted.
    fn register_as(&self, id: u64, stream: TcpStream, peer: SocketAddr) -> io::Result<Conn> {
        stream.set_nodelay(true)?;
        let local_port = stream.local_addr()?.port();
        let (read, write) = stream.into_split();
        let inner = Arc::new(Inner {
            peer,
            local_port,
            read: AsyncMutex::new(ReadSide {
                half: read,
                scratch: vec![0_u8; READ_CHUNK_BYTES],
            }),
            write: AsyncMutex::new(write),
            closed: AtomicBool::new(false),
            closing: tokio::sync::Notify::new(),
        });
        self.conns
            .lock()
            .expect("conn registry poisoned")
            .insert(id, inner);
        Ok(Conn::new(Arc::new(TcpConnHandle {
            id,
            peer: peer.to_string(),
        })))
    }

    /// Bind a listener on `bind` and register it under the address it actually bound, which is
    /// returned. What `listen` does, for either door: the trait's, and the HOT-lane slot's.
    async fn listen_on(&self, bind: &str) -> Result<String, TransportError> {
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
        Ok(addr)
    }

    /// Take the next connection off the listener bound at `addr`. What `accept` does, for either
    /// door.
    async fn accept_on(&self, addr: &str) -> Result<Conn, TransportError> {
        let listener = self
            .listeners
            .lock()
            .expect("listener registry poisoned")
            .get(addr)
            .cloned()
            .ok_or(TransportError::Closed)?;
        let (stream, peer) = listener.accept().await.map_err(|e| Self::map_io_err(&e))?;
        self.register(stream, peer)
            .map_err(|e| Self::map_io_err(&e))
    }

    /// Dial an admitted `authority` (`host:port`). What `dial` does once the destination has been
    /// read down to its authority, for either door.
    async fn dial_authority(&self, authority: &str) -> Result<Conn, TransportError> {
        let (stream, addr) = self.dialing(authority)?.await?;
        self.register(stream, addr)
            .map_err(|e| Self::map_io_err(&e))
    }

    /// The dial of an admitted `authority`, as a future that borrows nothing — what `dial` awaits,
    /// for either door (the HOT door's `connect` holds it and polls it to completion). An authority
    /// that is not a socket address is refused here, before any socket exists. Built inside the
    /// runtime whose clock bounds it.
    fn dialing(
        &self,
        authority: &str,
    ) -> Result<
        impl std::future::Future<Output = Result<(TcpStream, SocketAddr), TransportError>>
            + Send
            + 'static,
        TransportError,
    > {
        let addr: SocketAddr = authority
            .parse()
            .map_err(|_| TransportError::AddressRefused)?;
        // Bounded: a `connect` to an upstream that never answers the SYN would otherwise pin
        // this task and the half-open socket for the OS's own multi-minute retransmit window.
        // A budget that elapses is a `Timeout`, the same fact the io layer reports when it is
        // the one that gives up first — the caller reads one outcome for "the upstream did not
        // answer in time" however that verdict was reached.
        let connect = tokio::time::timeout(self.dial_timeout, TcpStream::connect(addr));
        Ok(async move {
            match connect.await {
                Ok(result) => result
                    .map(|stream| (stream, addr))
                    .map_err(|e| Self::map_io_err(&e)),
                Err(_) => Err(TransportError::Timeout),
            }
        })
    }

    /// Bind a listener the host may bind once per ACCEPTOR on one address — its per-core fan-out,
    /// every acceptor its own listener, the kernel spreading the connections between them — so on
    /// unix it is SO_REUSEPORT, as the host's own per-core data listeners are. Answers the listener
    /// and the address it actually bound. What the HOT door's `listen` does; it answers at once, so it
    /// resolves `bind` without waiting on a resolver, and runs inside the runtime the listener
    /// registers with.
    fn bind_shared(bind: &str) -> Result<(TcpListener, String), TransportError> {
        use std::net::ToSocketAddrs;
        let addr = bind
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .ok_or(TransportError::AddressRefused)?;
        let socket = if addr.is_ipv6() {
            tokio::net::TcpSocket::new_v6()
        } else {
            tokio::net::TcpSocket::new_v4()
        }
        .map_err(|_| TransportError::AddressRefused)?;
        #[cfg(unix)]
        {
            socket
                .set_reuseaddr(true)
                .and_then(|()| socket.set_reuseport(true))
                .map_err(|_| TransportError::AddressRefused)?;
        }
        socket
            .bind(addr)
            .map_err(|_| TransportError::AddressRefused)?;
        // The host's own per-core listeners' backlog, and tokio's default for a plain bind.
        let listener = socket
            .listen(1024)
            .map_err(|_| TransportError::AddressRefused)?;
        let bound = listener
            .local_addr()
            .map_err(|_| TransportError::AddressRefused)?
            .to_string();
        Ok((listener, bound))
    }

    /// POLL the next bytes of connection `id` into `buf`: what the HOT door's `poll_read` does. The
    /// frame pump's rules, poll-shaped: a finalised connection reads as its end; a read error ends
    /// the connection and deregisters it the way `close` does; an unknown one is `Closed`.
    fn poll_read_into(
        &self,
        id: u64,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TransportError>> {
        let Some(inner) = self.inner(id) else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        if inner.closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(0));
        }
        // One reader at a time is the frame pump's own rule; a second poller waits its turn.
        let Ok(mut side) = inner.read.try_lock() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        let mut filled = ReadBuf::new(buf);
        match std::pin::Pin::new(&mut side.half).poll_read(cx, &mut filled) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(filled.filled().len())),
            Poll::Ready(Err(e)) => {
                drop(side);
                // A read error is the connection's end, not just this read's (the frame pump's
                // rule: an RST flood must not leak one registry entry per reset).
                if let Some(removed) = self
                    .conns
                    .lock()
                    .expect("conn registry poisoned")
                    .remove(&id)
                {
                    removed.finalise();
                }
                Poll::Ready(Err(Self::map_io_err(&e)))
            }
        }
    }

    /// POLL some of `bytes` onto connection `id`: what the HOT door's `poll_write` does. A finalised
    /// or unknown connection is `Closed` — the write path's close race, poll-shaped.
    fn poll_write_on(
        &self,
        id: u64,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, TransportError>> {
        self.poll_writer(id, cx, |half, cx| {
            std::pin::Pin::new(half).poll_write(cx, bytes)
        })
    }

    /// POLL connection `id`'s written bytes onto the wire: what the HOT door's `poll_flush` does.
    fn poll_flush_on(&self, id: u64, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.poll_writer(id, cx, |half, cx| std::pin::Pin::new(half).poll_flush(cx))
    }

    fn poll_writer<T>(
        &self,
        id: u64,
        cx: &mut Context<'_>,
        op: impl FnOnce(&mut OwnedWriteHalf, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<Result<T, TransportError>> {
        let Some(inner) = self.inner(id) else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        if inner.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(TransportError::Closed));
        }
        let Ok(mut half) = inner.write.try_lock() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        op(&mut half, cx).map_err(|e| Self::map_io_err(&e))
    }

    /// Put every one of `bytes` on connection `id`. What `write` does, for either door.
    async fn send(&self, id: u64, bytes: &[u8]) -> Result<(), TransportError> {
        let inner = self.inner(id).ok_or(TransportError::Closed)?;
        let mut guard = inner.write.lock().await;
        // Raced against the connection's close: a peer that stops reading fills the send buffer
        // and would block `write_all` until it drains — which, for a peer that never reads, is
        // never. `close` must be able to interrupt that, or the connection it means to shed
        // leaks instead. The happy-path bytes are unchanged: this is the caller's own write when
        // it wins the race.
        let write = async {
            guard
                .write_all(bytes)
                .await
                .map_err(|e| Self::map_io_err(&e))?;
            guard.flush().await.map_err(|e| Self::map_io_err(&e))
        };
        Self::raced_write(&inner, write).await
    }

    fn inner(&self, id: u64) -> Option<Arc<Inner>> {
        self.conns
            .lock()
            .expect("conn registry poisoned")
            .get(&id)
            .cloned()
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
        // Checked BEFORE the removal, under the same lock. Removing first and then discovering a
        // live reader still holds a clone loses the connection either way: the stream cannot be
        // handed up, and the registry entry that would have let the caller go on using it is gone.
        // Answering `None` has to mean "not yours to take", not "taken and dropped".
        let mut registry = self.conns.lock().expect("conn registry poisoned");
        if Arc::strong_count(registry.get(&conn.id())?) != 1 {
            return None;
        }
        let inner = registry.remove(&conn.id())?;
        drop(registry);
        let inner = Arc::try_unwrap(inner).ok()?;
        let read = inner.read.into_inner().half;
        let write = inner.write.into_inner();
        let stream = read.reunite(write).ok()?;
        Some((stream, inner.peer))
    }

    /// The address of the buffer a connection reads through, for the test that pins one buffer per
    /// connection rather than one per read.
    #[cfg(test)]
    pub(crate) async fn scratch_addr(&self, id: u64) -> Option<usize> {
        let inner = self.inner(id)?;
        let guard = inner.read.lock().await;
        Some(guard.scratch.as_ptr() as usize)
    }

    /// Named for what it does rather than where it was first used: every I/O path in this crate —
    /// the dial, the frame reads, the writes and the refusal — maps its errors through it.
    ///
    /// The table is `http`'s, arm for arm. `tls` carries the same arms and one more of its own:
    /// malformed TLS bytes surface as `InvalidData`, which that transport maps to `HandshakeFailed`
    /// because it has a handshake to fail. This one has none, so the kind falls to `Closed` with
    /// every other unclassified error, and the difference is deliberate rather than drift.
    fn map_io_err(e: &io::Error) -> TransportError {
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

    /// Run an in-flight write raced against this connection's close, so a peer that has stopped
    /// reading cannot pin the write — and the fd, scratch, registry entry and both halves behind
    /// it — for the life of the process.
    ///
    /// The write path is the mirror of the read path in [`TcpTransport::frames`]: a `write_all`
    /// into a full send buffer blocks until the peer drains it, and a peer that never reads never
    /// does. Without this, [`TcpTransport::close`] could not interrupt such a write: it drops the
    /// registry's clone and sets the flag, but the write task holds its own clone and stays parked
    /// on the socket forever. Here the write is armed against `closing` exactly as the read is, so
    /// `close`/`finalise` wakes it, it reports [`TransportError::Closed`], and the connection is
    /// actually released.
    ///
    /// The happy path is byte-for-byte the caller's own write future: when it completes first, its
    /// result is returned untouched.
    async fn raced_write<F>(inner: &Inner, write: F) -> Result<(), TransportError>
    where
        F: std::future::Future<Output = Result<(), TransportError>>,
    {
        // Arm the wait BEFORE re-reading the flag, the same ordering the read path relies on: a
        // close that lands between the two is seen as the flag, one that lands after as the
        // notification, and neither leaves this write parked.
        let mut closing = std::pin::pin!(inner.closing.notified());
        closing.as_mut().enable();
        if inner.closed.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }
        let write = std::pin::pin!(write);
        match futures::future::select(write, closing).await {
            futures::future::Either::Left((r, _)) => r,
            // The close won: the write is dropped where it stood and the connection is released.
            futures::future::Either::Right(((), _)) => Err(TransportError::Closed),
        }
    }
}

/// Put a Unit 0 refusal's bytes on the wire and report whether they actually left.
///
/// `write_all` only proves the bytes reached the writer's own buffer. The kernel is told a refusal
/// was delivered, and a refusal is the client-visible answer to an authentication failure, so the
/// flush is the evidence and its failure is reported the same way the ordinary write path reports
/// one rather than being swallowed.
async fn deliver_refusal<W>(w: &mut W, bytes: &[u8]) -> Result<(), TransportError>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    w.write_all(bytes)
        .await
        .map_err(|e| TcpTransport::map_io_err(&e))?;
    w.flush().await.map_err(|e| TcpTransport::map_io_err(&e))
}

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for this wire — its key, the
/// layers it declares, and how it is built. The root names none of them.
pub mod linked {
    use std::sync::Arc;

    use busbar_contract::transport::{Transport, TransportMeta, TransportSettings};

    use crate::TcpTransport;

    /// The row's registry key.
    pub const KEY: &str = <TcpTransport as TransportMeta>::KEY;
    /// The layers this wire declares it can be built over.
    pub const COMPOSES_OVER: &[&str] = <TcpTransport as TransportMeta>::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = <TcpTransport as TransportMeta>::SESSION;

    /// It opens its own socket, so it takes no lower layer and reads no setting.
    #[must_use]
    pub fn build(_: Option<Arc<dyn Transport>>, _: &TransportSettings) -> Arc<dyn Transport> {
        Arc::new(TcpTransport::new())
    }
}

#[cfg(test)]
mod tests;
