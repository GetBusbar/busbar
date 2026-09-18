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
//! the connection's opaque id, because [`busbar_contract_transport::wire::ConnHandle`] only exposes `id()` and
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

use busbar_contract::{Kind, Plugin, TransportMeta};
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::ConnHandle;
use busbar_contract_transport::wire::ListenerHandle;
use busbar_contract_transport::wire::TransportError;
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
/// [`busbar_contract_transport::wire::ConnHandle`] requires; the real state lives in the transport's registry.
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
}

impl Plugin for TcpTransport {
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
