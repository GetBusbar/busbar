// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT ADAPTER: a transport admitted over the HOT-tier ABI ([`DynTransport`], either door)
//! as the host's own [`busbar_contract::Transport`] — so the composition root folds a dropped-in wire
//! into the SAME transport axis, through the SAME registration, as a linked one (#2 rule (1): one
//! contract, one loading path; #3 OWNER-LOCKED: transport is swappable, compiled in OR dropped in).
//!
//! # Why it lives here (#83)
//!
//! This crate is "the host-facing machinery for FETCHING, VERIFYING, LOADING and SUPERVISING a
//! plugin" (roster def 15). Presenting a loaded plugin to the host as the trait the host already
//! drives is that machinery, and its precedents are here: [`crate::store_adapter`] presents a loaded
//! store as the three unit-side store seams, and the hook seam presents a loaded hook as the async
//! routing policy. It is not the composition root's (def 1: "decides nothing a library could
//! decide"), and not the contract's (def 13: shapes only — this is runtime machinery).
//!
//! # The bridge, and what it costs
//!
//! The HOT decl's byte slots BLOCK until their operation completes (the transport owns its own I/O
//! driver), and the host's trait is asynchronous. So every slot call a trait method makes runs on the
//! host runtime's blocking pool (`spawn_blocking`) and the method awaits it: a host request thread is
//! never parked on a plugin's socket. The ABI crossing itself is the HOT-lane budget (#30); the
//! handoff to the blocking pool is the price of a blocking slot shape, and
//! `tests::the_adapters_added_latency_per_crossing_is_measured` measures both.
//!
//! One exception: `accept` runs on a thread of its own rather than the blocking pool. A listener
//! with no one connecting parks its `accept` indefinitely, and a runtime waits for its blocking pool
//! to drain when it drops — a parked accept there would hold a graceful stop open forever.
//!
//! # What the ABI does not carry
//!
//! The decl carries `listen` / `accept` / `dial` / `read` / `write` / `close` over opaque handles and
//! nothing else, so this adapter answers the trait's remaining methods as a byte stream answers them:
//! the envelope of an outbound message is its body, an adoption from another layer is a
//! [`TransportError::HandoffMismatch`], and a key handle is not presented (a transport that needs
//! configuration is handed the kernel-built [`busbar_plugin::hot::transport::WireConfig`], which no
//! caller of this adapter mints yet).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::transport::wire::{
    ArrivalRecord, CloseReason, Conn, ConnHandle, Direction, Encode, FrameMeta, Listener,
    ListenerHandle, RawStream, TransportError,
};
use busbar_contract::transport::{Transport, TransportSettings, TRANSPORT_ABI};
use busbar_contract::{
    DestinationFacts, Frame, Fut, Kind, PlaneAlloc, Plugin, Refusal, ScratchBytes, SlabBytes,
    StreamId, TransportConfigView, TransportKeyHandle, VerifiedDestination,
};
use busbar_plugin::hot::transport::WireOutcome;
use tokio::task::JoinHandle;

use crate::transport::{wire_settings, BuiltTransport, DynTransport};

/// How many bytes one `read` slot call may fill: the buffer every read on a connection reuses.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// A HOT-lane transport, built, presented as the host's [`Transport`].
pub struct WireTransport {
    hosted: Arc<Hosted>,
}

/// The built wire and what the adapter keeps beside it. Shared with the blocking calls in flight.
struct Hosted {
    built: BuiltTransport<'static>,
    key: &'static str,
    /// The layer this wire was built over, where it was built over one: its key, and the layer
    /// itself, kept alive for as long as the built state that points into it.
    lower: Option<(&'static str, Arc<Hosted>)>,
    /// The stack as an arrival reports it, bottom layer first.
    chain: Vec<&'static str>,
    /// The wire's listener handle for each address it bound.
    listeners: Mutex<HashMap<String, u64>>,
    /// The peer of every live connection this adapter handed out and has not closed or detached.
    conns: Mutex<HashMap<u64, String>>,
}

impl std::fmt::Debug for WireTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireTransport")
            .field("key", &self.hosted.key)
            .field(
                "composed_over",
                &self.hosted.lower.as_ref().map(|(k, _)| *k),
            )
            .finish_non_exhaustive()
    }
}

/// A slot's refusal in the transport kind's own vocabulary: `1..=10` are that vocabulary in order;
/// an operation the wire does not implement, or a fault it answered, closes the operation.
fn refusal(outcome: WireOutcome) -> TransportError {
    match outcome {
        WireOutcome::Refused => TransportError::Refused,
        WireOutcome::Timeout => TransportError::Timeout,
        WireOutcome::Reset => TransportError::Reset,
        WireOutcome::HandshakeFailed => TransportError::HandshakeFailed,
        WireOutcome::KeyUnavailable => TransportError::KeyUnavailable,
        WireOutcome::AddressRefused => TransportError::AddressRefused,
        WireOutcome::Backpressure => TransportError::Backpressure,
        WireOutcome::Framing => TransportError::Framing,
        WireOutcome::HandoffMismatch => TransportError::HandoffMismatch,
        WireOutcome::Ok | WireOutcome::Closed | WireOutcome::Unsupported | WireOutcome::Fault => {
            TransportError::Closed
        }
    }
}

/// Run one slot call on the blocking pool and await it (module docs, "The bridge").
async fn off<T: Send + 'static>(
    hosted: &Arc<Hosted>,
    call: impl FnOnce(&BuiltTransport<'static>) -> Result<T, WireOutcome> + Send + 'static,
) -> Result<T, TransportError> {
    let hosted = Arc::clone(hosted);
    tokio::task::spawn_blocking(move || call(&hosted.built))
        .await
        .map_err(|_| TransportError::Closed)?
        .map_err(refusal)
}

impl WireTransport {
    /// BUILD `wire` over `lower` (the adapter built beneath it, where the root composed it over a
    /// HOT-lane layer) from the deployment's `settings` — the linked row's `build(lower, settings)`,
    /// over the ABI.
    ///
    /// # Errors
    ///
    /// The wire's `build` slot refused, or is absent.
    pub fn build(
        wire: &'static DynTransport,
        lower: Option<&WireTransport>,
        settings: &TransportSettings,
    ) -> Result<Self, WireOutcome> {
        let built = wire.build(lower.map(|l| &l.hosted.built), &wire_settings(settings))?;
        let lower = lower.map(|l| (l.hosted.key, Arc::clone(&l.hosted)));
        let mut chain = lower
            .as_ref()
            .map_or_else(Vec::new, |(_, l)| l.chain.clone());
        chain.push(wire.key());
        Ok(Self {
            hosted: Arc::new(Hosted {
                built,
                key: wire.key(),
                lower,
                chain,
                listeners: Mutex::new(HashMap::new()),
                conns: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The admitted transport this adapter drives.
    #[must_use]
    pub fn wire(&self) -> &'static DynTransport {
        self.hosted.built.transport()
    }
}

impl Hosted {
    /// Hand out a connection the wire minted, remembering its peer.
    fn conn(&self, id: u64, peer: String) -> Conn {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, peer.clone());
        Conn::new(Arc::new(WireConn { id, peer }))
    }

    /// Forget a connection; `true` if it was live here.
    fn forget(&self, id: u64) -> bool {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id)
            .is_some()
    }

    fn live(&self, id: u64) -> bool {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&id)
    }
}

/// The opaque connection the host is handed: the wire's own handle and the peer it reported.
struct WireConn {
    id: u64,
    peer: String,
}

impl ConnHandle for WireConn {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// The opaque listener the host is handed: the address the wire bound.
struct WireListener {
    addr: String,
}

impl ListenerHandle for WireListener {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

impl Plugin for WireTransport {
    fn key(&self) -> &'static str {
        self.hosted.key
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        TRANSPORT_ABI
    }
}

impl Transport for WireTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            // The decl reports no local port for a connection.
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: self.hosted.chain.clone(),
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        // The wire answers an absent bind itself: the adapter decides no address.
        let bind = cfg.bind().unwrap_or_default().to_string();
        Box::pin(async move {
            let (id, addr) = off(&self.hosted, move |b| b.listen(&bind, None)).await?;
            self.hosted
                .listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(addr.clone(), id);
            Ok(Listener::new(Arc::new(WireListener { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let listener = self
                .hosted
                .listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&l.local_addr())
                .copied()
                .ok_or(TransportError::Closed)?;
            // A thread of its own, not the blocking pool (module docs).
            let (tx, rx) = tokio::sync::oneshot::channel();
            let hosted = Arc::clone(&self.hosted);
            std::thread::Builder::new()
                .name("busbar-wire-accept".into())
                .spawn(move || {
                    // Nobody is waiting any more (the accept was dropped): the connection it took
                    // is closed rather than left open in the wire with no owner.
                    if let Err(Ok((id, _))) = tx.send(hosted.built.accept(listener)) {
                        let _ = hosted.built.close(id);
                    }
                })
                .map_err(|_| TransportError::Closed)?;
            let (id, peer) = rx
                .await
                .map_err(|_| TransportError::Closed)?
                .map_err(refusal)?;
            Ok(self.hosted.conn(id, peer))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let authority = match dest.facts() {
                DestinationFacts::Upstream { address, .. } => address
                    .authority()
                    .ok_or(TransportError::AddressRefused)?
                    .to_string(),
                _ => return Err(TransportError::AddressRefused),
            };
            let peer = authority.clone();
            let id = off(&self.hosted, move |b| b.dial(&authority, None)).await?;
            Ok(self.hosted.conn(id, peer))
        })
    }

    fn frames(&self, conn: Conn) -> busbar_contract::transport::FrameStream {
        let state = (Arc::clone(&self.hosted), conn.id(), false);
        Box::pin(futures::stream::unfold(
            state,
            |(hosted, id, ended)| async move {
                if ended || !hosted.live(id) {
                    return None;
                }
                let read = off(&hosted, move |b| {
                    let mut buf = vec![0_u8; READ_CHUNK_BYTES];
                    b.read(id, &mut buf).map(|n| {
                        buf.truncate(n);
                        buf
                    })
                })
                .await;
                match read {
                    Ok(bytes) if bytes.is_empty() => None,
                    Ok(bytes) => {
                        let n = bytes.len() as u64;
                        let frame = Frame {
                            direction: Direction::Inbound,
                            stream: StreamId(0),
                            bytes: SlabBytes::new(Arc::<[u8]>::from(bytes)),
                            meta: FrameMeta {
                                bytes: n,
                                transport_units: None,
                                status: None,
                                status_code: None,
                                retry_after_secs: None,
                            },
                        };
                        Some((Ok((StreamId(0), frame)), (hosted, id, false)))
                    }
                    Err(e) => Some((Err(e), (hosted, id, true))),
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
        // Copied out of the arena, which is reset as soon as the write is queued (the trait's own
        // rule), onto the blocking call that puts it on the wire.
        let owned = bytes.as_slice().to_vec();
        let (id, len) = (conn.id(), owned.len());
        Box::pin(async move {
            if !self.hosted.live(id) {
                return Err(TransportError::Closed);
            }
            off(&self.hosted, move |b| b.write(id, &owned)).await?;
            Ok(len)
        })
    }

    /// The decl moves bytes and nothing else, so an outbound message's bytes are its body.
    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| Encode::ScratchExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // The decl has no adoption slot: a stream from another layer cannot cross it.
        Box::pin(async { Err(TransportError::HandoffMismatch) })
    }

    /// The connection's bytes as a stream of their own, driven through the same slots: this adapter
    /// forgets the connection, and the stream closes it when it is dropped.
    fn detach(&self, conn: &Conn) -> Option<RawStream> {
        if !self.hosted.forget(conn.id()) {
            return None;
        }
        Some(RawStream::new(
            self.hosted.key,
            conn.peer(),
            Box::new(WireIo::new(Arc::clone(&self.hosted), conn.id())),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.hosted.lower.as_ref().map(|(key, _)| *key)
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        if self.hosted.forget(conn.id()) {
            let _ = self.hosted.built.close(conn.id());
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        let owned = bytes.as_slice().to_vec();
        Box::pin(async move {
            let id = conn.id();
            if !self.hosted.forget(id) {
                return Err(TransportError::Closed);
            }
            // A refusal finalises the connection on every path out, delivered or not.
            off(&self.hosted, move |b| {
                let delivered = b.write(id, &owned);
                let _ = b.close(id);
                delivered
            })
            .await
        })
    }
}

/// A read slot's answer handed back from the blocking pool: its buffer and what it read.
type ReadDone = (Vec<u8>, Result<usize, WireOutcome>);

/// A detached connection's bytes: `read` and `write` on the blocking pool, `close` when dropped.
struct WireIo {
    hosted: Arc<Hosted>,
    id: u64,
    /// The read in flight, handing back its buffer and what it read.
    reading: Option<JoinHandle<ReadDone>>,
    /// The last read's bytes not yet handed out: `buf[at..len]`.
    buf: Vec<u8>,
    at: usize,
    len: usize,
    eof: bool,
    /// The write in flight; its error surfaces at the next write or flush.
    writing: Option<JoinHandle<Result<(), WireOutcome>>>,
    closed: bool,
}

impl WireIo {
    fn new(hosted: Arc<Hosted>, id: u64) -> Self {
        Self {
            hosted,
            id,
            reading: None,
            buf: vec![0_u8; READ_CHUNK_BYTES],
            at: 0,
            len: 0,
            eof: false,
            writing: None,
            closed: false,
        }
    }

    /// Settle the write in flight, if any.
    fn poll_written(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(writing) = self.writing.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let done = std::task::ready!(Pin::new(writing).poll(cx));
        self.writing = None;
        Poll::Ready(match done {
            Ok(Ok(())) => Ok(()),
            Ok(Err(outcome)) => Err(wire_io_error(outcome)),
            Err(_) => Err(io::ErrorKind::BrokenPipe.into()),
        })
    }
}

/// A slot's refusal as the I/O error a byte stream reports.
fn wire_io_error(outcome: WireOutcome) -> io::Error {
    let kind = match refusal(outcome) {
        TransportError::Refused => io::ErrorKind::ConnectionRefused,
        TransportError::Timeout => io::ErrorKind::TimedOut,
        TransportError::Reset => io::ErrorKind::ConnectionReset,
        _ => io::ErrorKind::BrokenPipe,
    };
    io::Error::new(kind, format!("transport slot answered {outcome:?}"))
}

impl futures::io::AsyncRead for WireIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            if this.at < this.len {
                let n = out.len().min(this.len - this.at);
                out[..n].copy_from_slice(&this.buf[this.at..this.at + n]);
                this.at += n;
                return Poll::Ready(Ok(n));
            }
            if this.eof || this.closed {
                return Poll::Ready(Ok(0));
            }
            let reading = match this.reading.as_mut() {
                Some(reading) => reading,
                None => {
                    let (hosted, id) = (Arc::clone(&this.hosted), this.id);
                    let mut buf = std::mem::take(&mut this.buf);
                    this.reading.insert(tokio::task::spawn_blocking(move || {
                        let read = hosted.built.read(id, &mut buf);
                        (buf, read)
                    }))
                }
            };
            let done = std::task::ready!(Pin::new(reading).poll(cx));
            this.reading = None;
            let (buf, read) = done.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            this.buf = buf;
            match read {
                Ok(0) => this.eof = true,
                Ok(n) => (this.at, this.len) = (0, n),
                Err(outcome) => return Poll::Ready(Err(wire_io_error(outcome))),
            }
        }
    }
}

impl futures::io::AsyncWrite for WireIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_written(cx))?;
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let (hosted, id, owned) = (Arc::clone(&self.hosted), self.id, bytes.to_vec());
        self.writing = Some(tokio::task::spawn_blocking(move || {
            hosted.built.write(id, &owned)
        }));
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_written(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_written(cx))?;
        if !std::mem::replace(&mut self.closed, true) {
            let _ = self.hosted.built.close(self.id);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for WireIo {
    fn drop(&mut self) {
        // Closing ends a read parked on the connection, so nothing is left on the blocking pool.
        if !self.closed {
            let _ = self.hosted.built.close(self.id);
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_adapter_tests.rs"]
mod tests;
