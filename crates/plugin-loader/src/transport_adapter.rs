// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STACK: a carrier, the connection security a binding asks for, and a framer, presented as the
//! host's own [`busbar_contract::Transport`] — the connection the kernel drives (TRANSPORT-STACK,
//! owner-approved 2026-09-27; #2 rule (1): one contract, one loading path; #3: a transport is
//! swappable, compiled in OR dropped in).
//!
//! Core builds every connection as `carrier -> [connection security] -> framer`. A carrier opens the
//! connection and moves its bytes; a framer (sans-IO) turns the bytes into frames and frames into
//! bytes; neither names the other, and neither knows which door the other came in by — each is the
//! contract's trait object ([`Carrier`], [`Framer`]), a linked implementation or the loader's
//! decl-backed one ([`crate::transport::DeclCarrier`], [`crate::transport::DeclFramer`]). A stack with
//! no framer is the degenerate case: every read is one frame, with no metadata.
//!
//! # Why it lives here (#83)
//!
//! Presenting loaded plugins to the host as the trait the host already drives is loading machinery
//! (roster def 15; its precedents are [`crate::store_adapter`] and the hook seam). It is not the
//! composition root's (def 1: "decides nothing a library could decide"), and not the contract's
//! (def 13: shapes only).
//!
//! # The bytes of one connection
//!
//! A connection's byte stream is one [`RawIo`]: the carrier's connection lowered to
//! `AsyncRead`/`AsyncWrite` ([`CarrierIo`]), wrapped by connection security where the binding asks
//! for it, or the stream another stack gave up on an upgrade. It is split so the frame pump and the
//! writers run at once. Every carrier crossing is a poll driven INLINE from the host's reactor on the
//! task that awaits it — no thread handoff (#30). The added latency per crossing is measured by
//! `tests::the_adapters_added_latency_per_crossing_is_measured` against the HOT-lane budget.
//!
//! # The upgrade moves the byte stream
//!
//! [`Transport::detach`] gives up a connection's stream with whatever its framer held unconsumed in
//! front of it; [`Transport::adopt`] takes a stream another stack gave up and opens this stack's
//! framer over it. The stream moves; no transport hands another anything.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::hot::transport::WireOutcome;
use busbar_contract::transport::wire::{
    ArrivalRecord, CloseReason, Conn, ConnHandle, ConnectionSecurity, Direction, Encode, FrameMeta,
    Listener, ListenerHandle, RawIo, RawStream, TransportError, WireStatus,
};
use busbar_contract::transport::{
    BytesOut, Carrier, ConnFacts, Dest, Framed, Framer, FramerOut, Side, Transport, TransportRow,
    TransportSettings, UpstreamAddress, TRANSPORT_ABI,
};
use busbar_contract::{
    DestinationFacts, Frame, Fut, Kind, PlaneAlloc, Plugin, Refusal, ScratchBytes, SlabBytes,
    StreamId, TransportConfigView, TransportKeyHandle, VerifiedDestination,
};
use futures::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use futures::lock::Mutex as AsyncMutex;

use crate::transport::{wire_settings, Built, DynTransport};

/// How many bytes one read of a connection's stream may take for the frame pump.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// How long a framer's close is given to reach the far side before the connection goes anyway.
const CLOSE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

// ── the carrier's connection as a byte stream ───────────────────────────────────────────────────

/// A carrier's connection as a byte stream: every poll is the carrier's own method, inline; the
/// connection closes when the stream is closed or dropped.
pub struct CarrierIo {
    carrier: Arc<dyn Carrier>,
    conn: u64,
    closed: bool,
}

impl CarrierIo {
    /// The byte stream of `carrier`'s connection `conn`, which it now owns.
    #[must_use]
    pub fn new(carrier: Arc<dyn Carrier>, conn: u64) -> Self {
        Self {
            carrier,
            conn,
            closed: false,
        }
    }
}

/// A carrier's refusal as the I/O error a byte stream reports.
fn io_error(e: TransportError) -> io::Error {
    let kind = match e {
        TransportError::Refused => io::ErrorKind::ConnectionRefused,
        TransportError::Timeout => io::ErrorKind::TimedOut,
        TransportError::Reset => io::ErrorKind::ConnectionReset,
        _ => io::ErrorKind::BrokenPipe,
    };
    io::Error::new(kind, format!("carrier answered {e:?}"))
}

/// A byte stream's I/O error as the transport failure it reports.
fn transport_error(e: &io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => TransportError::Refused,
        io::ErrorKind::TimedOut => TransportError::Timeout,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => TransportError::Reset,
        _ => TransportError::Closed,
    }
}

impl futures::io::AsyncRead for CarrierIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.carrier.poll_read(self.conn, cx, out).map_err(io_error)
    }
}

impl futures::io::AsyncWrite for CarrierIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.carrier
            .poll_write(self.conn, cx, bytes)
            .map_err(io_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        self.carrier.poll_flush(self.conn, cx).map_err(io_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        std::task::ready!(self.carrier.poll_close(self.conn, cx, CloseReason::Normal))
            .map_err(io_error)?;
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for CarrierIo {
    fn drop(&mut self) {
        // Closing wakes a read parked on the connection, and nothing waits on it any more.
        if !self.closed {
            let _ = self.carrier.poll_close(
                self.conn,
                &mut Context::from_waker(std::task::Waker::noop()),
                CloseReason::Normal,
            );
        }
    }
}

/// A stream that answers `leftover` before the stream under it: what a framer held unconsumed when
/// its connection moved on.
struct Prefixed {
    leftover: Vec<u8>,
    at: usize,
    io: Box<dyn RawIo>,
}

impl futures::io::AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.at < self.leftover.len() {
            let n = out.len().min(self.leftover.len() - self.at);
            let at = self.at;
            out[..n].copy_from_slice(&self.leftover[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(n));
        }
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}

impl futures::io::AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_close(cx)
    }
}

// ── what a framer produced ──────────────────────────────────────────────────────────────────────

/// A framer call's outputs, collected: the bytes owed to the far side, the frames it completed (a
/// stream's pieces assembled until the piece that ends the frame), and whether the connection's
/// frames ended.
struct Produced<'a> {
    namespace: Option<&'static str>,
    partial: &'a mut HashMap<u64, (Vec<u8>, FrameMeta)>,
    sent: Vec<u8>,
    frames: VecDeque<(StreamId, Frame)>,
    ended: bool,
}

impl<'a> Produced<'a> {
    fn new(
        namespace: Option<&'static str>,
        partial: &'a mut HashMap<u64, (Vec<u8>, FrameMeta)>,
    ) -> Self {
        Self {
            namespace,
            partial,
            sent: Vec::new(),
            frames: VecDeque::new(),
            ended: false,
        }
    }
}

/// A frame's metadata before any piece has said what it carries.
fn blank_meta() -> FrameMeta {
    FrameMeta {
        bytes: 0,
        transport_units: None,
        status: None,
        status_code: None,
        retry_after_secs: None,
        text: false,
    }
}

impl FramerOut for Produced<'_> {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }

    fn frame(&mut self, piece: Framed<'_>) {
        let (bytes, meta) = self
            .partial
            .entry(piece.stream.0)
            .or_insert_with(|| (Vec::new(), blank_meta()));
        bytes.extend_from_slice(piece.bytes);
        // The first piece that states a status is the frame's; the numbering is the one the framer
        // DECLARES, so a frame cannot report in a numbering its transport did not say it reports in.
        if meta.status.is_none() {
            meta.status = piece.status;
        }
        if meta.status_code.is_none() {
            meta.status_code = piece
                .status_code
                .zip(self.namespace)
                .map(|(code, ns)| WireStatus::new(ns, code));
        }
        if meta.retry_after_secs.is_none() {
            meta.retry_after_secs = piece.retry_after_secs;
        }
        meta.text |= piece.text;
        if piece.end_of_frame {
            let (bytes, mut meta) = self
                .partial
                .remove(&piece.stream.0)
                .unwrap_or_else(|| (Vec::new(), blank_meta()));
            meta.bytes = bytes.len() as u64;
            self.frames.push_back((
                piece.stream,
                Frame {
                    direction: Direction::Inbound,
                    stream: piece.stream,
                    bytes: SlabBytes::new(Arc::<[u8]>::from(bytes)),
                    meta,
                },
            ));
        }
    }

    fn end(&mut self) {
        self.ended = true;
    }

    fn now(&self) -> busbar_contract::transport::HostTime {
        crate::transport::host_time()
    }

    // This stack keeps no framer deadline: none of the framers it stacks states one. The
    // connector's stack calls `tick` at the stated instant.
    fn wake_at(&mut self, _monotonic_nanos: Option<u64>) {}
}

// ── the stack ───────────────────────────────────────────────────────────────────────────────────

/// A carrier, the connection security its accepted connections are wrapped in, and a framer,
/// presented as the host's [`Transport`] (module docs).
pub struct WireTransport {
    stack: Arc<Stack>,
}

struct Stack {
    /// The top layer's row: the framer's, or the carrier's when there is no framer.
    row: TransportRow,
    /// The carrier and its key.
    carrier: Option<(&'static str, Arc<dyn Carrier>)>,
    framer: Option<Arc<dyn Framer>>,
    /// The security accepted connections are wrapped in before the framer sees a byte.
    security: Option<Arc<dyn ConnectionSecurity>>,
    /// Each listener handed out (by its node-local identity): the carrier's listener handle.
    listeners: Mutex<HashMap<u64, u64>>,
    /// Every live connection handed out and not closed or detached.
    conns: Mutex<HashMap<u64, Arc<StackConn>>>,
    next: AtomicU64,
}

/// One connection: its stream (split), the framer's state over it, and what its arrival says.
struct StackConn {
    arrival: ArrivalRecord,
    /// The carrier connection under the stream, where this stack's own carrier opened it (an adopted
    /// stream has none): closing it is how a close reaches a read parked on it.
    carried: Option<(Arc<dyn Carrier>, u64)>,
    framing: Option<u64>,
    read: AsyncMutex<Option<ReadSide>>,
    write: AsyncMutex<Option<WriteHalf<Box<dyn RawIo>>>>,
    closed: AtomicBool,
}

/// The reading half, the frames completed and not yet handed up, and each stream's unfinished frame.
struct ReadSide {
    half: ReadHalf<Box<dyn RawIo>>,
    ready: VecDeque<(StreamId, Frame)>,
    partial: HashMap<u64, (Vec<u8>, FrameMeta)>,
    ended: bool,
    buf: Vec<u8>,
}

impl std::fmt::Debug for WireTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireTransport")
            .field("key", &self.stack.row.key)
            .field("carrier", &self.stack.carrier.as_ref().map(|(k, _)| *k))
            .finish_non_exhaustive()
    }
}

impl WireTransport {
    /// BUILD `wire` from the deployment's `settings` — over `lower`'s carrier, where `wire` is a
    /// framer the root composed over a dropped-in carrier — as the host's [`Transport`].
    ///
    /// # Errors
    ///
    /// The wire's `init` refused.
    pub fn build(
        wire: &'static DynTransport,
        lower: Option<&WireTransport>,
        settings: &TransportSettings,
    ) -> Result<Self, WireOutcome> {
        Ok(match wire.build(&wire_settings(settings))? {
            Built::Carrier(carrier) => Self::stack(*wire.row(), Some(carrier), None, None),
            Built::Framer(framer) => Self::stack(
                *wire.row(),
                lower.and_then(|l| l.stack.carrier.as_ref().map(|(_, c)| Arc::clone(c))),
                Some(framer),
                None,
            ),
        })
    }

    /// The stack of `carrier`, `security` and `framer`, presenting `row` (the framer's row, or the
    /// carrier's when there is no framer).
    #[must_use]
    pub fn stack(
        row: TransportRow,
        carrier: Option<Arc<dyn Carrier>>,
        framer: Option<Arc<dyn Framer>>,
        security: Option<Arc<dyn ConnectionSecurity>>,
    ) -> Self {
        Self {
            stack: Arc::new(Stack {
                row,
                carrier: carrier.map(|c| (c.key(), c)),
                framer,
                security,
                listeners: Mutex::new(HashMap::new()),
                conns: Mutex::new(HashMap::new()),
                next: AtomicU64::new(1),
            }),
        }
    }

    /// The row this stack presents.
    #[must_use]
    pub fn row(&self) -> &TransportRow {
        &self.stack.row
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The opaque connection the host is handed.
struct StackConnHandle {
    id: u64,
    peer: String,
}

impl ConnHandle for StackConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// The opaque listener the host is handed: the address the carrier bound.
struct StackListener {
    addr: String,
}

impl ListenerHandle for StackListener {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

impl Stack {
    fn carrier(&self) -> Result<&Arc<dyn Carrier>, TransportError> {
        self.carrier
            .as_ref()
            .map(|(_, c)| c)
            .ok_or(TransportError::HandoffMismatch)
    }

    /// The layers a connection stands on, bottom first.
    fn chain(&self) -> Vec<&'static str> {
        let mut chain: Vec<&'static str> = self.carrier.iter().map(|(k, _)| *k).collect();
        if self.framer.is_some() {
            chain.push(self.row.key);
        }
        chain
    }

    fn get(&self, id: u64) -> Option<Arc<StackConn>> {
        lock(&self.conns).get(&id).cloned()
    }

    fn forget(&self, id: u64) -> Option<Arc<StackConn>> {
        lock(&self.conns).remove(&id)
    }

    /// Hand out a connection over `io`: open this stack's framer over it (as `side`, sending what the
    /// framer opens with), or — with `leftover` — adopt the stream another framer gave up.
    async fn hand_out(
        &self,
        io: Box<dyn RawIo>,
        carried: Option<(Arc<dyn Carrier>, u64)>,
        arrival: ArrivalRecord,
        side: Side,
        target: &str,
        adopt: bool,
    ) -> Result<Conn, TransportError> {
        let (read, mut write) = io.split();
        let mut partial = HashMap::new();
        let mut produced = Produced::new(self.row.status_namespace, &mut partial);
        let framing = match &self.framer {
            None => None,
            Some(framer) => Some(if adopt {
                framer.adopt(side, &ConnFacts::default(), &[], &mut produced)?
            } else {
                framer.open(side, target, &ConnFacts::default(), &mut produced)?
            }),
        };
        let (sent, ready, ended) = (produced.sent, produced.frames, produced.ended);
        if !sent.is_empty() {
            write
                .write_all(&sent)
                .await
                .map_err(|e| transport_error(&e))?;
            write.flush().await.map_err(|e| transport_error(&e))?;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let peer = arrival.source.clone();
        lock(&self.conns).insert(
            id,
            Arc::new(StackConn {
                arrival,
                carried,
                framing,
                read: AsyncMutex::new(Some(ReadSide {
                    half: read,
                    ready,
                    partial,
                    ended,
                    buf: vec![0_u8; READ_CHUNK_BYTES],
                })),
                write: AsyncMutex::new(Some(write)),
                closed: AtomicBool::new(false),
            }),
        );
        Ok(Conn::new(Arc::new(StackConnHandle { id, peer })))
    }

    /// What a carrier connection's arrival says, with this stack's chain.
    fn arrival_of(&self, carrier: &Arc<dyn Carrier>, conn: u64, peer: String) -> ArrivalRecord {
        let facts = carrier.arrival(conn);
        ArrivalRecord {
            source: facts.as_ref().map_or(peer, |f| f.peer.clone()),
            port: facts.map_or(0, |f| f.local_port),
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: self.chain(),
        }
    }

    /// Write `bytes` to `conn` and flush them.
    async fn send(&self, conn: &StackConn, bytes: &[u8]) -> Result<(), TransportError> {
        let mut write = conn.write.lock().await;
        let half = write.as_mut().ok_or(TransportError::Closed)?;
        half.write_all(bytes)
            .await
            .map_err(|e| transport_error(&e))?;
        half.flush().await.map_err(|e| transport_error(&e))
    }

    /// The next frame of `conn`, reading and ingesting as many bytes as it takes; `None` at the end.
    async fn next_frame(
        &self,
        conn: &StackConn,
    ) -> Option<Result<(StreamId, Frame), TransportError>> {
        let mut guard = conn.read.lock().await;
        let side = guard.as_mut()?;
        loop {
            if conn.closed.load(Ordering::Acquire) {
                return None;
            }
            if let Some(frame) = side.ready.pop_front() {
                return Some(Ok(frame));
            }
            if side.ended {
                return None;
            }
            let n = match side.half.read(&mut side.buf).await {
                Ok(n) => n,
                Err(e) => return Some(Err(transport_error(&e))),
            };
            let (Some(framer), Some(state)) = (&self.framer, conn.framing) else {
                // No framer: every read is one frame, and the clean end is the end.
                if n == 0 {
                    side.ended = true;
                    return None;
                }
                let bytes = &side.buf[..n];
                return Some(Ok((
                    StreamId(0),
                    Frame {
                        direction: Direction::Inbound,
                        stream: StreamId(0),
                        bytes: SlabBytes::new(Arc::<[u8]>::from(bytes)),
                        meta: FrameMeta {
                            bytes: n as u64,
                            ..blank_meta()
                        },
                    },
                )));
            };
            let mut produced = Produced::new(self.row.status_namespace, &mut side.partial);
            let ingested = framer.ingest(state, &side.buf[..n], n == 0, &mut produced);
            let (sent, frames, ended) = (produced.sent, produced.frames, produced.ended);
            side.ready.extend(frames);
            side.ended |= ended || n == 0;
            if let Err(e) = ingested {
                side.ended = true;
                return Some(Err(e));
            }
            if !sent.is_empty() {
                if let Err(e) = self.send(conn, &sent).await {
                    side.ended = true;
                    return Some(Err(e));
                }
            }
        }
    }

    /// Close `conn` for `reason`: the framer's close bytes go out within the budget, then the stream.
    fn close(self: &Arc<Self>, id: u64, reason: CloseReason) {
        let Some(conn) = self.forget(id) else {
            return;
        };
        conn.closed.store(true, Ordering::Release);
        let mut partial = HashMap::new();
        let mut produced = Produced::new(self.row.status_namespace, &mut partial);
        if let (Some(framer), Some(state)) = (&self.framer, conn.framing) {
            framer.close(state, reason, &mut produced);
        }
        let farewell = produced.sent;
        // Nothing owed on the way out: the carrier connection closes NOW, on the caller's thread, and
        // a read parked on it wakes to see it closed.
        if farewell.is_empty() {
            if let Some((carrier, id)) = &conn.carried {
                let _ = carrier.poll_close(
                    *id,
                    &mut Context::from_waker(std::task::Waker::noop()),
                    reason,
                );
            }
        }
        let stack = Arc::clone(self);
        let finish = async move {
            if !farewell.is_empty() {
                let _ = futures::future::select(
                    Box::pin(stack.send(&conn, &farewell)),
                    Box::pin(futures_timer(CLOSE_BUDGET)),
                )
                .await;
            }
            if let Some(mut half) = conn.write.lock().await.take() {
                let _ = half.close().await;
            }
            conn.read.lock().await.take();
        };
        // On a runtime the close finishes there; off one the stream simply drops, which closes it.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(finish);
            }
            Err(_) => drop(finish),
        }
    }
}

/// A timer the close budget races, on the runtime the close runs on.
async fn futures_timer(d: std::time::Duration) {
    tokio::time::sleep(d).await;
}

impl Plugin for WireTransport {
    fn key(&self) -> &'static str {
        self.stack.row.key
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
        self.stack.get(conn.id()).map_or_else(
            || ArrivalRecord {
                source: conn.peer(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: self.stack.chain(),
            },
            |c| c.arrival.clone(),
        )
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        // The carrier answers an absent bind itself: the stack decides no address.
        let bind = cfg.bind().unwrap_or_default().to_string();
        Box::pin(async move {
            let (id, addr) = self.stack.carrier()?.listen(&bind)?;
            let listener = Listener::new(Arc::new(StackListener { addr }));
            lock(&self.stack.listeners).insert(listener.id(), id);
            Ok(listener)
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let carrier = Arc::clone(self.stack.carrier()?);
            let listener = *lock(&self.stack.listeners)
                .get(&l.id())
                .ok_or(TransportError::Closed)?;
            // The connection is handed out in the same poll that took it: an accept dropped while
            // pending took nothing.
            let (conn, peer) = std::future::poll_fn(|cx| carrier.poll_accept(listener, cx)).await?;
            let arrival = self.stack.arrival_of(&carrier, conn, peer);
            let raw: Box<dyn RawIo> = Box::new(CarrierIo::new(Arc::clone(&carrier), conn));
            let io = match &self.stack.security {
                Some(security) => security
                    .wrap(raw)
                    .await
                    .map_err(|_| TransportError::HandshakeFailed)?,
                None => raw,
            };
            self.stack
                .hand_out(io, Some((carrier, conn)), arrival, Side::Accept, "", false)
                .await
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let DestinationFacts::Upstream { address, .. } = dest.facts() else {
                return Err(TransportError::AddressRefused);
            };
            let carrier = Arc::clone(self.stack.carrier()?);
            let (target, reach) = match (address, &self.stack.framer) {
                (UpstreamAddress::Socket { authority, .. }, Some(framer)) => {
                    let located = framer.locate(authority)?;
                    // The stack's security wraps what it ACCEPTS; a target that asks for its bytes
                    // secured before they leave is not dialled in the clear.
                    if located.secure {
                        return Err(TransportError::AddressRefused);
                    }
                    (authority.to_string(), located.authority)
                }
                (UpstreamAddress::Socket { authority, .. }, None) => {
                    (authority.to_string(), authority.to_string())
                }
                (UpstreamAddress::Program { path, .. }, _) => (path.to_string(), String::new()),
            };
            let conn = match address {
                UpstreamAddress::Program {
                    path, args, env, ..
                } => carrier.dial(&Dest::Program {
                    program: path,
                    args,
                    env,
                })?,
                UpstreamAddress::Socket { .. } => carrier.dial(&Dest::Authority(&reach))?,
            };
            let mut io = CarrierIo::new(Arc::clone(&carrier), conn);
            // The dial's refusal (or its opening) is what the connection's first flush answers; a
            // dial dropped before it opened closes it (the stream drops).
            futures::io::AsyncWriteExt::flush(&mut io)
                .await
                .map_err(|e| transport_error(&e))?;
            let arrival = self.stack.arrival_of(&carrier, conn, target.clone());
            self.stack
                .hand_out(
                    Box::new(io),
                    Some((carrier, conn)),
                    arrival,
                    Side::Dial,
                    &target,
                    false,
                )
                .await
        })
    }

    fn frames(&self, conn: Conn) -> busbar_contract::transport::FrameStream {
        let stack = Arc::clone(&self.stack);
        let Some(held) = stack.get(conn.id()) else {
            return Box::pin(futures::stream::once(async {
                Err::<(StreamId, Frame), TransportError>(TransportError::Closed)
            }));
        };
        Box::pin(futures::stream::unfold(
            (stack, held, false),
            |(stack, held, done)| async move {
                if done {
                    return None;
                }
                match stack.next_frame(&held).await {
                    None => None,
                    Some(Ok(frame)) => Some((Ok(frame), (stack, held, false))),
                    Some(Err(e)) => Some((Err(e), (stack, held, true))),
                }
            },
        ))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let held = self.stack.get(conn.id()).ok_or(TransportError::Closed)?;
            match (&self.stack.framer, held.framing) {
                (Some(framer), Some(state)) => {
                    let mut partial = HashMap::new();
                    let mut produced = Produced::new(self.stack.row.status_namespace, &mut partial);
                    framer.emit(state, stream, bytes.as_slice(), true, &mut produced)?;
                    let sent = produced.sent;
                    self.stack.send(&held, &sent).await?;
                }
                // Straight from the arena: the write is driven inline, so the bytes are on the wire
                // (or refused) before the arena can be reset.
                _ => self.stack.send(&held, bytes.as_slice()).await?,
            }
            Ok(bytes.len())
        })
    }

    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, Encode> {
        match &self.stack.framer {
            Some(framer) => {
                let mut out: Vec<u8> = Vec::with_capacity(body.len() + 128);
                framer.encode_envelope(fields, body, &mut out as &mut dyn BytesOut)?;
                arena
                    .alloc_bytes(&out)
                    .map_err(|_| Encode::ScratchExhausted)
            }
            // A byte stream's message is its body.
            None => arena
                .alloc_bytes(body)
                .map_err(|_| Encode::ScratchExhausted),
        }
    }

    fn adopt<'a>(
        &'a self,
        from: &'a dyn Transport,
        conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            if self.stack.framer.is_none() {
                return Err(TransportError::HandoffMismatch);
            }
            // Read before the detach: after it, `from` knows nothing about this connection.
            let below = from.arrival(&conn);
            let raw = from.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            let mut chain = below.transport_chain.clone();
            chain.push(self.stack.row.key);
            let arrival = ArrivalRecord {
                transport_chain: chain,
                ..below
            };
            self.stack
                .hand_out(raw.into_io(), None, arrival, Side::Accept, "", true)
                .await
        })
    }

    /// The connection's byte stream, with whatever its framer held unconsumed in front of it: this
    /// stack forgets the connection, and the stream closes when it is closed or dropped. `None` while
    /// a reader or writer still holds it (an upgrade never races an in-flight read).
    fn detach(&self, conn: &Conn) -> Option<RawStream> {
        let held = self.stack.get(conn.id())?;
        let read = held.read.try_lock()?;
        let write = held.write.try_lock()?;
        if read.is_none() || write.is_none() {
            return None;
        }
        let mut leftover = Vec::new();
        if let (Some(framer), Some(state)) = (&self.stack.framer, held.framing) {
            framer
                .detach(state, &mut leftover as &mut dyn BytesOut)
                .ok()?;
        }
        drop((read, write));
        let held = self.stack.forget(conn.id())?;
        let half = held.read.try_lock()?.take()?;
        let whalf = held.write.try_lock()?.take()?;
        let io = half.half.reunite(whalf).ok()?;
        Some(RawStream::new(
            self.stack.row.key,
            conn.peer(),
            Box::new(Prefixed {
                leftover,
                at: 0,
                io,
            }),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.stack
            .framer
            .as_ref()
            .and(self.stack.carrier.as_ref().map(|(k, _)| *k))
    }

    fn close(&self, conn: Conn, reason: CloseReason) {
        self.stack.close(conn.id(), reason);
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let id = conn.id();
            let held = self.stack.get(id).ok_or(TransportError::Closed)?;
            let rendered = match (&self.stack.framer, held.framing) {
                (Some(framer), Some(state)) => {
                    let mut partial = HashMap::new();
                    let mut produced = Produced::new(self.stack.row.status_namespace, &mut partial);
                    framer
                        .refusal(state, stream, bytes.as_slice(), &mut produced)
                        .map(|()| produced.sent)
                }
                _ => Ok(bytes.as_slice().to_vec()),
            };
            // A refusal finalises the connection on every path out, delivered or not.
            let delivered = match rendered {
                Ok(out) => self.stack.send(&held, &out).await,
                Err(e) => Err(e),
            };
            self.stack.close(id, CloseReason::Normal);
            delivered
        })
    }
}
