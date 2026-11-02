// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL INBOUND BYTE-DUPLEX TRANSPORT — the byte half of a single full-duplex channel, owned
//! by the substrate so a protocol plane never re-implements framing, the write lock, correlation or
//! the shutdown lifecycle.
//!
//! ## What a transport owns, and NOTHING a plane means
//!
//! An inbound stdio-class channel is one bidirectional byte pipe shared by everything. What that
//! carrier owns is exactly four things, and this module is exactly those four:
//!
//! 1. **Framing** — one frame per line (bytes split on `0x0A`), a final unterminated line still a
//!    frame, a blank line not a frame. Frames cross as [`Vec<u8>`]; this module NEVER parses one.
//! 2. **A single write lock** — two answers interleaving inside one line would be a frame no reader
//!    could parse, so every outbound frame passes one [`tokio::sync::Mutex`] over the writer.
//! 3. **Correlation** — a caller on this side may issue a frame and await the one that answers it.
//!    The pairing is keyed on a [`CallRef`], a bare monotonic `u64` this module mints; the plane
//!    embeds it into its own frame however its wire spells an id, and its [`DuplexPlane::classify`]
//!    reads it back out. This module knows the number and nothing about where it lives in the bytes.
//! 4. **The session lifecycle** — the reader loop runs until EOF (zero bytes) or a read error, then
//!    drains in-flight handlers under a bound and flushes.
//!
//! ## The plane is TWO callbacks and no more
//!
//! A plane binds this transport by supplying a [`DuplexPlane`]:
//!
//! * [`classify`](DuplexPlane::classify) — "is this inbound frame a reply, and to which call I
//!   issued?" It returns the [`CallRef`] the frame answers, or `None` for anything else (a fresh
//!   request, a notification, garbage). This module routes a classified reply to the waiting caller
//!   and hands everything else to the handler. There is NO reply-shape logic here: no id member, no
//!   `result`/`error` inspection, no JSON — the plane decides what "a reply" is.
//! * [`handle`](DuplexPlane::handle) — process ONE inbound non-reply frame, concurrently with its
//!   siblings, writing any answers back through the [`DuplexHandle`] it is given.
//!
//! Everything a specific protocol layers on top — what a frame's id looks like, which verbs mean
//! what, session-scoped state, cancellation semantics — lives in the plane, on the far side of these
//! two callbacks. This crate names none of it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

/// A neutral correlation key: the identity of ONE call awaiting its answer on this channel, as a
/// bare monotonic number. `0` is the reserved "no call" value that [`DuplexHandle::mint`] never
/// returns, so a plane can spell "this frame answers nothing" without an `Option`.
///
/// The transport mints it and matches it; the plane embeds it into, and reads it back out of, its
/// own frame bytes — this module attaches no wire meaning to where the number lives.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallRef(pub u64);

impl CallRef {
    pub const NONE: CallRef = CallRef(0);

    #[must_use]
    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

const EOF_DRAIN: std::time::Duration = std::time::Duration::from_secs(3);

const MAX_INFLIGHT_HANDLERS: usize = 256;

const MAX_QUEUED_FRAMES: usize = MAX_INFLIGHT_HANDLERS;

const QUEUE_DEPTH: usize = MAX_INFLIGHT_HANDLERS + MAX_QUEUED_FRAMES;

const MAX_FRAME_BYTES: usize = crate::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES;

/// The two callbacks a plane supplies to bind this transport. The transport is generic over the
/// concrete implementor, so there is no boxing on the hot per-frame path; the implementor is shared
/// across concurrent handlers, hence `Send + Sync + 'static`.
#[async_trait::async_trait]
pub trait DuplexPlane: Send + Sync + 'static {
    /// Is this inbound frame a REPLY to a call this side issued, and to which? Return the answered
    /// [`CallRef`], or `None` for anything that is not a reply (a fresh request, a notification,
    /// unparsable bytes). A returned [`CallRef::NONE`] is treated as `None`. This is the ONLY place a
    /// plane's "what a reply looks like" lives; the transport reads no frame content of its own.
    fn classify(&self, frame: &[u8]) -> Option<CallRef>;

    /// Handle ONE inbound non-reply frame, writing any answers back through `out`. Runs concurrently
    /// with the handlers of other frames; the transport serialises only the bytes on the wire, never
    /// the handling.
    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle);
}

/// The write-and-call side of the channel, handed to every handler and returned to the caller of
/// [`serve`]. Cloneable and cheap: it is a shared handle onto the one writer and the one correlation
/// table. Every method here is transport-level — it moves bytes and pairs a call with its answer,
/// and reads none of what those bytes mean.
#[derive(Clone)]
pub struct DuplexHandle {
    shared: Arc<Shared>,
}

impl DuplexHandle {
    pub async fn emit(&self, frame: Vec<u8>) -> std::io::Result<()> {
        let mut out = self.shared.sink.lock().await;
        out.send(frame).await
    }

    pub fn mint(&self) -> CallRef {
        CallRef(self.shared.next_ref.fetch_add(1, Ordering::Relaxed))
    }

    pub async fn issue(&self, call: CallRef, frame: Vec<u8>) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(call.0, tx);
        let _registration = PendingCall {
            shared: self.shared.clone(),
            call: call.0,
        };

        if let Err(e) = self.emit(frame).await {
            tracing::debug!(error = %e, call = call.0, "duplex: the frame issuing a call could not be written; failing the call");
            return None;
        }

        rx.await.ok()
    }
}

struct PendingCall {
    shared: Arc<Shared>,
    call: u64,
}

impl Drop for PendingCall {
    fn drop(&mut self) {
        self.shared.pending.lock().unwrap().remove(&self.call);
    }
}

struct Shared {
    sink: tokio::sync::Mutex<Box<dyn FrameSink>>,

    pending: Mutex<HashMap<u64, oneshot::Sender<Vec<u8>>>>,

    next_ref: AtomicU64,

    inflight: Mutex<std::collections::HashSet<u64>>,

    next_inflight: AtomicU64,

    handlers: Arc<tokio::sync::Semaphore>,

    queued: std::sync::atomic::AtomicUsize,
}

/// THE PLUGGABLE WRITE HALF — one outbound frame in, framed onto the wire however the bound transport
/// frames. The pump's [`DuplexHandle::emit`] hands a frame here and reads nothing of the wire shape;
/// which shape (newline-terminated bytes vs one whole message per frame) is exactly the difference
/// between [`NewlineSink`] and [`MessageSink`]. Private: the crate exposes the two entry points
/// ([`serve`], [`serve_messages`]) that pick the sink, not the sink trait itself.
#[async_trait::async_trait]
trait FrameSink: Send {
    /// Write ONE frame, framed for this transport, and flush it. `Err` means the frame did NOT reach
    /// the wire — the caller decides what a lost frame costs it, because only the caller knows what
    /// it wrote (see [`DuplexHandle::emit`]).
    async fn send(&mut self, frame: Vec<u8>) -> std::io::Result<()>;
    /// Flush any buffered bytes at end-of-session.
    async fn flush(&mut self) -> std::io::Result<()>;
}

struct NewlineSink<W> {
    writer: W,
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> FrameSink for NewlineSink<W> {
    async fn send(&mut self, mut frame: Vec<u8>) -> std::io::Result<()> {
        frame.push(b'\n');

        self.writer.write_all(&frame).await?;
        self.writer.flush().await
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush().await
    }
}

struct MessageSink<Sk> {
    sink: Sk,
}

#[async_trait::async_trait]
impl<Sk: Sink<Vec<u8>> + Unpin + Send> FrameSink for MessageSink<Sk> {
    async fn send(&mut self, frame: Vec<u8>) -> std::io::Result<()> {
        self.sink
            .send(frame)
            .await
            .map_err(|_| std::io::Error::other(SINK_REFUSED))
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        self.sink
            .flush()
            .await
            .map_err(|_| std::io::Error::other(SINK_REFUSED))
    }
}

const SINK_REFUSED: &str = "the message sink refused the frame (the channel is closed)";

fn new_shared(sink: Box<dyn FrameSink>) -> Arc<Shared> {
    Arc::new(Shared {
        sink: tokio::sync::Mutex::new(sink),
        pending: Mutex::new(HashMap::new()),
        next_ref: AtomicU64::new(1),
        inflight: Mutex::new(std::collections::HashSet::new()),
        next_inflight: AtomicU64::new(0),
        handlers: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_HANDLERS)),
        queued: std::sync::atomic::AtomicUsize::new(0),
    })
}

/// What the reader learned from offering ONE frame to the session.
#[derive(Debug, PartialEq, Eq)]
enum Offered {
    /// The frame was routed to its waiting caller, or accepted for handling.
    Accepted,
    /// The peer has every handler in flight AND [`MAX_QUEUED_FRAMES`] more frames waiting for one,
    /// and is still writing. Both of this session's bounds are exhausted at once, so there is no
    /// place left to put the frame that does not cost this node unbounded memory — and no
    /// plane-side meaning here to refuse it with, exactly as for a framing fault. The session ends.
    Overrun,
}

fn offer_frame<P: DuplexPlane>(
    shared: &Arc<Shared>,
    plane: &Arc<P>,
    frames: &tokio::sync::mpsc::Sender<Vec<u8>>,
    frame: Vec<u8>,
) -> Offered {
    if let Some(call) = plane.classify(&frame).filter(|c| !c.is_none()) {
        if let Some(tx) = shared.pending.lock().unwrap().remove(&call.0) {
            let _ = tx.send(frame);
        }

        return Offered::Accepted;
    }

    shared
        .queued
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    match frames.try_send(frame) {
        Ok(()) => Offered::Accepted,
        Err(_) => {
            shared
                .queued
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            tracing::debug!(
                "duplex: the session's handler cap and frame queue are both full and the peer is still writing; ending the session"
            );
            Offered::Overrun
        }
    }
}

fn spawn_dispatcher<P: DuplexPlane>(
    shared: &Arc<Shared>,
    handle: &DuplexHandle,
    plane: &Arc<P>,
) -> (
    tokio::sync::mpsc::Sender<Vec<u8>>,
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let shared = shared.clone();
    let handle = handle.clone();
    let plane = plane.clone();
    let task = tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                _ = stop_rx.changed() => return,
                frame = rx.recv() => frame,
            };
            let Some(frame) = frame else { return };

            let permit = tokio::select! {
                biased;
                _ = stop_rx.changed() => return,
                permit = shared.handlers.clone().acquire_owned() => permit,
            };
            let Ok(permit) = permit else { return };
            spawn_handler(&shared, &handle, &plane, frame, permit);
        }
    });
    (tx, task, stop_tx)
}

fn spawn_handler<P: DuplexPlane>(
    shared: &Arc<Shared>,
    handle: &DuplexHandle,
    plane: &Arc<P>,
    frame: Vec<u8>,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let key = shared.next_inflight.fetch_add(1, Ordering::Relaxed);

    shared.inflight.lock().unwrap().insert(key);

    shared
        .queued
        .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    let plane = plane.clone();
    let handle = handle.clone();
    let for_cleanup = shared.clone();

    tokio::spawn(async move {
        let _permit = permit;

        let _slot = InflightSlot {
            shared: for_cleanup,
            key,
        };
        plane.handle(frame, handle).await;
    });
}

struct InflightSlot {
    shared: Arc<Shared>,
    key: u64,
}

impl Drop for InflightSlot {
    fn drop(&mut self) {
        self.shared
            .inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

async fn drain_and_flush(
    shared: &Arc<Shared>,
    dispatcher: tokio::task::JoinHandle<()>,
    stop_dispatcher: tokio::sync::watch::Sender<bool>,
) {
    let deadline = tokio::time::Instant::now() + EOF_DRAIN;

    let working = || {
        shared.queued.load(std::sync::atomic::Ordering::Acquire) > 0
            || !shared.inflight.lock().unwrap().is_empty()
    };
    while working() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let _ = stop_dispatcher.send(true);
    let _ = dispatcher.await;

    let stragglers = shared.inflight.lock().unwrap().len();
    if stragglers > 0 {
        tracing::debug!(
            stragglers,
            "duplex: end-of-session drain bound reached with handler(s) still running; letting them \
             finish in the background rather than forcing them"
        );
    }

    if let Err(e) = shared.sink.lock().await.flush().await {
        tracing::debug!(error = %e, "duplex: the end-of-session flush failed; buffered bytes were lost");
    }
}

pub async fn serve<R, W, P>(reader: R, writer: W, plane: Arc<P>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    P: DuplexPlane,
{
    let shared = new_shared(Box::new(NewlineSink { writer }));
    let handle = DuplexHandle {
        shared: shared.clone(),
    };
    let (frames, dispatcher, stop_dispatcher) = spawn_dispatcher(&shared, &handle, &plane);
    let mut lines = tokio::io::BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();

        let read = (&mut lines)
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut buf)
            .await;
        match read {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        } else if buf.len() > MAX_FRAME_BYTES {
            break;
        }
        if buf.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if offer_frame(&shared, &plane, &frames, std::mem::take(&mut buf)) == Offered::Overrun {
            break;
        }
    }
    drain_and_flush(&shared, dispatcher, stop_dispatcher).await;
}

pub async fn serve_messages<St, Sk, P>(mut stream: St, sink: Sk, plane: Arc<P>)
where
    St: Stream<Item = Vec<u8>> + Unpin,
    Sk: Sink<Vec<u8>> + Unpin + Send + 'static,
    P: DuplexPlane,
{
    let shared = new_shared(Box::new(MessageSink { sink }));
    let handle = DuplexHandle {
        shared: shared.clone(),
    };
    let (frames, dispatcher, stop_dispatcher) = spawn_dispatcher(&shared, &handle, &plane);

    while let Some(frame) = stream.next().await {
        if offer_frame(&shared, &plane, &frames, frame) == Offered::Overrun {
            break;
        }
    }
    drain_and_flush(&shared, dispatcher, stop_dispatcher).await;
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/byte_duplex_tests.rs"]
mod tests;
