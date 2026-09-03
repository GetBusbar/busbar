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
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
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
    /// The reserved "no call" ref. Never minted; a plane returns it (or `None`) to say a frame
    /// correlates to nothing.
    pub const NONE: CallRef = CallRef(0);

    /// `true` when this is the reserved [`CallRef::NONE`].
    #[must_use]
    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// How long EOF waits for in-flight handlers to finish before the loop returns anyway. Long enough
/// for the ordinary one-shot invocation (a frame whose answer is computed in milliseconds, with EOF
/// already on the pipe) and short enough that a handler that cannot or will not finish does not hold
/// the loop open. A supervising launcher's close-then-wait-then-kill reads a bound this size as
/// prompt.
const EOF_DRAIN: std::time::Duration = std::time::Duration::from_secs(3);

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
    /// Write ONE frame under the single write lock, framed however the bound [`FrameSink`] frames.
    /// Over the newline byte sink (the [`serve`] path) that is the bytes then the `0x0A` terminator, so
    /// a caller composing such a frame must not embed a newline; over the message sink (the
    /// [`serve_messages`] path) the frame IS one whole message and no terminator is added. The handle
    /// stays framing-agnostic: it hands the sink one frame and the sink decides the wire shape.
    pub async fn emit(&self, frame: Vec<u8>) {
        let mut out = self.shared.sink.lock().await;
        out.send(frame).await;
    }

    /// Mint a fresh, non-zero [`CallRef`] for a call this side is about to issue. Monotonic for the
    /// life of the channel; never returns [`CallRef::NONE`].
    pub fn mint(&self) -> CallRef {
        CallRef(self.shared.next_ref.fetch_add(1, Ordering::Relaxed))
    }

    /// Issue a call: register `call` as awaiting an answer, [`emit`](Self::emit) `frame`, and await
    /// the reply frame the reader routes back when [`DuplexPlane::classify`] later names this
    /// `call`. `None` when the channel closes before an answer arrives.
    ///
    /// The caller mints `call` with [`mint`](Self::mint) and embeds it into `frame` however its wire
    /// spells a correlation id; the registration happens BEFORE the frame is written, so a reply
    /// that races back cannot find an empty table.
    pub async fn issue(&self, call: CallRef, frame: Vec<u8>) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(call.0, tx);
        self.emit(frame).await;
        match rx.await {
            Ok(reply) => Some(reply),
            Err(_) => {
                // The channel closed (EOF dropped the sender) before an answer arrived.
                self.shared.pending.lock().unwrap().remove(&call.0);
                None
            }
        }
    }
}

/// The shared spine of one channel: the locked sink, the correlation table, the ref mint, and the
/// in-flight handler registry. Non-generic over the sink — it is type-erased at the entry point
/// ([`serve`] or [`serve_messages`]) so a [`DuplexHandle`] a plane holds carries neither the writer
/// type nor the framing it speaks.
struct Shared {
    /// ONE sink, ONE lock — see the module header, rule 2. Type-erased to a boxed [`FrameSink`] so a
    /// [`DuplexHandle`] a plane holds carries neither the concrete writer type nor which framing
    /// (newline bytes vs one-message-per-frame) the bound transport speaks.
    sink: tokio::sync::Mutex<Box<dyn FrameSink>>,
    /// Calls issued on this side awaiting their answer, keyed on the raw [`CallRef`] number.
    pending: Mutex<HashMap<u64, oneshot::Sender<Vec<u8>>>>,
    /// The monotonic mint; starts at 1 so [`CallRef::NONE`] (`0`) is never handed out.
    next_ref: AtomicU64,
    /// In-flight per-frame handlers, keyed on a private sequence so each removes itself on
    /// completion (bounded memory) and the loop can abort the remainder at EOF.
    inflight: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    /// The private sequence behind the `inflight` keys.
    next_inflight: AtomicU64,
}

/// THE PLUGGABLE WRITE HALF — one outbound frame in, framed onto the wire however the bound transport
/// frames. The pump's [`DuplexHandle::emit`] hands a frame here and reads nothing of the wire shape;
/// which shape (newline-terminated bytes vs one whole message per frame) is exactly the difference
/// between [`NewlineSink`] and [`MessageSink`]. Private: the crate exposes the two entry points
/// ([`serve`], [`serve_messages`]) that pick the sink, not the sink trait itself.
#[async_trait::async_trait]
trait FrameSink: Send {
    /// Write ONE frame, framed for this transport, and flush it.
    async fn send(&mut self, frame: Vec<u8>);
    /// Flush any buffered bytes at end-of-session.
    async fn flush(&mut self);
}

/// The BYTE framing: a frame is its bytes then the `0x0A` terminator — byte-for-byte the wire the
/// stdio pump always spoke. Wraps any `AsyncWrite`.
struct NewlineSink<W> {
    writer: W,
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> FrameSink for NewlineSink<W> {
    async fn send(&mut self, mut frame: Vec<u8>) {
        frame.push(b'\n');
        let _ = self.writer.write_all(&frame).await;
        let _ = self.writer.flush().await;
    }
    async fn flush(&mut self) {
        let _ = self.writer.flush().await;
    }
}

/// The MESSAGE framing: a frame IS one whole message, emitted with no terminator. Wraps any
/// `Sink<Vec<u8>>` — the already-upgraded write half of a message duplex (e.g. a WebSocket, whose
/// text/binary payloads a caller has mapped to frame bytes at the upgrade site).
struct MessageSink<Sk> {
    sink: Sk,
}

#[async_trait::async_trait]
impl<Sk: Sink<Vec<u8>> + Unpin + Send> FrameSink for MessageSink<Sk> {
    async fn send(&mut self, frame: Vec<u8>) {
        // `SinkExt::send` feeds then flushes; the message is one frame, so there is no terminator to
        // add. A closed sink drops the frame — the reader side has already ended the session.
        let _ = self.sink.send(frame).await;
    }
    async fn flush(&mut self) {
        let _ = self.sink.flush().await;
    }
}

/// Assemble the shared spine over a chosen (type-erased) [`FrameSink`]. The mint starts at 1 so
/// [`CallRef::NONE`] (`0`) is never handed out.
fn new_shared(sink: Box<dyn FrameSink>) -> Arc<Shared> {
    Arc::new(Shared {
        sink: tokio::sync::Mutex::new(sink),
        pending: Mutex::new(HashMap::new()),
        next_ref: AtomicU64::new(1),
        inflight: Mutex::new(HashMap::new()),
        next_inflight: AtomicU64::new(0),
    })
}

/// ROUTE ONE inbound frame: a REPLY the plane recognises goes to the caller awaiting it and reaches no
/// handler; everything else is handled concurrently under a private key so it clears itself on
/// completion and the EOF path can abort whatever remains. Shared by both entry points so the
/// correlation contract is written once, regardless of framing.
fn dispatch_frame<P: DuplexPlane>(
    shared: &Arc<Shared>,
    handle: &DuplexHandle,
    plane: &Arc<P>,
    frame: Vec<u8>,
) {
    if let Some(call) = plane.classify(&frame).filter(|c| !c.is_none()) {
        if let Some(tx) = shared.pending.lock().unwrap().remove(&call.0) {
            let _ = tx.send(frame);
        }
        // A reply to a call nobody is waiting on is dropped: with no plane-side meaning to consult,
        // the transport has nothing to answer it with.
        return;
    }
    let key = shared.next_inflight.fetch_add(1, Ordering::Relaxed);
    let plane = plane.clone();
    let handle = handle.clone();
    let for_cleanup = shared.clone();
    let running = tokio::spawn(async move {
        plane.handle(frame, handle).await;
        for_cleanup.inflight.lock().unwrap().remove(&key);
    });
    shared
        .inflight
        .lock()
        .unwrap()
        .insert(key, running.abort_handle());
}

/// END OF SESSION: DRAIN the in-flight handlers under a bound, then abort the remainder and flush. A
/// one-shot invocation (one frame, then EOF/close) has its answer computed after the far end goes
/// away, so a straight abort would serve nothing to exactly the caller who asked for one thing. Shared
/// by both entry points.
async fn drain_and_flush(shared: &Arc<Shared>) {
    let deadline = tokio::time::Instant::now() + EOF_DRAIN;
    while !shared.inflight.lock().unwrap().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for (_, h) in shared.inflight.lock().unwrap().drain() {
        h.abort();
    }
    shared.sink.lock().await.flush().await;
}

/// SERVE one inbound byte-duplex channel over any `AsyncRead`/`AsyncWrite` pair until EOF, driving
/// `plane`'s two callbacks. Returns when the reader reaches EOF (or errors) and the bounded in-flight
/// drain completes. Generic so a plane serves its real process stdin/stdout and a test drives an
/// in-memory duplex through the identical path.
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
    let mut lines = tokio::io::BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        // One frame per line, split on 0x0A. EOF — zero bytes read — ends the session; a final
        // unterminated line is still one frame.
        match lines.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.iter().all(u8::is_ascii_whitespace) {
            continue; // a blank line is not a frame
        }
        dispatch_frame(&shared, &handle, &plane, std::mem::take(&mut buf));
    }
    drain_and_flush(&shared).await;
}

/// SERVE one inbound MESSAGE-duplex channel until the stream ends, driving the SAME `plane` callbacks,
/// correlation table and drain lifecycle as [`serve`] — the difference is framing, and nothing else.
///
/// Where [`serve`] frames a byte stream on `0x0A`, this takes a channel that is ALREADY
/// message-oriented: `stream` yields one frame per message and `sink` accepts one message per frame,
/// with no newline convention. That is exactly the shape of an already-upgraded WebSocket, whose HTTP
/// upgrade, routing and message-kind handling (text/binary vs ping/pong/close) a caller performs at
/// the upgrade site and reduces to `Vec<u8>` frames here — so the neutral pump names no protocol and
/// stays out of the transport handshake. The stream ending (the peer's close, or a dropped sender)
/// ends the session, mirroring EOF on the byte path.
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
    // One frame per message, no framing to strip. The stream ending (close / dropped sender) is the
    // message-duplex analogue of EOF.
    while let Some(frame) = stream.next().await {
        dispatch_frame(&shared, &handle, &plane, frame);
    }
    drain_and_flush(&shared).await;
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/byte_duplex_tests.rs"]
mod tests;
