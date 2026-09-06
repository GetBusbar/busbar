// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-connection side table. One [`ConnState`] stands for one HTTP/2 connection, which may
//! carry many concurrent gRPC calls ("multiplexed streams" in the architecture's grpc row) — each
//! call is one [`busbar_contract::StreamId`], keyed in `outbound` below.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as SyncMutex};

use busbar_contract::wire::Frame;
use busbar_contract::StreamId;
use busbar_contract_transport::wire::ConnHandle;
use busbar_contract_transport::wire::TransportError;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// The opaque handle the kernel is given. Carries identity only — see `busbar-transport-stdio`'s
/// identical note on why the real state cannot live on `Conn` itself.
pub(crate) struct GrpcConnHandle {
    pub(crate) id: u64,
    pub(crate) peer: String,
}

impl ConnHandle for GrpcConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// Any duplex byte stream the layer below can hand up. Boxed rather than concrete because which
/// carrier is under this one — a plain socket, a TLS one, an in-memory pair — is that layer's
/// business and never this one's.
pub(crate) trait Lower: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Lower for T {}

/// The boxed form, as it crosses the handoff.
pub(crate) type LowerIo = Box<dyn Lower>;

/// The seam that cuts one lower stream, wherever it has ended up.
///
/// The HTTP/2 client hands the stream to a task of its OWN — the executor it was built with spawns
/// the driver that holds the socket — and that task ends only once every request sender on the
/// connection has gone and every call on it has finished. Neither is something `close` can promise
/// about a peer that has stopped answering, so a dialled connection closed from this side kept its
/// descriptor and both tasks around it. Cutting the stream is the one thing that reaches into a
/// task nothing here holds a handle to: the driver's next read fails, it finishes, and the socket
/// goes back to the kernel with it.
pub(crate) struct Cut {
    cut: std::sync::atomic::AtomicBool,
    waker: SyncMutex<Option<std::task::Waker>>,
}

impl Cut {
    fn new() -> Self {
        Self {
            cut: std::sync::atomic::AtomicBool::new(false),
            waker: SyncMutex::new(None),
        }
    }

    /// Cut it. Whatever is parked on a read of this stream is woken to find it gone.
    pub(crate) fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::Release);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn is_cut(&self) -> bool {
        self.cut.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Remember who to wake, and say whether the stream is already cut. Checked AFTER the waker is
    /// stored, so a cut landing between the two still wakes this poller.
    fn park(&self, cx: &std::task::Context<'_>) -> bool {
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        self.is_cut()
    }
}

/// A lower stream with a [`Cut`] on it. Reads end and writes fail once it is cut, which is what
/// ends whatever is driving the stream — however deeply that driver has been handed the stream.
pub(crate) struct Cuttable {
    io: LowerIo,
    cut: Arc<Cut>,
}

impl Cuttable {
    /// Wrap a stream, handing back the seam that cuts it.
    pub(crate) fn new(io: LowerIo) -> (Self, Arc<Cut>) {
        let cut = Arc::new(Cut::new());
        (
            Self {
                io,
                cut: cut.clone(),
            },
            cut,
        )
    }
}

impl tokio::io::AsyncRead for Cuttable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.cut.park(cx) {
            // End of stream, which is what a socket the kernel has taken back reads as.
            return std::task::Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Cuttable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.cut.is_cut() {
            return std::task::Poll::Ready(Err(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.cut.is_cut() {
            return std::task::Poll::Ready(Err(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.cut.is_cut() {
            return std::task::Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// How many inbound frames one connection may hold for a `frames()` consumer that is not keeping
/// up — the per-unit frame buffer the architecture's backpressure rule names.
pub(crate) const INBOUND_FRAME_BUFFER: usize = 64;

/// How many outbound messages one call may hold for a peer that is not reading — the same
/// per-unit depth the inbound side keeps, in the other direction. Past it, `write()` waits on the
/// peer rather than queueing on this process's heap and calling that "sent".
pub(crate) const OUTBOUND_FRAME_BUFFER: usize = 64;

/// How many served `:path`s one connection remembers. A long-lived connection serves calls
/// forever; this diagnostic record is for the last handful, not a leak-shaped unbounded log of
/// every RPC an HTTP/2 connection has ever carried.
pub(crate) const SERVED_PATHS_CAP: usize = 32;

/// One inbound item: a stream-tagged frame, or a transport failure on that stream.
pub(crate) type InboundItem = Result<(StreamId, Frame), TransportError>;

/// One open gRPC call's outbound half: the channel `write()` feeds and the RPC task drains. Bounded
/// at [`OUTBOUND_FRAME_BUFFER`], so a writer whose peer has stopped reading waits instead of
/// queueing.
pub(crate) type OutboundTx = mpsc::Sender<Vec<u8>>;

/// The draining half of one call's outbound queue, as the RPC task holds it.
pub(crate) type OutboundRx = mpsc::Receiver<Vec<u8>>;

/// One call's outbound queue, at the one depth both sides of this crate open it with.
pub(crate) fn outbound_channel() -> (OutboundTx, OutboundRx) {
    mpsc::channel(OUTBOUND_FRAME_BUFFER)
}

/// Opening a call is asynchronous, so what the map holds is the OPENING, not the opened channel.
///
/// Two `write()`s naming the same unseen stream must be one call: the first inserts this future
/// under the lock before it awaits anything, so the second finds it and awaits the same open rather
/// than starting a second one whose registration would overwrite — and drop — the first's sender.
pub(crate) type OpenCall = futures::future::Shared<
    Pin<Box<dyn Future<Output = Result<OutboundTx, TransportError>> + Send>>,
>;

/// An already-open call, in the shape the map holds. The server side registers these: an accepted
/// RPC's channel exists before anything can look it up.
pub(crate) fn opened(tx: OutboundTx) -> OpenCall {
    use futures::FutureExt;
    (Box::pin(std::future::ready(Ok(tx)))
        as Pin<Box<dyn Future<Output = Result<OutboundTx, TransportError>> + Send>>)
        .shared()
}

/// One entry in the outbound map: the call, and the serial that says WHICH call it is.
///
/// A `StreamId` is not an identity over time. The dial side takes them from whatever writes, the
/// accept side counts them up per connection, and a call's cleanup runs when that call ends — which
/// may be after the id has been used again. Removing by id alone let a finished call take the entry
/// of the live one that had reused it, ending a second unit's answer for the first one's death.
#[derive(Clone)]
pub(crate) struct Call {
    serial: u64,
    open: OpenCall,
}

impl Call {
    pub(crate) fn new(serial: u64, open: OpenCall) -> Self {
        Self { serial, open }
    }

    pub(crate) fn serial(&self) -> u64 {
        self.serial
    }

    pub(crate) fn open(&self) -> OpenCall {
        self.open.clone()
    }
}

/// One connection's real state.
pub(crate) struct ConnState {
    /// Every stream's inbound frames land on this ONE channel, tagged with their `StreamId` — the
    /// multiplexing is the tag, not a separate channel per stream, so `frames()` can just drain it.
    ///
    /// Held as an option so it can be ENDED. A sender this state owned outright was one that
    /// outlived the connection: the receiver could never reach end-of-stream, and `frames()` stayed
    /// pending forever on a connection whose peer had gone. What ends it is the connection's own
    /// completion — and `close`.
    inbound_tx: SyncMutex<Option<mpsc::Sender<InboundItem>>>,
    pub(crate) inbound_rx: AsyncMutex<Option<mpsc::Receiver<InboundItem>>>,
    /// One outbound channel per open stream (gRPC call). `write()` looks a stream up here; the
    /// task driving that RPC (accepted inbound, or opened by a dial-side `write` to a fresh
    /// `StreamId`) owns the receiving half and forwards each message onto the wire.
    pub(crate) outbound: SyncMutex<HashMap<u64, Call>>,
    /// Counts every call this connection has registered, so each one can be told from the next one
    /// to use its id. Never reused, unlike the ids themselves.
    next_call_serial: std::sync::atomic::AtomicU64,
    /// The dial-side connection, the origin URI, and the gRPC method every call it opens is
    /// dialled against — the method the destination named, so two destinations on one transport
    /// can name two different upstream methods.
    pub(crate) dialer: Option<(Arc<crate::client::Dialer>, http::Uri, &'static str)>,
    pub(crate) next_local_stream: std::sync::atomic::AtomicU64,
    /// The `:path` of every RPC served on this connection, in arrival order. gRPC names each call
    /// by a path, so this is what the transport actually answered on — recorded rather than
    /// assumed, because "the method a destination named is the method dialled" is otherwise a
    /// claim nothing checks.
    pub(crate) served_paths: SyncMutex<VecDeque<String>>,
    /// The way to stop the task driving this connection's HTTP/2 half. The accept side spawns that
    /// task and keeps this seam rather than the join handle: firing it asks for a graceful
    /// shutdown, so calls already in flight end with their own trailers instead of being cut. A
    /// connection nothing can stop is one `close` only stops listing.
    pub(crate) shutdown: SyncMutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// The way to stop a DIALLED connection, where the accept side's graceful seam has no
    /// counterpart: the HTTP/2 client's own driver holds the stream, so cutting the stream is what
    /// ends it. See [`Cut`].
    cut: SyncMutex<Option<Arc<Cut>>>,
    /// The composed stack this connection stands on, bottom layer first, ending in `grpc`. It is
    /// the layer below's chain plus this one, carried across the handoff — a connection that named
    /// only itself was one a location could not resolve against.
    pub(crate) chain: Vec<&'static str>,
}

impl ConnState {
    pub(crate) fn new(
        dialer: Option<(Arc<crate::client::Dialer>, http::Uri, &'static str)>,
        chain: Vec<&'static str>,
    ) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_FRAME_BUFFER);
        Arc::new(Self {
            inbound_tx: SyncMutex::new(Some(inbound_tx)),
            inbound_rx: AsyncMutex::new(Some(inbound_rx)),
            outbound: SyncMutex::new(HashMap::new()),
            next_call_serial: std::sync::atomic::AtomicU64::new(1),
            dialer,
            next_local_stream: std::sync::atomic::AtomicU64::new(1),
            served_paths: SyncMutex::new(VecDeque::new()),
            shutdown: SyncMutex::new(None),
            cut: SyncMutex::new(None),
            chain,
        })
    }
}

impl ConnState {
    /// Hand one inbound item to whatever is polling `frames()`, waiting when the per-unit frame
    /// buffer is full.
    ///
    /// This is the bidirectional half of backpressure the architecture requires and the transport
    /// battery names as a cell: a peer writing faster than `frames()` is polled must stall against
    /// the HTTP/2 flow-control window, not queue on this process's heap. Peer bytes are untrusted,
    /// and this connection carries every multiplexed call's inbound messages on this one channel.
    pub(crate) async fn send_inbound(&self, item: InboundItem) -> Result<(), ()> {
        // Cloned out from under the lock and awaited outside it: the wait is on the reader, which
        // may be a long one, and it must not hold every other call's sender hostage.
        let tx = self.inbound_tx.lock().unwrap().clone().ok_or(())?;
        tx.send(item).await.map_err(|_| ())
    }

    /// End the inbound side: no frame will ever arrive on this connection again, so `frames()`
    /// finishes rather than waiting for one. Called when the connection's own task completes, and
    /// by `close`.
    pub(crate) fn end_inbound(&self) {
        self.inbound_tx.lock().unwrap().take();
    }

    /// The serial the next call registered on this connection will carry.
    pub(crate) fn next_call_serial(&self) -> u64 {
        self.next_call_serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Put one call in the map under `id`, taking a fresh serial for it.
    pub(crate) fn register(&self, id: u64, open: OpenCall) -> u64 {
        let serial = self.next_call_serial();
        self.insert(id, serial, open);
        serial
    }

    /// Put one call in the map under `id` with a serial already taken — the dial side takes it
    /// before building the opening future, because the task that will later clean up after that
    /// call has to be handed the serial it is cleaning up.
    pub(crate) fn insert(&self, id: u64, serial: u64, open: OpenCall) {
        self.outbound
            .lock()
            .unwrap()
            .insert(id, Call { serial, open });
    }

    /// The call registered under `id`, whichever one it is now. Reading without removing is
    /// something only the battery does: every path in the crate that looks a call up either opens
    /// one under the same lock or is ending it.
    #[cfg(test)]
    pub(crate) fn call(&self, id: u64) -> Option<OpenCall> {
        self.outbound
            .lock()
            .unwrap()
            .get(&id)
            .map(|c| c.open.clone())
    }

    /// End the call `serial` names, and only that one: an id whose entry now belongs to a later
    /// call is left alone. Returns the call, where the entry was still this one's.
    pub(crate) fn end_call(&self, id: u64, serial: u64) -> Option<OpenCall> {
        let mut open = self.outbound.lock().unwrap();
        match open.get(&id) {
            Some(call) if call.serial == serial => open.remove(&id).map(|c| c.open),
            _ => None,
        }
    }

    /// Take whatever call `id` holds now — what refusing one call does, since a refusal names the
    /// call the kernel is looking at, not one it holds a serial for.
    pub(crate) fn take_call(&self, id: u64) -> Option<OpenCall> {
        self.outbound.lock().unwrap().remove(&id).map(|c| c.open)
    }

    /// Every call open on this connection right now.
    pub(crate) fn all_calls(&self) -> Vec<OpenCall> {
        self.outbound
            .lock()
            .unwrap()
            .values()
            .map(|c| c.open.clone())
            .collect()
    }

    /// Remember how to stop the task driving this connection.
    pub(crate) fn arm_shutdown(&self, stop: tokio::sync::oneshot::Sender<()>) {
        *self.shutdown.lock().unwrap() = Some(stop);
    }

    /// Remember how to cut the stream this connection runs on.
    pub(crate) fn arm_cut(&self, cut: Arc<Cut>) {
        *self.cut.lock().unwrap() = Some(cut);
    }

    /// Ask that task to shut down, once. A connection already stopped stays stopped.
    ///
    /// Both seams fire: the accept side's graceful shutdown, where one was armed, and the cut on
    /// the stream a dialled connection runs on. A dialled connection has no graceful seam to fire —
    /// the driver holding its stream is one the HTTP/2 client spawned, and it ends only when every
    /// request sender is gone AND every call on it has finished, neither of which a close can
    /// promise about a peer that has stopped answering.
    pub(crate) fn stop(&self) {
        if let Some(stop) = self.shutdown.lock().unwrap().take() {
            let _ = stop.send(());
        }
        let cut = self.cut.lock().unwrap().take();
        if let Some(cut) = cut {
            cut.cut();
        }
    }

    /// Record one more served `:path`, evicting the oldest once [`SERVED_PATHS_CAP`] is reached —
    /// a connection open for a million calls remembers the last handful, not all of them.
    pub(crate) fn record_served_path(&self, path: String) {
        let mut served = self.served_paths.lock().unwrap();
        if served.len() >= SERVED_PATHS_CAP {
            served.pop_front();
        }
        served.push_back(path);
    }
}
