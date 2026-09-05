// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-connection side table. One [`ConnState`] stands for one HTTP/2 connection, which may
//! carry many concurrent gRPC calls ("multiplexed streams" in the architecture's ws row) — each
//! call is one [`busbar_contract::StreamId`], keyed in `outbound` below.

use std::collections::HashMap;
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

/// How many inbound frames one connection may hold for a `frames()` consumer that is not keeping
/// up — the per-unit frame buffer the architecture's backpressure rule names.
pub(crate) const INBOUND_FRAME_BUFFER: usize = 64;

/// One inbound item: a stream-tagged frame, or a transport failure on that stream.
pub(crate) type InboundItem = Result<(StreamId, Frame), TransportError>;

/// One open gRPC call's outbound half: the channel `write()` feeds and the RPC task drains.
pub(crate) type OutboundTx = mpsc::UnboundedSender<Vec<u8>>;

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

/// One connection's real state.
pub(crate) struct ConnState {
    /// Every stream's inbound frames land on this ONE channel, tagged with their `StreamId` — the
    /// multiplexing is the tag, not a separate channel per stream, so `frames()` can just drain it.
    pub(crate) inbound_tx: mpsc::Sender<InboundItem>,
    pub(crate) inbound_rx: AsyncMutex<Option<mpsc::Receiver<InboundItem>>>,
    /// One outbound channel per open stream (gRPC call). `write()` looks a stream up here; the
    /// task driving that RPC (accepted inbound, or opened by a dial-side `write` to a fresh
    /// `StreamId`) owns the receiving half and forwards each message onto the wire.
    pub(crate) outbound: SyncMutex<HashMap<u64, OpenCall>>,
    /// The dial-side connection, the origin URI, and the gRPC method every call it opens is
    /// dialled against — the method the destination named, so two destinations on one transport
    /// can name two different upstream methods.
    pub(crate) dialer: Option<(Arc<crate::client::Dialer>, http::Uri, &'static str)>,
    pub(crate) next_local_stream: std::sync::atomic::AtomicU64,
    /// The `:path` of every RPC served on this connection, in arrival order. gRPC names each call
    /// by a path, so this is what the transport actually answered on — recorded rather than
    /// assumed, because "the method a destination named is the method dialled" is otherwise a
    /// claim nothing checks.
    pub(crate) served_paths: SyncMutex<Vec<String>>,
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
            inbound_tx,
            inbound_rx: AsyncMutex::new(Some(inbound_rx)),
            outbound: SyncMutex::new(HashMap::new()),
            dialer,
            next_local_stream: std::sync::atomic::AtomicU64::new(1),
            served_paths: SyncMutex::new(Vec::new()),
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
        self.inbound_tx.send(item).await.map_err(|_| ())
    }
}
