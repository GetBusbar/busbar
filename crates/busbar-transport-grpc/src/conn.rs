// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-connection side table. One [`ConnState`] stands for one HTTP/2 connection, which may
//! carry many concurrent gRPC calls ("multiplexed streams" in the architecture's ws row) — each
//! call is one [`busbar_contract::StreamId`], keyed in `outbound` below.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as SyncMutex};

use busbar_contract::unit::ConfigView;
use busbar_contract::wire::{ConnHandle, Frame, TransportError};
use busbar_contract::{StreamId, TransportConfigView};
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

/// One inbound item: a stream-tagged frame, or a transport failure on that stream.
pub(crate) type InboundItem = Result<(StreamId, Frame), TransportError>;

/// One connection's real state.
pub(crate) struct ConnState {
    /// Every stream's inbound frames land on this ONE channel, tagged with their `StreamId` — the
    /// multiplexing is the tag, not a separate channel per stream, so `frames()` can just drain it.
    pub(crate) inbound_tx: mpsc::UnboundedSender<InboundItem>,
    pub(crate) inbound_rx: AsyncMutex<Option<mpsc::UnboundedReceiver<InboundItem>>>,
    /// One outbound channel per open stream (gRPC call). `write()` looks a stream up here; the
    /// task driving that RPC (accepted inbound, or opened by a dial-side `write` to a fresh
    /// `StreamId`) owns the receiving half and forwards each message onto the wire.
    pub(crate) outbound: SyncMutex<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>,
    /// The dial-side connection this Conn rides on, plus the origin URI (scheme + authority) every
    /// call it opens needs, so `write()` can lazily open a new RPC for a `StreamId` it has not
    /// seen before. `None` for an accepted (server-side) connection, whose streams are opened by
    /// the PEER — see the crate's own report on this asymmetry.
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
}

impl ConnState {
    pub(crate) fn new(
        dialer: Option<(Arc<crate::client::Dialer>, http::Uri, &'static str)>,
    ) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            inbound_tx,
            inbound_rx: AsyncMutex::new(Some(inbound_rx)),
            outbound: SyncMutex::new(HashMap::new()),
            dialer,
            next_local_stream: std::sync::atomic::AtomicU64::new(1),
            served_paths: SyncMutex::new(Vec::new()),
        })
    }
}

/// A trivial config view: `bind` is the only field this transport reads.
#[derive(Debug, Clone)]
pub struct StaticConfig {
    bind: Option<String>,
}

impl StaticConfig {
    /// A config naming one bind address.
    #[must_use]
    pub fn bind_to(addr: impl Into<String>) -> Self {
        Self {
            bind: Some(addr.into()),
        }
    }
}

impl ConfigView for StaticConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for StaticConfig {
    fn bind(&self) -> Option<&str> {
        self.bind.as_deref()
    }
}
