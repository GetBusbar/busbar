// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-connection side table. [`busbar_contract_transport::wire::Conn`] is a sealed, opaque handle (only
//! `id()`/`peer()` are readable from outside), so the live split socket halves live here, keyed by
//! `Conn::id()`.

use std::sync::atomic::AtomicBool;

use busbar_contract::unit::ConfigView;
use busbar_contract::TransportConfigView;
use busbar_contract_transport::wire::ConnHandle;
use futures::stream::{SplitSink, SplitStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// The opaque handle the kernel is given. Carries identity only.
pub(crate) struct WsConnHandle {
    pub(crate) id: u64,
    pub(crate) peer: String,
}

impl ConnHandle for WsConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// The framed WebSocket socket, over whatever duplex the layer below handed up. The stream is
/// boxed rather than concrete because which carrier is under it — a plain socket, a TLS one, an
/// in-memory pair — is the lower layer'''s business and never this one'''s.
pub(crate) trait LowerIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> LowerIo for T {}

pub(crate) type Sock = WebSocketStream<Box<dyn LowerIo>>;

/// What the layer below knew about this connection when it gave the stream up.
///
/// An upgrade replaces the layer an arrival record describes; it does not delete what the layers
/// underneath already established. The port the bytes arrived on, the name offered at the TLS
/// handshake, the protocol negotiated there and the certificate the peer presented are all facts
/// about THIS connection that no later layer can re-derive — the `tls` layer has given the stream
/// up and will never be asked again. `ws` declares Sni, Alpn and Port selector forms, so a record
/// that answered zero and `None` to all of them made every location resolving on those forms
/// unresolvable against a connection that genuinely had them.
#[derive(Clone, Debug, Default)]
pub(crate) struct LowerFacts {
    pub(crate) port: u16,
    pub(crate) alpn: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) peer_cert: Option<busbar_contract_transport::wire::CertFacts>,
}

impl LowerFacts {
    /// The facts worth keeping out of the record the layer below reported.
    pub(crate) fn of(record: &busbar_contract_transport::wire::ArrivalRecord) -> Self {
        Self {
            port: record.port,
            alpn: record.alpn.clone(),
            sni: record.sni.clone(),
            peer_cert: record.peer_cert.clone(),
        }
    }
}

/// One connection's real state: the split socket halves behind the single write lock every
/// outbound frame passes through, plus the poison fence for a write that never completed cleanly.
pub(crate) struct ConnState {
    pub(crate) reader: AsyncMutex<Option<SplitStream<Sock>>>,
    pub(crate) writer: AsyncMutex<SplitSink<Sock, Message>>,
    pub(crate) poisoned: AtomicBool,
    /// Set by `close`, before anything is spawned. The frame pump holds its own handle on this
    /// state, so removing the connection from the registry does not reach a pump already suspended
    /// in a read: this is the fence that does, and it is what makes a close the end of the session
    /// for the read side too rather than only for the registry.
    pub(crate) closed: AtomicBool,
    /// The composed stack this connection stands on, bottom layer first, ending in `ws`. It is what
    /// the layer below reported plus this one, carried across the handoff — a connection that named
    /// only itself was one a location could not resolve against.
    pub(crate) chain: Vec<&'static str>,
    /// What the layer below reported about this connection, carried across the handoff.
    pub(crate) lower: LowerFacts,
}

impl ConnState {
    pub(crate) fn new(
        sock: Sock,
        chain: Vec<&'static str>,
        lower: LowerFacts,
    ) -> std::sync::Arc<Self> {
        use futures::StreamExt;
        let (writer, reader) = sock.split();
        std::sync::Arc::new(Self {
            reader: AsyncMutex::new(Some(reader)),
            writer: AsyncMutex::new(writer),
            poisoned: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            chain,
            lower,
        })
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// A trivial config view: `bind` is the only field this transport reads (the address to `listen`
/// on); everything else answers `None`/`false`.
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
