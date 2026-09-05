// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::Stream;

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::unit::Refusal;
use busbar_contract::wire::{
    ArrivalRecord, CloseReason, Conn, Frame, Listener, TransportError, Unit0Trigger,
};
use busbar_contract::{
    grammar::SelectorForm, AbiVersion, ArenaBytes, Fut, Kind, Plugin, StreamId, Transport,
    TransportConfigView, TransportKeyHandle, TransportMeta,
};

use crate::client;
use crate::conn::{ConnState, GrpcConnHandle};

type FrameStream = std::pin::Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// The gRPC transport: unary and multiplexed streams over HTTP/2, byte-blind. In-tree, inside the
/// trusted computing base — see the architecture doc's transport and transports-table sections.
///
/// It opens no socket of its own. The layer it composes over binds, accepts and dials, and this one
/// drives HTTP/2 over the stream that layer gives up — so the composed chain is real rather than
/// declared, and the network guard sits in front of the dial for the whole stack at once.
pub struct GrpcTransport {
    next_id: AtomicU64,
    conns: SyncMutex<HashMap<u64, Arc<ConnState>>>,
    /// The layer this one composes over. `None` for an instance that will only ever be handed a
    /// stream directly, which is all a transport owning no socket can otherwise do.
    lower: Option<Arc<dyn Transport>>,
}

impl Default for GrpcTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcTransport {
    /// A transport with no layer under it. `listen`, `accept` and `dial` all need one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            lower: None,
        }
    }

    /// A transport composed over `lower` — the layer that binds, accepts and dials for it.
    #[must_use]
    pub fn over(lower: Arc<dyn Transport>) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            lower: Some(lower),
        }
    }

    fn lower(&self) -> Result<&Arc<dyn Transport>, TransportError> {
        self.lower.as_ref().ok_or(TransportError::HandoffMismatch)
    }

    /// Take the stream out of a connection the layer below owns, with the chain it stood on.
    fn take(
        &self,
        lower: &Arc<dyn Transport>,
        conn: &Conn,
    ) -> Result<(crate::conn::LowerIo, Vec<&'static str>), TransportError> {
        let mut chain = lower.arrival(conn).transport_chain;
        let raw = lower.detach(conn).ok_or(TransportError::HandoffMismatch)?;
        chain.push(<Self as TransportMeta>::KEY);
        let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(raw.into_io());
        Ok((Box::new(stream), chain))
    }

    fn mint_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn state_of(&self, id: u64) -> Option<Arc<ConnState>> {
        self.conns.lock().unwrap().get(&id).cloned()
    }
}

impl Plugin for GrpcTransport {
    fn key(&self) -> &'static str {
        <Self as TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

impl TransportMeta for GrpcTransport {
    const KEY: &'static str = "grpc";
    // See `busbar-transport-ws`'s identical note: grpc is the top transport of its stack and
    // therefore the one that owns claim selection over the request that opens each call, including
    // its `:path`.
    const SELECTOR_FORMS: &'static [SelectorForm] = &[
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::PathPattern,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::Sni,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[];
    // The layers this one is actually built over, and the Cargo edges say the same: `http`
    // carries an inbound connection, `tcp` carries a dialled one.
    const COMPOSES_OVER: &'static [&'static str] = &["http", "tcp"];
    const HANDOFF: Option<busbar_contract::wire::Handoff> = None;
    const FRAMING: busbar_contract::Framing = busbar_contract::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstMessage);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    // "carries the per-frame StatusClass at Terminal (the grpc-status trailer)" — the transports
    // table's own words for this row.
    const STATUS_CLASS: Option<busbar_contract::wire::StatusAt> =
        Some(busbar_contract::wire::StatusAt::Terminal);
}

impl Transport for GrpcTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            // The chain the layer below reported, plus this one.
            transport_chain: self
                .state_of(conn.id())
                .map_or_else(|| vec!["grpc"], |s| s.chain.clone()),
        }
    }

    /// The listener is the layer below's. This transport binds nothing.
    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move { self.lower()?.listen(cfg, keys).await })
    }

    /// Take the next connection off the layer below and serve HTTP/2 over the stream it gives up.
    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let lower = self.lower()?;
            let conn = lower.accept(l).await?;
            let peer = conn.peer();
            let (stream, chain) = self.take(lower, &conn)?;
            let id = self.mint_id();
            let state = ConnState::new(None, chain);
            self.conns.lock().unwrap().insert(id, state.clone());
            crate::server::serve_connection(stream, state);
            Ok(Conn::new(Arc::new(GrpcConnHandle { id, peer })))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let DestinationFacts::Upstream { address, .. } = dest.facts() else {
                return Err(TransportError::AddressRefused);
            };
            let authority = address
                .authority()
                .ok_or(TransportError::AddressRefused)?;
            // The method the destination names is the `:path` every call this connection opens is
            // dialled against. A destination that names none falls back to this crate's own frame
            // method, which is the only path a byte-blind transport can serve on its own.
            let method = address.method().unwrap_or(crate::server::RPC_PATH);
            // The socket is the layer below's, dialled against the address this destination
            // already carries. Re-addressing narrows the sealed destination to what that layer
            // reads; it does not re-seal it, and it cannot widen where the unit may go.
            let lower = self.lower()?;
            let beneath = dest
                .beneath(
                    lower.key(),
                    busbar_contract::UpstreamAddress::Socket {
                        authority,
                        sni: address.sni(),
                    },
                )
                .ok_or(TransportError::AddressRefused)?;
            let conn = lower.dial(&beneath, keys).await?;
            let (stream, chain) = self.take(lower, &conn)?;
            let (dialer, origin) = client::handshake_h2(stream, authority).await?;
            let id = self.mint_id();
            let state = ConnState::new(Some((Arc::new(dialer), origin, method)), chain);
            self.conns.lock().unwrap().insert(id, state);
            Ok(Conn::new(Arc::new(GrpcConnHandle {
                id,
                peer: authority.to_string(),
            })))
        })
    }

    fn frames(&self, conn: Conn) -> FrameStream {
        let id = conn.id();
        let Some(state) = self.state_of(id) else {
            return Box::pin(futures::stream::once(async {
                Err::<(StreamId, Frame), TransportError>(TransportError::Closed)
            }));
        };
        Box::pin(futures::stream::unfold(state, move |state| async move {
            let mut guard = state.inbound_rx.lock().await;
            let rx = guard.as_mut()?;
            let item = rx.recv().await;
            drop(guard);
            item.map(|item| (item, state))
        }))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        let id = conn.id();
        Box::pin(async move {
            let Some(state) = self.state_of(id) else {
                return Err(TransportError::Closed);
            };
            let payload = bytes.as_slice().to_vec();
            let n = payload.len();
            let existing = state.outbound.lock().unwrap().get(&stream.0).cloned();
            let tx = match existing {
                Some(tx) => tx,
                None => {
                    // A fresh `StreamId` this connection has not seen: on the DIAL side, that
                    // OPENS a new gRPC call. An accepted (server) connection cannot originate a
                    // call — its streams are opened by the peer — so an unseen id there is a
                    // caller error, not something this transport can serve.
                    let Some((dialer, origin, method)) = state.dialer.clone() else {
                        return Err(TransportError::Framing);
                    };
                    let tx = client::open_stream(
                        state.clone(),
                        (*dialer).clone(),
                        origin,
                        method,
                        stream,
                    )
                    .await?;
                    state.outbound.lock().unwrap().insert(stream.0, tx.clone());
                    tx
                }
            };
            tx.send(payload).map_err(|_| TransportError::Reset)?;
            Ok(n)
        })
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        let id = conn.id();
        if let Some(state) = self.conns.lock().unwrap().remove(&id) {
            // Explicitly drop every outbound sender rather than rely on the `Arc<ConnState>`'s
            // refcount reaching zero: a `forward_inbound` task reading the OTHER direction of one
            // of this connection's calls holds its own clone of `state` for as long as that
            // direction stays open (e.g. a peer that never half-closes its own send side), so the
            // map entry disappearing here would otherwise never actually end any call's response
            // stream. Clearing the map ends each open call's outbound stream (and so its
            // `grpc-status` trailer) immediately, independent of what the other direction is
            // doing.
            state.outbound.lock().unwrap().clear();
        }
    }

    /// Refuse one call, or the whole connection where the caller names no call.
    ///
    /// `Unit0Trigger::FirstMessage` opens a session PER STREAM here, on a connection that may be
    /// carrying several at once. A refusal of request *n* is therefore about request *n*: its
    /// outbound stream is written and ended, and *n±1* go on to complete on the same connection,
    /// untouched. Only a refusal that names no stream is about the connection, and that one closes
    /// it — which is what a transport with a single stream would have meant all along.
    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let id = conn.id();
            let Some(state) = self.state_of(id) else {
                return Ok(());
            };
            let payload = bytes.as_slice().to_vec();
            match stream {
                Some(stream) => {
                    // Remove the sender as well as writing to it: dropping it is what ends this
                    // call's response stream (and so emits its `grpc-status` trailer), which is the
                    // difference between refusing one call and leaving it half-served.
                    let tx = state.outbound.lock().unwrap().remove(&stream.0);
                    if let Some(tx) = tx {
                        let _ = tx.send(payload);
                    }
                }
                None => {
                    let senders: Vec<_> =
                        state.outbound.lock().unwrap().values().cloned().collect();
                    for tx in senders {
                        let _ = tx.send(payload.clone());
                    }
                    self.close(conn, CloseReason::Normal);
                }
            }
            Ok(())
        })
    }
}


