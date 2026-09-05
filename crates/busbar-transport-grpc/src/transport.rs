// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::Stream;
use tokio::net::TcpListener as TokioTcpListener;

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::unit::Refusal;
use busbar_contract::wire::{
    ArrivalRecord, CloseReason, Conn, Frame, Listener, ListenerHandle, TransportError,
    Unit0Trigger,
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
pub struct GrpcTransport {
    next_id: AtomicU64,
    conns: SyncMutex<HashMap<u64, Arc<ConnState>>>,
    listeners: SyncMutex<HashMap<String, Arc<TokioTcpListener>>>,
}

impl Default for GrpcTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcTransport {
    /// A fresh transport instance with no live connections.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            listeners: SyncMutex::new(HashMap::new()),
        }
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
    // See `busbar-transport-ws`'s identical note: grpc is the top transport of its stack (over
    // `http`) and therefore the one that would own claim selection over the request that opens
    // each call, including its `:path`.
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
    const COMPOSES_OVER: &'static [&'static str] = &["http"];
    const HANDOFF: Option<busbar_contract::wire::Handoff> = None;
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
            // See the crate's own report: the real stack is `tcp`/`tls`/`http`/`grpc`, and this
            // crate only ever sees the already-established HTTP/2 connection it built itself.
            transport_chain: vec!["grpc"],
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
            let addr = cfg.bind().ok_or(TransportError::AddressRefused)?;
            let listener = TokioTcpListener::bind(addr)
                .await
                .map_err(|_| TransportError::AddressRefused)?;
            let local = listener
                .local_addr()
                .map_err(|_| TransportError::AddressRefused)?
                .to_string();
            self.listeners
                .lock()
                .unwrap()
                .insert(local.clone(), Arc::new(listener));
            Ok(Listener::new(Arc::new(GrpcListenerHandle { addr: local })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let listener = self
                .listeners
                .lock()
                .unwrap()
                .get(&l.local_addr())
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (tcp, peer) = listener.accept().await.map_err(|_| TransportError::Closed)?;
            let id = self.mint_id();
            let state = ConnState::new(None);
            self.conns.lock().unwrap().insert(id, state.clone());
            crate::server::serve_connection(tcp, state);
            Ok(Conn::new(Arc::new(GrpcConnHandle {
                id,
                peer: peer.to_string(),
            })))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let DestinationFacts::Upstream { host, .. } = dest.facts() else {
                return Err(TransportError::AddressRefused);
            };
            let (host_name, port) = host
                .rsplit_once(':')
                .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_string(), p)))
                .ok_or(TransportError::AddressRefused)?;
            let (dialer, origin) = client::dial_h2(&host_name, port).await?;
            let id = self.mint_id();
            let state = ConnState::new(Some((Arc::new(dialer), origin)));
            self.conns.lock().unwrap().insert(id, state);
            Ok(Conn::new(Arc::new(GrpcConnHandle {
                id,
                peer: host.to_string(),
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
                    let Some((dialer, origin)) = state.dialer.clone() else {
                        return Err(TransportError::Framing);
                    };
                    let tx =
                        client::open_stream(state.clone(), (*dialer).clone(), origin, stream)
                            .await?;
                    state.outbound.lock().unwrap().insert(stream.0, tx.clone());
                    tx
                }
            };
            tx.send(payload).map_err(|_| TransportError::Reset)?;
            Ok(n)
        })
    }

    fn upgrade<'a>(
        &'a self,
        _conn: Conn,
        _to: &'a str,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move { Err(TransportError::Framing) })
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

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            // AMBIGUITY (see the crate's own report): `unit0_refusal` takes a whole `Conn`, but on
            // this transport `Unit0Trigger::FirstMessage` opens a session PER STREAM on a
            // connection that may carry several. The contract gives no stream to target, so this
            // best-effort broadcasts the refusal onto every stream currently open on the
            // connection, then closes the whole connection — safe (nothing is left half-served)
            // but almost certainly wider than a real deployment wants.
            let id = conn.id();
            if let Some(state) = self.state_of(id) {
                let payload = bytes.as_slice().to_vec();
                let senders: Vec<_> = state.outbound.lock().unwrap().values().cloned().collect();
                for tx in senders {
                    let _ = tx.send(payload.clone());
                }
            }
            self.close(conn, CloseReason::Normal);
            Ok(())
        })
    }
}

struct GrpcListenerHandle {
    addr: String,
}

impl ListenerHandle for GrpcListenerHandle {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}
