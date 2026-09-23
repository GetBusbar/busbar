// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use busbar_contract::transport::wire::ArrivalRecord;
use busbar_contract::transport::wire::CloseReason;
use busbar_contract::transport::wire::Conn;
use busbar_contract::transport::wire::Direction;
use busbar_contract::transport::wire::FrameMeta;
use busbar_contract::transport::wire::Listener;
use busbar_contract::transport::wire::TransportError;
use busbar_contract::{
    Frame, Fut, Refusal, ScratchBytes, SlabBytes, StreamId, Transport, TransportConfigView,
    TransportKeyHandle, TransportMeta,
};
use futures::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use rustls_pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    deliver_refusal, send_close_notify, shut_down_session, split_address, BoxedIo, InnerRead,
    InnerWrite, TlsListenerHandle, TlsTransport,
};

impl Transport for TlsTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let inner = self.inner(conn.id());
        ArrivalRecord {
            source: conn.peer(),
            port: inner.as_ref().map_or(0, |i| i.local_port),
            alpn: inner.as_ref().and_then(|i| i.alpn.clone()),
            sni: inner.as_ref().and_then(|i| i.sni.clone()),
            peer_cert: inner.as_ref().and_then(|i| i.peer_cert.clone()),
            transport_chain: inner
                .as_ref()
                .map_or_else(|| vec!["tcp", "tls"], |i| i.chain.clone()),
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
            let server_cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&keys.slot())
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            let bind = cfg.bind().unwrap_or("127.0.0.1:0");
            let listener = TcpListener::bind(bind)
                .await
                .map_err(|_| TransportError::AddressRefused)?;
            let addr = listener
                .local_addr()
                .map_err(|_| TransportError::AddressRefused)?
                .to_string();
            self.listeners
                .lock()
                .expect("poisoned")
                .insert(addr.clone(), (Arc::new(listener), keys.slot()));
            let _ = server_cfg; // resolved once here to fail fast; re-resolved per-accept by slot
            Ok(Listener::new(Arc::new(TlsListenerHandle { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let addr = l.local_addr();
            let (listener, slot) = self
                .listeners
                .lock()
                .expect("poisoned")
                .get(&addr)
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|_| TransportError::Closed)?;
            stream.set_nodelay(true).ok();
            let local_port = stream.local_addr().map_or(0, |a| a.port());
            // Every accepted connection on this listener uses the config registered for the slot
            // this listener was provisioned with in `listen` — not a fixed slot of accept's own —
            // because the listener has no per-connection SNI to route on before the handshake
            // completes. A deployment that needs SNI-routed certs resolves that at the
            // transport-key unit, not here.
            let cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&slot)
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            let acceptor = TlsAcceptor::from(cfg);
            // The handshake runs inline, so it is also this accept loop's exposure: a peer that
            // completes the TCP connection and then says nothing costs itself nothing and holds the
            // listener indefinitely. The budget ends that — on expiry the future is dropped, and
            // with it the half-open stream, and the loop is free for the next caller.
            let tls_stream = tokio::time::timeout(
                self.handshake_timeout,
                acceptor.accept(Box::new(stream) as BoxedIo),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer, vec!["tcp", "tls"], local_port))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let address = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { address, .. } => address,
                _ => return Err(TransportError::AddressRefused),
            };
            let (name, addr) = split_address(&address)?;
            let cfg = self
                .client_configs
                .lock()
                .expect("poisoned")
                .get(&keys.slot())
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            // The same budget the handshake below runs under, on the leg BEFORE it: the doc on
            // `HANDSHAKE_TIMEOUT` says the two ends of this crate's tolerance for a peer that will
            // not talk are one number, and an unbounded connect here left that untrue — an upstream
            // that never answered the SYN held the dial task and its half-open socket for as long
            // as the operating system did.
            let stream = tokio::time::timeout(self.handshake_timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|e| Self::map_io_err(&e))?;
            stream.set_nodelay(true).ok();
            let local_port = stream.local_addr().map_or(0, |a| a.port());
            let connector = TlsConnector::from(cfg);
            let server_name = ServerName::try_from(name)
                .map_err(|_| TransportError::AddressRefused)?
                .to_owned();
            // Bounded for the same reason `accept`/`adopt` are: the TCP connect above proves the
            // far side answered a SYN, not that it will ever send a ServerHello. A stalled or
            // hostile upstream that completes the handshake's transport leg and then goes silent
            // would otherwise park this dial task — and the socket it holds — for the life of the
            // process. On expiry the future is dropped, the IO drops with it, and the caller sees
            // the same `Timeout` the inbound side reports for a handshake that never progressed.
            let tls_stream = tokio::time::timeout(
                self.handshake_timeout,
                connector.connect(server_name, Box::new(stream) as BoxedIo),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_client(tls_stream, addr, vec!["tcp", "tls"], local_port))
        })
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        Box::pin(futures::stream::unfold(inner, move |inner| async move {
            let inner = inner?;
            if inner.closed.load(Ordering::Acquire) {
                return None;
            }
            let mut guard = inner.read.lock().await;
            let side = &mut *guard;
            // Arm the wait BEFORE re-reading the flag: a close that lands between the two is seen
            // as the flag, and one that lands after it is seen as the notification. Neither order
            // leaves this parked.
            let mut closing = Box::pin(inner.closing.notified());
            closing.as_mut().enable();
            if inner.closed.load(Ordering::Acquire) {
                return None;
            }
            let reading = std::pin::pin!(async {
                match &mut side.half {
                    InnerRead::Server(r) => r.read(&mut side.scratch).await,
                    InnerRead::Client(r) => r.read(&mut side.scratch).await,
                }
            });
            let result = match futures::future::select(reading, closing).await {
                futures::future::Either::Left((r, _)) => r,
                // The close won: the read is dropped where it stood and the stream ends.
                futures::future::Either::Right(((), _)) => return None,
            };
            match result {
                Ok(0) => None,
                Ok(n) => {
                    // Copied out to exactly this frame's length; the scratch keeps whatever the
                    // read left in it, which nothing else ever looks at.
                    let bytes: Arc<[u8]> = Arc::from(&side.scratch[..n]);
                    drop(guard);
                    let frame = Frame {
                        direction: Direction::Inbound,
                        stream: StreamId(0),
                        bytes: SlabBytes::new(bytes),
                        meta: FrameMeta {
                            bytes: n as u64,
                            transport_units: None,
                            status: None,
                            status_code: None,
                            retry_after_secs: None,
                        },
                    };
                    Some((Ok((StreamId(0), frame)), Some(inner)))
                }
                Err(e) => {
                    drop(guard);
                    // Post-handshake read: an `InvalidData` here is a bad record on a live session,
                    // not a handshake that never completed.
                    Some((Err(TlsTransport::map_session_err(&e)), None))
                }
            }
        }))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let mut guard = inner.write.lock().await;
            match &mut *guard {
                InnerWrite::Server(w) => {
                    w.write_all(bytes.as_slice())
                        .await
                        .map_err(|e| Self::map_session_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_session_err(&e))?;
                }
                InnerWrite::Client(w) => {
                    w.write_all(bytes.as_slice())
                        .await
                        .map_err(|e| Self::map_session_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_session_err(&e))?;
                }
            }
            Ok(bytes.len())
        })
    }

    /// A byte stream carries no envelope of its own: the bytes are the body, and a field written
    /// beside them would be bytes the peer never asked for. A transport that named one anyway would
    /// be inventing a framing this wire does not have.
    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, busbar_contract::transport::wire::Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| busbar_contract::transport::wire::Encode::ScratchExhausted)
    }

    /// The in-band upgrade, from this side: the STARTTLS-shaped handoff the transports table names.
    ///
    /// `tcp` gives up its stream and `tls` takes it, and the connection that comes out is one this
    /// transport's own registry holds — which is precisely what the source could never have
    /// returned. The facts of the new layer are derived from the completed handshake and nothing
    /// is carried over from the layer below: after this returns, the source knows nothing about the
    /// connection and this transport knows everything.
    fn adopt<'a>(
        &'a self,
        from: &'a dyn Transport,
        conn: Conn,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            if !Self::COMPOSES_OVER.contains(&from.key()) {
                return Err(TransportError::HandoffMismatch);
            }
            // Read before the stream is taken: once the source has given the connection up it
            // knows nothing about it, and the port the bytes arrived on is the lower layer's to
            // report — this transport never opened that socket.
            let below = from.arrival(&conn);
            let mut chain = below.transport_chain;
            let local_port = below.port;
            let raw = from.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            chain.push(Self::KEY);
            let peer: SocketAddr = raw
                .peer()
                .parse()
                .map_err(|_| TransportError::HandoffMismatch)?;
            let stream: BoxedIo = Box::new(FuturesAsyncReadCompatExt::compat(raw.into_io()));
            let cfg = self
                .server_configs
                .lock()
                .expect("poisoned")
                .get(&keys.slot())
                .cloned()
                .ok_or(TransportError::KeyUnavailable)?;
            // Same budget as `accept`, for the same reason: the peer whose stream was just handed
            // up is under no obligation to send a ClientHello, and this await is otherwise unbounded.
            let tls_stream = tokio::time::timeout(
                self.handshake_timeout,
                TlsAcceptor::from(cfg).accept(stream),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::HandshakeFailed)?;
            Ok(self.insert_server(tls_stream, peer, chain, local_port))
        })
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract::transport::wire::RawStream> {
        // Checked BEFORE the removal, under the same lock: see the sibling `tcp` note. Removing
        // first and then failing to unwrap loses the connection — no stream up, no entry left.
        let mut registry = self.conns.lock().expect("poisoned");
        if Arc::strong_count(registry.get(&conn.id())?) != 1 {
            return None;
        }
        let inner = registry.remove(&conn.id())?;
        drop(registry);
        let peer = conn.peer();
        let inner = Arc::try_unwrap(inner).ok()?;
        let stream: BoxedIo = match (inner.read.into_inner().half, inner.write.into_inner()) {
            (InnerRead::Server(r), InnerWrite::Server(w)) => Box::new(r.unsplit(w)),
            (InnerRead::Client(r), InnerWrite::Client(w)) => Box::new(r.unsplit(w)),
            // The halves of one connection are always the same side; a mismatch would mean the
            // registry had been torn, and there is no stream to hand up in that case.
            _ => return None,
        };
        Some(busbar_contract::transport::wire::RawStream::new(
            Self::KEY,
            peer,
            Box::new(TokioAsyncReadCompatExt::compat(stream)),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        // `tls` opens its own socket at `listen`/`dial` (a direct TLS listener over the raw TCP it
        // binds itself); the STARTTLS handoff `adopt` answers is a per-connection upgrade, not a
        // property of this instance, so there is no lower-layer instance to name here.
        None
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        // A frame stream holds its own clone of the state, so removing the registry entry is not
        // enough to drop the TLS stream: the flag is what ends that stream at its next poll, after
        // which the last clone goes and the socket really does close.
        let inner = self.conns.lock().expect("poisoned").remove(&conn.id());
        if let Some(inner) = inner {
            inner.finalise();
            shut_down_session(inner);
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        // `tls` inherits `tcp`'s single stream; the connection is the whole of what can be refused.
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let delivered = {
                let mut guard = inner.write.lock().await;
                match &mut *guard {
                    InnerWrite::Server(w) => deliver_refusal(w, bytes.as_slice()).await,
                    InnerWrite::Client(w) => deliver_refusal(w, bytes.as_slice()).await,
                }
            };
            // A refusal finalises the connection, so it ends it the way `close` does: dropping the
            // registry's clone is not enough, because a frame stream that started before the
            // refusal holds its own clone and would stay parked on the socket forever, keeping the
            // rustls session alive with it. The flag is what ends that stream, after which the last
            // clone goes and the session and its socket really close.
            //
            // This runs on every path out, delivered or not. A refusal whose bytes never reached
            // the peer is still a finalised connection — returning the write's error first would
            // leave the entry registered and that pump parked, which is the leak this ends, on the
            // one path where the peer is already gone.
            let removed = self.conns.lock().expect("poisoned").remove(&conn.id());
            if let Some(removed) = removed {
                removed.finalise();
                // Inline here: this path is already async, so the alert goes out before the refusal
                // reports done rather than on a task the caller cannot wait for.
                send_close_notify(&removed).await;
            }
            delivered
        })
    }
}
