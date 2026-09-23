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
    TransportMeta,
};
use futures::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{deliver_refusal, TcpListenerHandle, TcpTransport};

impl Transport for TcpTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let port = self.inner(conn.id()).map_or(0, |i| i.local_port);
        ArrivalRecord {
            source: conn.peer(),
            port,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["tcp"],
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
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
                .expect("listener registry poisoned")
                .insert(addr.clone(), Arc::new(listener));
            Ok(Listener::new(Arc::new(TcpListenerHandle { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let addr = l.local_addr();
            let listener = self
                .listeners
                .lock()
                .expect("listener registry poisoned")
                .get(&addr)
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (stream, peer) = listener.accept().await.map_err(|e| Self::map_io_err(&e))?;
            self.register(stream, peer)
                .map_err(|e| Self::map_io_err(&e))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let authority = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { address, .. } => {
                    address.authority().ok_or(TransportError::AddressRefused)?
                }
                _ => return Err(TransportError::AddressRefused),
            };
            let addr: SocketAddr = authority
                .parse()
                .map_err(|_| TransportError::AddressRefused)?;
            // Bounded: a `connect` to an upstream that never answers the SYN would otherwise pin
            // this task and the half-open socket for the OS's own multi-minute retransmit window.
            // A budget that elapses is a `Timeout`, the same fact the io layer reports when it is
            // the one that gives up first — the caller reads one outcome for "the upstream did not
            // answer in time" however that verdict was reached.
            let stream =
                match tokio::time::timeout(self.dial_timeout, TcpStream::connect(addr)).await {
                    Ok(result) => result.map_err(|e| Self::map_io_err(&e))?,
                    Err(_) => return Err(TransportError::Timeout),
                };
            self.register(stream, addr)
                .map_err(|e| Self::map_io_err(&e))
        })
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        // The pump is `'static`: it cannot borrow `self`, so it holds its own clone of the registry
        // and the connection id, which is all it needs to deregister itself on a read error the way
        // `close` deregisters on a finalise.
        let conns = Arc::clone(&self.conns);
        let id = conn.id();
        Box::pin(futures::stream::unfold(inner, move |inner| {
            let conns = Arc::clone(&conns);
            async move {
                let inner = inner?;
                if inner.closed.load(Ordering::Acquire) {
                    return None;
                }
                let mut guard = inner.read.lock().await;
                let side = &mut *guard;
                // Arm the wait BEFORE re-reading the flag: a close that lands between the two is
                // seen as the flag, and one that lands after it is seen as the notification. Neither
                // order leaves this parked.
                let mut closing = std::pin::pin!(inner.closing.notified());
                closing.as_mut().enable();
                if inner.closed.load(Ordering::Acquire) {
                    return None;
                }
                let reading = std::pin::pin!(side.half.read(&mut side.scratch));
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
                        // The next state is a fresh clone of the handle rather than a move of
                        // `inner`: the `closing` future above borrows `inner` and, because
                        // `Notified` has a real `Drop`, that borrow lives to the end of this block —
                        // moving `inner` out here would collide with it. An `Arc` bump is cheaper
                        // than the per-frame `Box::pin` this arm's wait no longer needs.
                        Some((Ok((StreamId(0), frame)), Some(Arc::clone(&inner))))
                    }
                    Err(e) => {
                        drop(guard);
                        // A read error is the connection's end, not just this frame's. Deregister
                        // and finalise it the way `close` does — otherwise the registry entry (and
                        // the fd, the scratch and both halves it pins) leaks for the life of the
                        // process, which under an RST flood that never reaches the clean-EOF path is
                        // one leaked connection per reset.
                        if let Some(removed) =
                            conns.lock().expect("conn registry poisoned").remove(&id)
                        {
                            removed.finalise();
                        }
                        Some((Err(TcpTransport::map_io_err(&e)), None))
                    }
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
            // Raced against the connection's close: a peer that stops reading fills the send buffer
            // and would block `write_all` until it drains — which, for a peer that never reads, is
            // never. `close` must be able to interrupt that, or the connection it means to shed
            // leaks instead. The happy-path bytes are unchanged: this is the caller's own write when
            // it wins the race.
            let write = async {
                guard
                    .write_all(bytes.as_slice())
                    .await
                    .map_err(|e| Self::map_io_err(&e))?;
                guard.flush().await.map_err(|e| Self::map_io_err(&e))
            };
            Self::raced_write(&inner, write).await?;
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

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        conn: Conn,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // Nothing composes over `tcp` by being adopted onto it: `tcp` IS the bottom, so there is no
        // lower layer whose stream it could take. It only ever hands one up, through `detach`.
        let _ = conn;
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract::transport::wire::RawStream> {
        let (stream, peer) = self.take_stream(conn)?;
        Some(busbar_contract::transport::wire::RawStream::new(
            Self::KEY,
            peer.to_string(),
            Box::new(TokioAsyncReadCompatExt::compat(stream)),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        // `tcp` IS the bottom: it opens its own socket and nothing built it over a lower layer.
        None
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        // Dropping the halves closes the socket (sends FIN); nothing here is fallible in a way
        // the caller can act on, so this stays synchronous per the trait's own shape. A frame
        // stream holds its own clone of the state, so removing the registry entry is not enough
        // to drop the halves: the flag is what ends that stream at its next poll, after which the
        // last clone goes and the socket really does close.
        let inner = self
            .conns
            .lock()
            .expect("conn registry poisoned")
            .remove(&conn.id());
        if let Some(inner) = inner {
            inner.finalise();
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        // `tcp` carries one stream, so there is nothing narrower than the connection to refuse on.
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let delivered = {
                let mut guard = inner.write.lock().await;
                // Raced against the close, the same as the ordinary write path: the refusal is meant
                // to SHED a bad connection, so a peer that has stopped reading must not be able to
                // block its delivery forever and pin the very connection the refusal is ending. When
                // the close wins, the bytes are gone and the connection is finalised below anyway.
                Self::raced_write(&inner, deliver_refusal(&mut *guard, bytes.as_slice())).await
            };
            // A refusal finalises the connection, so it ends it the way `close` does: dropping the
            // registry's clone is not enough, because a frame stream that started before the
            // refusal holds its own clone and would stay parked on the socket forever. The flag is
            // what ends that stream, after which the last clone goes and the socket really closes.
            //
            // This runs on every path out, delivered or not. A refusal whose bytes never reached
            // the peer is still a finalised connection — returning the write's error first would
            // leave the entry registered and that pump parked, which is the leak this ends, on the
            // one path where the peer is already gone.
            let removed = self
                .conns
                .lock()
                .expect("conn registry poisoned")
                .remove(&conn.id());
            if let Some(removed) = removed {
                removed.finalise();
            }
            delivered
        })
    }
}
