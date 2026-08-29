// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PEER-CERTIFICATE OBSERVATION at the connector — how a response learns which key answered it.
//!
//! The consumers of the peer identity need OBSERVATION, not (only) in-handshake verification:
//! the SPKI pin is compared application-side after a completed exchange (and is carried on
//! responses even when no pin is configured at all), so the engine's job is to read the leaf the
//! already-verified handshake produced and deliver its pin WITH the response it belongs to.
//!
//! Delivery rides `Connected::extra` — the exact mechanism reqwest's `tls_info(true)` is built on
//! over hyper_util. The legacy pool copies each connection's `Connected` extras into the
//! extensions of EVERY response served on that connection, so the "pooled connection is hidden"
//! problem is solved by the pool itself, per-connection-correctly: two pooled connections with
//! different renewal-era certificates each attribute a response to their own connection's cert.
//! The pooled-reuse propagation is pinned by this module's spike test (two sequential requests on
//! ONE connection both carry [`PeerSpki`]) — the keystone the whole design stands on.
//!
//! The pin is computed ONCE at connect time (`spki::pin` over the leaf), never per request. An
//! unwalkable certificate yields absence, never a pass — "we could not look" and "it matched" are
//! the two answers a pin exists to keep apart, and absence is the refusing arm application-side.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::rt;
use hyper_rustls::MaybeHttpsStream;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The observed transport-layer identity of the peer: the `sha256/<b64>` pin of the leaf
/// certificate's SubjectPublicKeyInfo, in the one canonical spelling
/// (`crate::plane_host::spki::pin`). Cloneable and cheap: the pool clones it into every
/// response's extensions.
#[derive(Clone, Debug)]
pub struct PeerSpki(pub Arc<str>);

/// Read the observed peer identity off an engine response. The drop-in for the old
/// `reqwest::tls::TlsInfo` read: `None` on a plaintext hop, an unwalkable certificate, or an
/// unobserving posture.
pub fn peer_spki<B>(resp: &http::Response<B>) -> Option<&str> {
    resp.extensions().get::<PeerSpki>().map(|p| p.0.as_ref())
}

/// The observing connector layer. `observe: false` (the LLM lanes) skips the certificate walk and
/// pin hash per connect; the [`ObservedIo`] wrapper stays in the connector TYPE either way, so
/// both postures share one concrete connector and the difference is a branch at connect time,
/// never a type split.
#[derive(Clone)]
pub struct SpkiObserve<C> {
    inner: C,
    observe: bool,
}

impl<C> SpkiObserve<C> {
    pub fn new(inner: C, observe: bool) -> Self {
        SpkiObserve { inner, observe }
    }
}

/// The connector's stream, carrying what was observed at connect time. A newtype delegating the
/// hyper I/O traits; its one job is [`Connection::connected`], where the observation becomes a
/// `Connected` extra the pool will replay onto every response this connection serves.
pub struct ObservedIo<T> {
    inner: T,
    spki: Option<PeerSpki>,
}

impl ObservedIo<MaybeHttpsStream<TokioIo<TcpStream>>> {
    /// The observed peer identity, read ONCE by the owned pool's dial task into its
    /// per-connection snapshot (the same fact `connected()` carries as a `Connected` extra —
    /// exposed directly because the owned pool replays extras itself instead of through
    /// hyper_util's pool).
    pub(crate) fn peer_spki_snapshot(&self) -> Option<PeerSpki> {
        self.spki.clone()
    }

    /// Whether ALPN negotiated h2 on this connection — the owned pool's protocol branch. A
    /// plaintext hop (h2c rides prior-knowledge posture, not ALPN) is `false`.
    pub(crate) fn negotiated_h2(&self) -> bool {
        match &self.inner {
            MaybeHttpsStream::Https(tls) => {
                let (_, conn) = tls.inner().get_ref();
                conn.alpn_protocol() == Some(b"h2")
            }
            MaybeHttpsStream::Http(_) => false,
        }
    }
}

impl<T: rt::Read + rt::Write + Connection + Unpin> Connection for ObservedIo<T> {
    fn connected(&self) -> Connected {
        let connected = self.inner.connected();
        match &self.spki {
            Some(pin) => connected.extra(pin.clone()),
            None => connected,
        }
    }
}

impl<T: rt::Read + rt::Write + Unpin> rt::Read for ObservedIo<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: rt::Read + rt::Write + Unpin> rt::Write for ObservedIo<T> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

impl<C> tower::Service<http::Uri> for SpkiObserve<C>
where
    C: tower::Service<http::Uri, Response = MaybeHttpsStream<TokioIo<TcpStream>>>,
    C::Future: Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = ObservedIo<MaybeHttpsStream<TokioIo<TcpStream>>>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: http::Uri) -> Self::Future {
        let observe = self.observe;
        let connect = self.inner.call(dst);
        Box::pin(async move {
            let io = connect.await.map_err(Into::into)?;
            // Post-handshake, at connect time: the chain the already-verified handshake
            // produced; index 0 is the leaf. A plaintext hop, or a leaf the DER walk refuses,
            // observes NOTHING — honestly absent, matching the empty TlsInfo of old.
            let spki = if observe {
                match &io {
                    MaybeHttpsStream::Https(tls) => {
                        let (_, conn) = tls.inner().get_ref();
                        conn.peer_certificates()
                            .and_then(|certs| certs.first())
                            .and_then(|leaf| crate::plane_host::spki::pin(leaf.as_ref()).ok())
                            .map(|pin| PeerSpki(pin.into()))
                    }
                    MaybeHttpsStream::Http(_) => None,
                }
            } else {
                None
            };
            Ok(ObservedIo { inner: io, spki })
        })
    }
}
