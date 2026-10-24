// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HTTPS ARM of the engine's connector: plain TCP for an `http` target, and for an `https`
//! target the handshake the connector's TLS wrap runs (`crate::secure`) over the TCP the
//! layer below dialled. The layer `hyper-rustls`'s `HttpsConnector` was in this stack, kept call
//! for call: the scheme cascade (`http` plain, any other non-`https` scheme refused, no scheme
//! refused), the server name taken from the URI host with an IPv6 literal's brackets removed and
//! checked BEFORE the dial, the handshake's error wrapped once more as an `io::Error` of kind
//! `Other`, and a connection that agreed `h2` by ALPN reported as negotiated h2. Only where the TLS
//! code runs moved: into the connector.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::rt;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::secure::{ClientTls, SecuredIo, NO_LAYER};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The connector for the `https` scheme over `T` (the TCP / CONNECT-tunnel layer).
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    /// The TLS client every `https` handshake runs on; `None` in a process that installed no TLS
    /// wrap, where an `https` dial fails after its TCP connect, naming the missing install.
    tls: Option<Arc<dyn ClientTls>>,
}

impl<T> HttpsConnector<T> {
    pub fn new(http: T, tls: Option<Arc<dyn ClientTls>>) -> Self {
        HttpsConnector { http, tls }
    }
}

/// A stream that might be protected with TLS.
pub enum MaybeHttpsStream {
    /// A stream over plain text.
    Http(TokioIo<TcpStream>),
    /// A stream protected with TLS.
    Https(TokioIo<Box<dyn SecuredIo>>),
}

impl MaybeHttpsStream {
    /// The secured session, on the TLS arm.
    pub(crate) fn secured(&self) -> Option<&dyn SecuredIo> {
        match self {
            MaybeHttpsStream::Https(tls) => Some(&**tls.inner()),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

impl<T> tower::Service<http::Uri> for HttpsConnector<T>
where
    T: tower::Service<http::Uri, Response = TokioIo<TcpStream>>,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
{
    type Response = MaybeHttpsStream;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<MaybeHttpsStream, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, dst: http::Uri) -> Self::Future {
        match dst.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                let future = self.http.call(dst);
                return Box::pin(async move {
                    Ok(MaybeHttpsStream::Http(future.await.map_err(Into::into)?))
                });
            }
            Some(scheme) if scheme != &http::uri::Scheme::HTTPS => {
                let message = format!("unsupported scheme {scheme}");
                return Box::pin(async move { Err(io::Error::other(message).into()) });
            }
            Some(_) => {}
            None => return Box::pin(async move { Err(io::Error::other("missing scheme").into()) }),
        };

        let handshake = match &self.tls {
            Some(tls) => {
                // The server name is the URI's host, an IPv6 literal unbracketed.
                let mut hostname = dst.host().unwrap_or_default();
                if let Some(trimmed) = hostname.strip_prefix('[').and_then(|h| h.strip_suffix(']'))
                {
                    hostname = trimmed;
                }
                match tls.handshake(hostname) {
                    Ok(handshake) => Some(handshake),
                    Err(e) => return Box::pin(async move { Err(e) }),
                }
            }
            None => None,
        };

        let connecting_future = self.http.call(dst);
        Box::pin(async move {
            let tcp = connecting_future.await.map_err(Into::into)?;
            let Some(handshake) = handshake else {
                return Err(io::Error::other(NO_LAYER).into());
            };
            Ok(MaybeHttpsStream::Https(TokioIo::new(
                handshake(tcp.into_inner())
                    .await
                    .map_err(io::Error::other)?,
            )))
        })
    }
}

impl Connection for MaybeHttpsStream {
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let tls = s.inner();
                if tls.alpn() == Some(b"h2") {
                    tls.tcp().connected().negotiated_h2()
                } else {
                    tls.tcp().connected()
                }
            }
        }
    }
}

impl rt::Read for MaybeHttpsStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Self::Http(s) => Pin::new(s).poll_read(cx, buf),
            Self::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl rt::Write for MaybeHttpsStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            Self::Http(s) => Pin::new(s).poll_write(cx, buf),
            Self::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Self::Http(s) => Pin::new(s).poll_flush(cx),
            Self::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Self::Http(s) => Pin::new(s).poll_shutdown(cx),
            Self::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Http(s) => s.is_write_vectored(),
            Self::Https(s) => s.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            Self::Http(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Https(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }
}
