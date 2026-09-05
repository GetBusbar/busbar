// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A type-erased duplex byte stream, so one [`tokio_tungstenite::WebSocketStream`] type can sit
//! over a plain TCP socket, a TLS-wrapped one, or (in the battery) an in-memory duplex — the exact
//! placeholder for "the lower-layer boundary" this crate's own report calls out: a real deployment
//! would hand this transport an already-established `Conn` from the tcp/tls/http transport crates
//! once they exist, instead of this crate dialling/accepting raw sockets itself.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Anything that is a duplex, unpin, sendable byte stream. Blanket-implemented, so any concrete
/// stream type can be boxed as one.
pub trait Rw: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Rw for T {}

/// The boxed form, with `AsyncRead`/`AsyncWrite` implemented by delegation so it can stand in
/// anywhere a concrete stream type is expected.
pub struct BoxedRw(pub Box<dyn Rw>);

impl AsyncRead for BoxedRw {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedRw {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
