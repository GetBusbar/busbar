// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A HOST SOCKET AS A BYTE STREAM: the connector's own non-blocking TCP socket, its readiness on the
//! registering worker's reactor ([`crate::io`]), presented as `futures-io` `AsyncRead`/`AsyncWrite`
//! for whatever the host serves over a detached connection (the kernel's own loop, connection
//! security's wrap). Bytes a framer took and did not answer come first.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::io::{Direction, Registered};

/// A registered host socket, with the bytes to read before it.
#[derive(Debug)]
pub struct HostStream {
    sock: Registered<TcpStream>,
    first: VecDeque<u8>,
}

impl HostStream {
    /// `sock`, read after `first`.
    #[must_use]
    pub fn new(sock: Registered<TcpStream>, first: Vec<u8>) -> Self {
        Self {
            sock,
            first: first.into(),
        }
    }

    /// The socket.
    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        self.sock.get_ref()
    }
}

impl futures::io::AsyncRead for HostStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.first.is_empty() {
            let n = self.first.len().min(buf.len());
            for (slot, b) in buf.iter_mut().zip(self.first.drain(..n)) {
                *slot = b;
            }
            return Poll::Ready(Ok(n));
        }
        self.sock.poll_io(Direction::Read, cx, |mut s| s.read(buf))
    }
}

impl futures::io::AsyncWrite for HostStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.sock
            .poll_io(Direction::Write, cx, |mut s| s.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A socket write is handed to the kernel whole; there is nothing held here to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.sock.get_ref().shutdown(Shutdown::Write) {
            Err(e) if e.kind() != io::ErrorKind::NotConnected => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(())),
        }
    }
}
