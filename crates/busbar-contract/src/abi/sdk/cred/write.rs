// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one way a [`Seal`] reaches the wire.

use std::task::Poll;

use zeroize::Zeroizing;

use super::Seal;
use crate::abi::host::conn::connector::RequestPiece;
use crate::abi::sdk::conn::{Answer, Connector};
use crate::abi::sdk::io::{Io, IoAnswer};

#[allow(missing_debug_implementations)]
enum Part {
    Public(Vec<u8>),
    Sealed(Seal),
}

/// Public bytes and sealed pieces in wire order, for a framed field value (a header line). A raw
/// stream's auth message is one whole [`Seal`]: write it with [`SealedWrite::message`].
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct Parts {
    parts: Vec<Part>,
}

impl Parts {
    /// An empty wire.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append public bytes.
    #[must_use]
    pub fn public(mut self, bytes: &[u8]) -> Self {
        self.parts.push(Part::Public(bytes.to_vec()));
        self
    }

    /// Append a sealed piece.
    #[must_use]
    pub fn sealed(mut self, seal: Seal) -> Self {
        self.parts.push(Part::Sealed(seal));
        self
    }

    /// The total length in bytes.
    pub fn len(&self) -> usize {
        self.parts
            .iter()
            .map(|p| match p {
                Part::Public(b) => b.len(),
                Part::Sealed(s) => s.len(),
            })
            .sum()
    }

    /// Whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(any(test, feature = "test-seal"))]
    pub(crate) fn assembled(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(self.len()));
        for p in &self.parts {
            match p {
                Part::Public(b) => buf.extend_from_slice(b),
                Part::Sealed(s) => buf.extend_from_slice(s.wire()),
            }
        }
        buf
    }
}

/// Bytes on their way to the host, held where the plugin cannot read them. Park it on the op's
/// ticket across a PENDING answer and poll it again; it is wiped when it drops.
#[allow(missing_debug_implementations)]
pub struct SealedWrite {
    pub(crate) buf: Zeroizing<Vec<u8>>,
    done: usize,
}

impl SealedWrite {
    /// The assembled wire.
    pub fn new(wire: Parts) -> Self {
        let mut buf = Zeroizing::new(Vec::with_capacity(wire.len()));
        for p in &wire.parts {
            match p {
                Part::Public(b) => buf.extend_from_slice(b),
                Part::Sealed(s) => buf.extend_from_slice(s.wire()),
            }
        }
        Self { buf, done: 0 }
    }

    pub(crate) fn from_bytes(buf: Zeroizing<Vec<u8>>) -> Self {
        Self { buf, done: 0 }
    }

    /// A whole auth message, written alone.
    pub fn message(seal: Seal) -> Self {
        Self::new(Parts::new().sealed(seal))
    }

    /// The total length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether every byte has been taken.
    pub fn finished(&self) -> bool {
        self.done >= self.buf.len()
    }

    /// Write what is left on a connector `stream`: `Ready(Ok(()))` once every byte is taken.
    pub fn poll(&mut self, c: &mut Connector<'_>, stream: u64) -> Answer<()> {
        while !self.finished() {
            match c.write(stream, &self.buf[self.done..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return Poll::Pending,
                Poll::Ready(Ok(n)) => self.done += n,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Write what is left on an I/O `handle`: `Ready(Ok(()))` once every byte is taken.
    pub fn poll_io(&mut self, io: &mut Io<'_>, handle: u64) -> Poll<IoAnswer<()>> {
        while !self.finished() {
            match io.write(handle, &self.buf[self.done..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return Poll::Pending,
                Poll::Ready(Ok(n)) => self.done += n,
            }
        }
        Poll::Ready(Ok(()))
    }

    #[cfg(any(test, feature = "test-seal"))]
    pub(crate) fn drive<E>(
        &mut self,
        write: &mut impl FnMut(&[u8]) -> Poll<Result<usize, E>>,
    ) -> Poll<Result<(), E>> {
        while !self.finished() {
            match write(&self.buf[self.done..]) {
                Poll::Pending | Poll::Ready(Ok(0)) => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => self.done += n,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Write what is left as request BODY pieces on a framed `stream` (`piece` names the body):
    /// `Ready(Ok(()))` once every byte is taken.
    pub fn poll_request(
        &mut self,
        c: &mut Connector<'_>,
        stream: u64,
        piece: &RequestPiece,
    ) -> Answer<()> {
        while !self.finished() {
            match c.write_request(stream, piece, &self.buf[self.done..]) {
                Poll::Pending | Poll::Ready(Ok(0)) => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => self.done += n,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Write it as one request piece on a framed `stream` (`piece`'s spans index these bytes).
    pub fn request(
        &mut self,
        c: &mut Connector<'_>,
        stream: u64,
        piece: &RequestPiece,
    ) -> Answer<usize> {
        c.write_request(stream, piece, &self.buf)
    }
}

/// THE ANSWER PATH OF A KIND THAT ANSWERS INTO A HOST BUFFER (a plane's `on_piece` reply). The
/// buffer takes plain bytes, so the sealed bytes leave the SDK here: copied straight from this
/// write's zeroizing buffer into the host's, never through a plugin `Vec` or `String`. That copy
/// is the in-process residual the destination requires (`cred::json`).
impl SealedWrite {
    /// Write what is left into `buf`, as much as there is room for (backpressure: the host
    /// flushes it and calls again). Answers how many bytes went in; [`SealedWrite::finished`]
    /// once every byte is taken.
    pub fn stream_into(&mut self, buf: &mut crate::abi::sdk::HostBuf<'_, u8>) -> usize {
        let n = buf.stream(&self.buf[self.done..]);
        self.done += n;
        n
    }

    /// The bytes not yet taken (a length is public).
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.done)
    }
}
