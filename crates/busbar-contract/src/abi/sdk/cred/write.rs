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
pub(crate) enum Part {
    Public(Vec<u8>),
    Sealed(Seal),
}

/// Public bytes and sealed pieces in wire order, for a framed field value (a header line). A raw
/// stream's auth message is one whole [`Seal`]: write it with [`SealedWrite::message`].
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct Parts {
    pub(crate) parts: Vec<Part>,
    secure: bool,
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
        self.secure |= seal.secure_required();
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
}

/// Bytes on their way to the host, held where the plugin cannot read them. Park it on the op's
/// ticket across a PENDING answer and poll it again; it is wiped when it drops.
#[allow(missing_debug_implementations)]
pub struct SealedWrite {
    pub(crate) buf: Zeroizing<Vec<u8>>,
    pub(crate) done: usize,
    /// It carries a credential that goes out only secured ([`super::Cred::secure_required`]).
    pub(crate) secure: bool,
    /// The connection was confirmed secured before the first byte.
    confirmed: bool,
    /// The connection was found in the clear: every later poll refuses (a replayed `FACTS` writes
    /// nothing, so only this remembers it).
    refused: bool,
}

/// Before a credential that must go out secured is written on `stream`: whether the host connector
/// reports it secured ([`Connector::facts`]). A host that offers no facts, or a stream it reports
/// in the clear, refuses ([`super::NOT_SECURE`]). `None` facts are a replayed call's: the entry
/// that first made it decided.
pub(crate) fn confirm_secure(c: &mut Connector<'_>, stream: u64) -> Answer<()> {
    match c.facts(stream) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(Some(o))) if o.secure => Poll::Ready(Ok(())),
        Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
        Poll::Ready(Ok(Some(_)) | Err(_)) => Poll::Ready(Err(
            crate::abi::sdk::conn::ConnFailure::Refused(super::NOT_SECURE.into()),
        )),
    }
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
        Self {
            buf,
            done: 0,
            secure: wire.secure,
            confirmed: false,
            refused: false,
        }
    }

    pub(crate) fn from_bytes(buf: Zeroizing<Vec<u8>>, secure: bool) -> Self {
        Self {
            buf,
            done: 0,
            secure,
            confirmed: false,
            refused: false,
        }
    }

    /// Whether it carries a credential that goes out only secured.
    pub fn secure_required(&self) -> bool {
        self.secure
    }

    fn confirm(&mut self, c: &mut Connector<'_>, stream: u64) -> Answer<()> {
        if self.secure && !self.confirmed {
            match confirm_secure(c, stream) {
                Poll::Ready(Ok(())) if !self.refused => self.confirmed = true,
                Poll::Pending if !self.refused => return Poll::Pending,
                _ => {
                    self.refused = true;
                    return Poll::Ready(Err(crate::abi::sdk::conn::ConnFailure::Refused(
                        super::NOT_SECURE.into(),
                    )));
                }
            }
        }
        Poll::Ready(Ok(()))
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
        std::task::ready!(self.confirm(c, stream))?;
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
    ///
    /// An I/O handle reports no connection security, so a credential that must go out secured is
    /// refused here.
    pub fn poll_io(&mut self, io: &mut Io<'_>, handle: u64) -> Poll<IoAnswer<()>> {
        if self.secure {
            return Poll::Ready(Err(crate::abi::sdk::io::IoFailure::Refused(
                super::NOT_SECURE.into(),
            )));
        }
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
    ///
    /// # Errors
    /// [`super::NOT_SECURE`]: it carries a credential that must go out secured, and a host buffer
    /// reports no connection security (as [`SealedWrite::poll_io`] refuses it). Nothing is written.
    pub fn stream_into(
        &mut self,
        buf: &mut crate::abi::sdk::HostBuf<'_, u8>,
    ) -> Result<usize, &'static str> {
        if self.secure {
            return Err(super::NOT_SECURE);
        }
        let n = buf.stream(&self.buf[self.done..]);
        self.done += n;
        Ok(n)
    }

    /// The bytes not yet taken (a length is public).
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.done)
    }
}
