// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector::tls` — the core-side connection-security seam, folded in

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

pub mod client;
pub mod explain;
pub mod store;
mod write_progress;

#[cfg(test)]
mod write_progress_tests;

use busbar_contract::transport::wire::{ConnectionSecurity, SecuredIo, SecuredIoFut};
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::sections::TlsCfg;
use busbar_kernel::config::SecretRef;
use rustls::ServerConfig;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// BUSBAR'S CLIENT IDENTITY for one destination, from its two secret references: the PEM chain
/// and the PEM private key, parsed once.
pub fn client_identity(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    cert: &SecretRef,
    key: &SecretRef,
) -> Result<busbar_contract::transport::trust::ClientIdentity, String> {
    crate::off_path::tls::client_identity(resolver, cert, key)
}

/// The ALPN ids a TLS listener offers, in its order of preference. The listener's hyper builder
pub(crate) const ALPN_OFFER: [&[u8]; 2] = [ALPN_H2, b"http/1.1"];

/// The ALPN id of HTTP/2 over TLS (RFC 9113 §3.3).
const ALPN_H2: &[u8] = b"h2";

/// The HTTP/2 client connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A connection whose ALPN is `h2` is KNOWN to be HTTP/2, so RFC 9113 §3.4 governs its first bytes
async fn expect_h2_preface<S: futures::io::AsyncRead + Unpin>(io: &mut S) -> std::io::Result<()> {
    let mut got = [0u8; 24];
    let mut n = 0;
    while n < got.len() {
        let read = futures::io::AsyncReadExt::read(io, &mut got[n..]).await?;
        n += read;
        if read == 0 || got[..n] != H2_PREFACE[..n] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "an ALPN h2 connection did not open with the HTTP/2 connection preface \
                 (RFC 9113 §3.4); connection closed",
            ));
        }
    }
    Ok(())
}

/// An ALPN-h2 stream whose preface [`expect_h2_preface`] has read: reads hand the preface back
struct Preface<S> {
    io: S,
    replayed: usize,
}

impl<S: futures::io::AsyncRead + Unpin> futures::io::AsyncRead for Preface<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let rest = &H2_PREFACE[self.replayed..];
        if rest.is_empty() {
            return std::pin::Pin::new(&mut self.io).poll_read(cx, buf);
        }
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.replayed += n;
        std::task::Poll::Ready(Ok(n))
    }
}

impl<S: futures::io::AsyncWrite + Unpin> futures::io::AsyncWrite for Preface<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_close(cx)
    }
}

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`], through the crypto
/// backend (`busbar_contract::crypto::tls`), which approves it; returned frozen.
pub fn build_server_config(
    tls: &TlsCfg,
    resolver: &SecretResolver,
) -> Result<Arc<ServerConfig>, String> {
    crate::off_path::tls::build_server_config(tls, resolver)
}

/// The plaintext connection-security wrap: a byte-for-byte no-op.
///
/// Every accepted/dialled stream a plaintext binding hands to `wrap` comes back completely
/// unchanged — no allocation beyond the `Box` already required to cross the opaque seam, no bytes
/// read or written. This is what makes a plaintext binding's wire byte-identical to a binding that
/// never went through this crate at all.
#[derive(Debug, Default, Clone, Copy)]
pub struct Identity;

impl ConnectionSecurity for Identity {
    fn wrap<'a>(&'a self, io: busbar_contract::transport::ConnectionIo) -> SecuredIoFut<'a> {
        Box::pin(async move { Ok(SecuredIo::anonymous(io)) })
    }
}

/// The TLS connection-security wrap: runs the rustls server handshake built by
pub struct Tls {
    config: Arc<ServerConfig>,
}

impl Tls {
    /// Wrap an already-built server config for the [`ConnectionSecurity`] seam.
    #[must_use]
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl ConnectionSecurity for Tls {
    fn wrap<'a>(&'a self, io: busbar_contract::transport::ConnectionIo) -> SecuredIoFut<'a> {
        Box::pin(async move {
            let plan = busbar_contract::crypto::tls::write_progress::server_plan(&self.config)
                .map_err(std::io::Error::other)?;
            let credit = io
                .storage
                .try_reserve(plan.requested_bytes())
                .map_err(std::io::Error::other)?;
            let storage = io.storage;
            let tokio_io = FuturesAsyncReadCompatExt::compat(io.io);
            let acceptor = tokio_rustls::TlsAcceptor::from(self.config.clone());
            let funded = write_progress::handshake(credit, || acceptor.accept(tokio_io)).await?;
            let session = funded.stream().get_ref().1;
            let tls_handshake = Some(
                busbar_contract::transport::wire::HandshakeInfo::capture(
                    &storage,
                    session.alpn_protocol(),
                    session.server_name(),
                )
                .map_err(std::io::Error::other)?,
            );
            // The leaf rustls verified, copied once into storage charged before the copy.
            let peer_certificate = busbar_contract::transport::wire::PeerCertificate::capture(
                &storage,
                session
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map_or(&[][..], |leaf| leaf.as_ref()),
            )
            .map_err(std::io::Error::other)?;
            let known_h2 = session.alpn_protocol() == Some(ALPN_H2);
            let (tls_stream, progress) = write_progress::TrackedTls::new(funded, plan)?;
            let mut io = TokioAsyncReadCompatExt::compat(tls_stream);
            if !known_h2 {
                return Ok(SecuredIo {
                    io: Box::new(io),
                    peer_certificate,
                    progress,
                    storage,
                    tls_handshake,
                });
            }
            expect_h2_preface(&mut io).await?;
            Ok(SecuredIo {
                io: Box::new(Preface { io, replayed: 0 }),
                peer_certificate,
                progress,
                storage,
                tls_handshake,
            })
        })
    }
}

/// Why [`prepare`] refused to bring a binding up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailClosed {
    /// The binding's `tls:` config demands TLS but the transport it would be served over has not
    /// declared a wrappable byte stream. Serving it in
    /// plaintext instead would be exactly the silent downgrade this seam exists to rule out.
    IncapableTransport {
        /// The label (listener address, or similar) the caller passed to [`prepare`], for the
        /// error message a boot failure prints.
        label: String,
    },
    /// The TLS material could not be resolved through the secret kind or did not parse into a
    /// usable certificate/key (missing cert, bad PEM, mismatched cert/key pair, ...).
    MaterialUnavailable {
        /// The label the caller passed to [`prepare`].
        label: String,
        /// [`build_server_config`]'s own error, naming the secret SOURCE, never its bytes.
        reason: String,
    },
}

impl std::fmt::Display for FailClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailClosed::IncapableTransport { label } => write!(
                f,
                "TLS is configured for '{label}' but its transport cannot terminate TLS \
                 (WRAPPABLE_BYTE_STREAM = false); refusing to serve it in plaintext"
            ),
            FailClosed::MaterialUnavailable { label, reason } => {
                write!(f, "TLS configuration error for '{label}': {reason}")
            }
        }
    }
}

impl std::error::Error for FailClosed {}

/// Reconcile one binding's operator config against its transport's capability and build the opaque
/// connection-security wrap.
pub fn prepare(
    label: &str,
    tls_cfg: Option<&TlsCfg>,
    resolver: &SecretResolver,
    transport_capable: bool,
) -> Result<Arc<dyn ConnectionSecurity>, FailClosed> {
    crate::off_path::tls::prepare(label, tls_cfg, resolver, transport_capable)
}

/// Prepare a listener using the selected transport supplier's server ALPN offer.
/// The supplied order and an empty offer are preserved exactly.
pub fn prepare_for_alpn(
    label: &str,
    tls_cfg: Option<&TlsCfg>,
    resolver: &SecretResolver,
    transport_capable: bool,
    alpn: &[&[u8]],
) -> Result<Arc<dyn ConnectionSecurity>, FailClosed> {
    crate::off_path::tls::prepare_for_alpn(label, tls_cfg, resolver, transport_capable, alpn)
}

#[cfg(test)]
mod tests;
