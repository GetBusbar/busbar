// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector::tls` — the core-side connection-security seam, folded in

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

pub mod client;

use busbar_contract::transport::wire::{ConnectionSecurity, RawIo, SecuredIoFut};
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::sections::TlsCfg;
use busbar_kernel::config::SecretRef;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Install ring's [`rustls::crypto::CryptoProvider`] as the process default. Must run before

pub fn install_crypto_provider() {
    let _ = ring().install_default();
}

/// Ring's crypto backend, the one backend busbar links.
pub(crate) fn ring() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// The process's crypto backend, installed first ([`install_crypto_provider`]): the default the

#[must_use]
pub fn installed_crypto() -> Arc<rustls::crypto::CryptoProvider> {
    let _ = ring().install_default();
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(ring()))
}

/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,

fn read_pem(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
    what: &str,
) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
    resolver
        .resolve_at_config(
            secret,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}

/// Parse the PEM certificate chain (leaf first). Errors name the secret source; cert bytes are

fn load_cert_chain(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "cert")?;
    let seal = busbar_kernel::seal::lend();
    let bytes = bytes.expose(&seal);
    let certs = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS cert ({src}): {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS cert ({src}) contains no certificates (expected a PEM chain, leaf first)"
        ));
    }
    Ok(certs)
}

/// Parse the PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encodings. NEVER logs key

fn load_private_key(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
) -> Result<PrivateKeyDer<'static>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "key")?;
    let seal = busbar_kernel::seal::lend();
    let bytes = bytes.expose(&seal);

    use rustls::pki_types::pem::Error as PemError;
    PrivateKeyDer::from_pem_slice(bytes).map_err(|e| match e {
        PemError::NoItemsFound => {
            format!("TLS key ({src}) contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)")
        }
        other => format!("cannot parse TLS key ({src}): {other}"),
    })
}

/// BUSBAR'S CLIENT IDENTITY for one destination, from its two secret references: the PEM chain

pub fn client_identity(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    cert: &SecretRef,
    key: &SecretRef,
) -> Result<busbar_contract::transport::trust::ClientIdentity, String> {
    let chain = load_cert_chain(resolver, cert)?;
    let key = load_private_key(resolver, key)?;
    Ok(busbar_contract::transport::trust::ClientIdentity {
        cert_chain: chain.into_iter().map(|c| c.as_ref().to_vec()).collect(),
        private_key: key.secret_der().to_vec().into(),
    })
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).

fn load_client_roots(
    resolver: &SecretResolver,
    secret: &SecretRef,
) -> Result<RootCertStore, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "client_ca")?;
    let seal = busbar_kernel::seal::lend();
    let bytes = bytes.expose(&seal);
    let cas = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS client_ca ({src}): {e}"))?;
    if cas.is_empty() {
        return Err(format!("TLS client_ca ({src}) contains no CA certificates"));
    }
    let mut roots = RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| format!("invalid CA certificate in TLS client_ca ({src}): {e}"))?;
    }
    Ok(roots)
}

/// The ALPN ids a TLS listener offers, in its order of preference. The listener's hyper builder

const ALPN_OFFER: [&[u8]; 2] = [ALPN_H2, b"http/1.1"];

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

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`].

pub fn build_server_config(
    tls: &TlsCfg,
    resolver: &SecretResolver,
) -> Result<ServerConfig, String> {
    let certs = load_cert_chain(resolver, &tls.cert)?;
    let key = load_private_key(resolver, &tls.key)?;

    let builder = ServerConfig::builder();

    let builder = match &tls.client_ca {
        Some(ca) => {
            let roots = load_client_roots(resolver, ca)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    format!(
                        "cannot build client-cert verifier from TLS client_ca ({}): {e}",
                        ca.describe()
                    )
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut config = builder.with_single_cert(certs, key).map_err(|e| {
        format!(
            "TLS cert/key are not a valid pair (cert {}, key {}): {e}",
            tls.cert.describe(),
            tls.key.describe()
        )
    })?;

    config.alpn_protocols = ALPN_OFFER.iter().map(|p| p.to_vec()).collect();

    Ok(config)
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
    fn wrap<'a>(&'a self, io: Box<dyn RawIo>) -> SecuredIoFut<'a> {
        Box::pin(async move { Ok(io) })
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
    fn wrap<'a>(&'a self, io: Box<dyn RawIo>) -> SecuredIoFut<'a> {
        Box::pin(async move {
            let tokio_io = FuturesAsyncReadCompatExt::compat(io);
            let acceptor = tokio_rustls::TlsAcceptor::from(self.config.clone());
            let tls_stream = acceptor.accept(tokio_io).await?;
            let known_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(ALPN_H2);
            let mut io = TokioAsyncReadCompatExt::compat(tls_stream);
            if !known_h2 {
                return Ok(Box::new(io) as Box<dyn RawIo>);
            }
            expect_h2_preface(&mut io).await?;
            Ok(Box::new(Preface { io, replayed: 0 }) as Box<dyn RawIo>)
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

pub fn prepare(
    label: &str,
    tls_cfg: Option<&TlsCfg>,
    resolver: &SecretResolver,
    transport_capable: bool,
) -> Result<Arc<dyn ConnectionSecurity>, FailClosed> {
    match tls_cfg {
        None => Ok(Arc::new(Identity)),
        Some(_) if !transport_capable => Err(FailClosed::IncapableTransport {
            label: label.to_string(),
        }),
        Some(tls) => {
            let _ = installed_crypto();
            let config = build_server_config(tls, resolver).map_err(|reason| {
                FailClosed::MaterialUnavailable {
                    label: label.to_string(),
                    reason,
                }
            })?;
            Ok(Arc::new(Tls::new(Arc::new(config))))
        }
    }
}

#[cfg(test)]
mod tests;
