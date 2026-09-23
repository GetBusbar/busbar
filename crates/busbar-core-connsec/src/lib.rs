// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connsec` — the core-side connection-security seam (DECISIONS #40).
//!
//! A trusted, compiled-in `core`-kind sibling of `busbar-kernel` (the same category as
//! `busbar-core-admin` / `busbar-core-oauth2`): never a plugin, always linked, off the hot path. It owns the
//! WHOLE connection-security prep for one binding — read the operator's `tls:` config, pull the
//! resolved key material through the secret kind (`busbar_kernel::config::secret::SecretResolver`,
//! the one seam every other TLS-material reader in this tree already goes through), and build an
//! OPAQUE [`busbar_contract::transport::wire::ConnectionSecurity`] wrap.
//!
//! A transport is handed nothing but that wrap. It calls the ONE operation the trait exposes —
//! `wrap(stream) -> securedstream` — and never sees a rustls type or a key byte: the whole point of
//! the contract-side trait is that this crate is the only place in the tree that names
//! `rustls::ServerConfig` for an INBOUND (listener) binding. A future connection-security variant
//! (mTLS with a different verifier shape, a PQ hybrid signature scheme, ...) is a change to this
//! crate alone.
//!
//! ## Negotiation and fail-closed
//!
//! The operator's binding config is the source of truth for whether a binding is TLS.
//! [`prepare`] reconciles it against the transport's declared
//! [`busbar_contract::transport::TransportMeta::WRAPPABLE_BYTE_STREAM`] capability:
//!
//! * config plaintext (`tls: None`) ⇒ the [`Identity`] wrap (a byte-for-byte no-op).
//! * config TLS + a capable transport ⇒ the material is resolved and a [`Tls`] wrap is built and
//!   handed over.
//! * config TLS + an INCAPABLE transport, or config TLS whose cert/key cannot be resolved/parsed ⇒
//!   [`prepare`] returns `Err` and the binding must not come up. There is no third outcome: a
//!   binding is never silently downgraded to plaintext.
//!
//! ## Where the TLS-config-build logic came from
//!
//! [`load_cert_chain`], [`load_private_key`], [`load_client_roots`], [`build_server_config`] and
//! [`install_crypto_provider`] are relocated byte-for-byte (only the module path each name is
//! reached through changed) from `busbar-kernel`'s own `tls` module, where the SAME native inbound
//! TLS termination has built its `rustls::ServerConfig` this way since before this crate existed.
//! `busbar_kernel::tls` keeps `read_pem` (an outbound TLS-identity reader in `busbar-a2a` also calls
//! it) and the accept-loop/hyper-serving machinery — a LISTENER concern this crate does not touch —
//! but no longer builds a `ServerConfig` itself.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

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
/// [`build_server_config`].
///
/// A thin re-export of `busbar_kernel::tls::install_crypto_provider` — that function stays in
/// `busbar-kernel` because it is a process-wide utility several subsystems call (the egress
/// engine's client-side TLS, `hyper-rustls`, test setup), not something exclusive to an inbound
/// listener's connection-security prep. This crate names it too so a caller of THIS crate's public
/// API never has to reach into `busbar-kernel` directly for it.
pub fn install_crypto_provider() {
    busbar_kernel::tls::install_crypto_provider();
}

/// Parse the PEM certificate chain (leaf first). Errors name the secret source; cert bytes are
/// public, but we still avoid echoing them.
///
/// Relocated verbatim from `busbar_kernel::tls::load_cert_chain`.
fn load_cert_chain(
    resolver: &SecretResolver,
    secret: &SecretRef,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let src = secret.describe();
    let bytes = busbar_kernel::tls::read_pem(resolver, secret, "cert")?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
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
/// material - error messages name only the secret source.
///
/// Relocated verbatim from `busbar_kernel::tls::load_private_key`.
fn load_private_key(
    resolver: &SecretResolver,
    secret: &SecretRef,
) -> Result<PrivateKeyDer<'static>, String> {
    let src = secret.describe();
    let bytes = busbar_kernel::tls::read_pem(resolver, secret, "key")?;
    // `PrivateKeyDer::from_pem_slice` accepts PKCS#8, PKCS#1, and SEC1 sections, picking the first
    // private-key section it finds. `NoItemsFound` means none was present; any other variant is a
    // genuine parse error. Neither path echoes key material - error messages name only the source.
    use rustls::pki_types::pem::Error as PemError;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| match e {
        PemError::NoItemsFound => {
            format!("TLS key ({src}) contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)")
        }
        other => format!("cannot parse TLS key ({src}): {other}"),
    })
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).
///
/// Relocated verbatim from `busbar_kernel::tls::load_client_roots`.
fn load_client_roots(
    resolver: &SecretResolver,
    secret: &SecretRef,
) -> Result<RootCertStore, String> {
    let src = secret.describe();
    let bytes = busbar_kernel::tls::read_pem(resolver, secret, "client_ca")?;
    let cas = CertificateDer::pem_slice_iter(&bytes)
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

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`].
///
/// * `client_ca` present ⇒ a [`WebPkiClientVerifier`] is installed: the client MUST present a
///   certificate chaining to that CA or the handshake fails (mTLS required).
/// * `client_ca` absent ⇒ `with_no_client_auth()` (server-only TLS).
///
/// ALPN advertises only `http/1.1` — busbar's axum server speaks http/1.1, so we must not advertise
/// h2. Returns a clear, source-named error on any load/parse problem (the caller turns it into `die`).
///
/// Relocated verbatim from `busbar_kernel::tls::build_server_config` (DECISIONS #40): every field,
/// default and error message is unchanged — only the module this function lives in moved.
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

    // http/1.1 only — busbar's axum 0.7 server does not serve h2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

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
/// [`build_server_config`] over the accepted stream.
///
/// Holds the already-built [`ServerConfig`] (never a `SecretRef`, never key bytes — those were
/// consumed when the config was built) so `wrap` never re-reads the secret kind per connection.
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
            // `RawIo` is the contract's rustls-free, futures-io-based stream type; `tokio_rustls`
            // needs tokio's `AsyncRead`/`AsyncWrite`. `FuturesAsyncReadCompatExt::compat` bridges
            // the futures-io stream in, the handshake runs, and `TokioAsyncReadCompatExt::compat`
            // bridges the tokio-io result back out — the same futures-io/tokio-io seam
            // `busbar-transport-tls` already crosses for its own in-band TLS upgrade.
            let tokio_io = FuturesAsyncReadCompatExt::compat(io);
            let acceptor = tokio_rustls::TlsAcceptor::from(self.config.clone());
            let tls_stream = acceptor.accept(tokio_io).await?;
            let raw: Box<dyn RawIo> = Box::new(TokioAsyncReadCompatExt::compat(tls_stream));
            Ok(raw)
        })
    }
}

/// Why [`prepare`] refused to bring a binding up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailClosed {
    /// The binding's `tls:` config demands TLS but the transport it would be served over has not
    /// declared [`busbar_contract::transport::TransportMeta::WRAPPABLE_BYTE_STREAM`]. Serving it in
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
/// wrap the transport is handed — the negotiation DECISIONS #40 requires:
///
/// * `tls_cfg` is `None` ⇒ `Ok(`[`Identity`]`)`, regardless of `transport_capable` (a plaintext
///   binding never needs the capability at all).
/// * `tls_cfg` is `Some` and `transport_capable` is `false` ⇒
///   `Err(`[`FailClosed::IncapableTransport`]`)` — never a silent plaintext downgrade.
/// * `tls_cfg` is `Some`, `transport_capable` is `true`, and the material resolves and parses ⇒
///   `Ok(`[`Tls`]`)`.
/// * `tls_cfg` is `Some`, `transport_capable` is `true`, but the material does not resolve/parse ⇒
///   `Err(`[`FailClosed::MaterialUnavailable`]`)` — [`build_server_config`] already fails closed on
///   a missing/bad cert; this just carries that failure through the same `Result`.
///
/// # Errors
///
/// See [`FailClosed`].
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
            install_crypto_provider();
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
