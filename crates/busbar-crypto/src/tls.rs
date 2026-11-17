// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TLS through the linked backend's provider (CRYPTO-SEAM §2.3 rules). The provider never leaves this
//! module and is never installed as the rustls process default: the only way to get a config or a
//! verifier is a function here, so the backend's approval runs inside the only constructor.

use core::fmt;
use std::sync::{Arc, OnceLock};

use busbar_crypto_backend as b;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::{ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm};

use crate::BACKEND;

mod tickets;
pub use tickets::{ListenerTickets, TICKET_MAX_AGE};

/// The backend refused a TLS config or component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRefused {
    /// Why.
    pub reason: &'static str,
    /// The backend that refused ([`BACKEND`]).
    pub backend: &'static str,
}

impl fmt::Display for TlsRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "crypto backend {} refused the TLS configuration: {}",
            self.backend, self.reason
        )
    }
}

impl std::error::Error for TlsRefused {}

/// Why a TLS config or verifier was not built.
#[derive(Debug)]
pub enum TlsError {
    /// The backend refused it.
    Refused(TlsRefused),
    /// rustls refused it (bad certificate, key or option).
    Rustls(rustls::Error),
    /// The verifier could not be built from these roots.
    Verifier(rustls::client::VerifierBuilderError),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => r.fmt(f),
            Self::Rustls(e) => e.fmt(f),
            Self::Verifier(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        Self::Rustls(e)
    }
}

impl From<TlsRefused> for TlsError {
    fn from(r: TlsRefused) -> Self {
        Self::Refused(r)
    }
}

fn refused(e: b::Error) -> TlsRefused {
    let reason = match e {
        b::Error::Refused { reason, .. } => reason,
        b::Error::ProviderUnavailable => "the crypto provider is unavailable",
        b::Error::Rng => "the random number generator failed",
        b::Error::Invalid(w) | b::Error::SelfTest(w) => w,
        b::Error::Mismatch => "verification failed",
    };
    TlsRefused {
        reason,
        backend: BACKEND,
    }
}

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(b::tls_provider())).clone()
}

/// A builder for a client config, protocol versions already set.
pub type ClientBuilder = ConfigBuilder<ClientConfig, rustls::WantsVerifier>;
/// A builder for a server config, protocol versions already set.
pub type ServerBuilder = ConfigBuilder<ServerConfig, rustls::WantsVerifier>;

/// A client config: `build` finishes the builder (verifier, client auth, options), then the
/// backend approves the result, which is returned frozen.
pub fn client_config(
    build: impl FnOnce(ClientBuilder) -> Result<ClientConfig, rustls::Error>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let builder =
        ClientConfig::builder_with_provider(provider()).with_protocol_versions(b::TLS_VERSIONS)?;
    let config = build(builder)?;
    b::approve_client_config(&config).map_err(refused)?;
    Ok(Arc::new(config))
}

/// A server config, built and approved like [`client_config`].
pub fn server_config(
    build: impl FnOnce(ServerBuilder) -> Result<ServerConfig, rustls::Error>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let builder =
        ServerConfig::builder_with_provider(provider()).with_protocol_versions(b::TLS_VERSIONS)?;
    let config = build(builder)?;
    b::approve_server_config(&config).map_err(refused)?;
    Ok(Arc::new(config))
}

/// The webpki server-certificate verifier for `roots`.
pub fn server_verifier(roots: Arc<RootCertStore>) -> Result<Arc<WebPkiServerVerifier>, TlsError> {
    WebPkiServerVerifier::builder_with_provider(roots, provider())
        .build()
        .map_err(TlsError::Verifier)
}

/// The webpki client-certificate verifier for `roots`; `options` sets CRLs, anonymous clients
/// and the like.
pub fn client_verifier(
    roots: Arc<RootCertStore>,
    options: impl FnOnce(ClientCertVerifierBuilder) -> ClientCertVerifierBuilder,
) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    options(WebPkiClientVerifier::builder_with_provider(
        roots,
        provider(),
    ))
    .build()
    .map_err(TlsError::Verifier)
}

/// The handshake signature algorithms, for custom verifiers.
#[must_use]
pub fn signature_algorithms() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

/// Verify a TLS 1.2 handshake signature (for custom verifiers).
pub fn verify_tls12_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &signature_algorithms())
}

/// Verify a TLS 1.3 handshake signature (for custom verifiers).
pub fn verify_tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &signature_algorithms())
}

/// The webpki certificate signature algorithms.
#[must_use]
pub fn webpki_algs() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
    b::webpki_algs()
}

/// Whether `e` is the verifier refusing a CA certificate (CA:TRUE) presented as the end entity.
#[must_use]
pub fn ca_used_as_end_entity(e: &rustls::Error) -> bool {
    b::ca_used_as_end_entity(e)
}

/// A private key loaded through the provider (for certificate resolvers).
pub fn signing_key(
    key: &rustls_pki_types::PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    provider().key_provider.load_private_key(key.clone_key())
}
