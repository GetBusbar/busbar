// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The rustls provider, the webpki algorithms and the TLS approval hooks. Only `busbar-crypto`
//! calls these; the provider never becomes the rustls process default.

use std::sync::Arc;

use crate::Error;

/// The protocol versions every config is built with.
pub static TLS_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// The rustls provider: AWS-LC's.
#[must_use]
pub fn tls_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// A session-ticket producer (AES-256-GCM tickets under a rotating key).
pub fn ticketer() -> Result<Arc<dyn rustls::server::ProducesTickets>, Error> {
    rustls::crypto::aws_lc_rs::Ticketer::new().map_err(|_| Error::Rng)
}

static WEBPKI_ALGS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ED25519,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// The signature algorithms webpki verifies certificates with.
#[must_use]
pub fn webpki_algs() -> &'static [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm] {
    WEBPKI_ALGS
}

/// Whether `e` is the verifier refusing a CA certificate (CA:TRUE) presented as the end entity.
#[must_use]
pub fn ca_used_as_end_entity(e: &rustls::Error) -> bool {
    matches!(
        e,
        rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other))
            if matches!(
                other.0.downcast_ref::<webpki::Error>(),
                Some(webpki::Error::CaUsedAsEndEntity)
            )
    )
}

/// Whether a built client config may be used. The software backend approves every config.
pub fn approve_client_config(config: &rustls::ClientConfig) -> Result<(), Error> {
    let _ = config;
    Ok(())
}

/// Whether a built server config may be used. The software backend approves every config.
pub fn approve_server_config(config: &rustls::ServerConfig) -> Result<(), Error> {
    let _ = config;
    Ok(())
}
