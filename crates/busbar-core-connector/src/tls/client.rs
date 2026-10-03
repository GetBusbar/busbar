// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OUTBOUND half of connection security: the client side of the one TLS path.
//!
//! A dialled connection is secured host-side exactly as an accepted one is — a transport carries
//! bytes, and core wraps them — so the host's outbound trust decisions ([`EgressTrust`]: extra trust
//! anchors, a per-destination SPKI pin, a client identity for a mutual handshake) are applied HERE,
//! never inside a transport. [`build_client_config`] turns that trust into a `rustls` client config,
//! and [`TlsDial`] is the [`ConnectionSecurity`] wrap that runs the client handshake over a dialled
//! stream for one server name. Nothing here crosses the plugin ABI: a transport sees only the opaque
//! wrap, never a certificate, a key or a rustls type.

use std::sync::Arc;

use busbar_contract::transport::trust::EgressTrust;
use busbar_contract::transport::wire::{ConnectionSecurity, RawIo, SecuredIoFut};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::tls::install_crypto_provider;

/// The platform trust anchors every outbound connection starts from.
fn webpki_roots_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// A client identity (the key and chain a mutual handshake presents) the TLS stack cannot use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadClientIdentity(pub String);

impl std::fmt::Display for BadClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the mTLS client identity does not parse: {}", self.0)
    }
}

impl std::error::Error for BadClientIdentity {}

/// The client TLS config an outbound connection is secured with, given the host's outbound trust.
///
/// The unset case is spelled FIRST and returns early down the exact branch every outbound connection
/// has always taken — platform roots, no client auth — so a caller that decided nothing is provably
/// unchanged rather than merely equal to what it was.
///
/// # Errors
///
/// A configured client identity whose private key does not parse, or whose chain the stack will not
/// accept. Never a silent fallback to no client auth: a mutual peer would then see an anonymous
/// client the operator configured to present an identity.
pub fn build_client_config(trust: &EgressTrust) -> Result<rustls::ClientConfig, BadClientIdentity> {
    install_crypto_provider();
    if trust.is_unset() {
        return Ok(rustls::ClientConfig::builder()
            .with_root_certificates(webpki_roots_store())
            .with_no_client_auth());
    }
    match &trust.client_identity {
        None => Ok(wants_client_cert(trust).with_no_client_auth()),
        Some(identity) => {
            let key = rustls_pki_types::PrivateKeyDer::try_from(identity.private_key.clone())
                .map_err(|e| BadClientIdentity(format!("private key: {e}")))?;
            let chain: Vec<rustls_pki_types::CertificateDer<'static>> = identity
                .cert_chain
                .iter()
                .cloned()
                .map(rustls_pki_types::CertificateDer::from)
                .collect();
            wants_client_cert(trust)
                .with_client_auth_cert(chain, key)
                .map_err(|e| BadClientIdentity(format!("certificate chain: {e}")))
        }
    }
}

/// [`build_client_config`] for one declared need, at boot: a bad client identity refuses the boot,
/// naming the need.
///
/// # Errors
///
/// The need's client identity does not parse; the text names the need.
pub fn need_client_config(need: &str, trust: &EgressTrust) -> Result<rustls::ClientConfig, String> {
    build_client_config(trust).map_err(|e| format!("need `{need}`: {e}; refusing to boot"))
}

/// The client config for a need whose `trust_from` names an operator CA (`pem`, the PEM the need's
/// settings hold): the public roots with every certificate of `pem` added on top as an extra trust
/// anchor (spec section 5, the host connector: "an extra trusted root added on top of the public
/// roots, as in 1.5.5"). Never a replacement for the public roots, and chain and name validation
/// stay on.
///
/// # Errors
///
/// `pem` holds no certificate, a section that does not parse, or a certificate the TLS stack will
/// not take as a trust anchor. Never a silent fallback to the public roots alone: the need is
/// refused, as an mTLS identity that fails to parse is.
pub fn operator_ca_config(pem: &[u8]) -> Result<rustls::ClientConfig, String> {
    use rustls::pki_types::pem::PemObject as _;
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the operator CA does not parse: {e}"))?;
    if certs.is_empty() {
        return Err("the operator CA holds no certificate".into());
    }
    let mut anchors = rustls::RootCertStore::empty();
    for cert in &certs {
        anchors
            .add(cert.clone())
            .map_err(|e| format!("the operator CA is not a usable trust anchor: {e}"))?;
    }
    let trust = EgressTrust {
        extra_anchors: certs.into_iter().map(|c| c.to_vec()).collect(),
        ..EgressTrust::default()
    };
    build_client_config(&trust).map_err(|e| e.to_string())
}

/// The verifier half of the client config, before the client-auth choice: platform roots plus any
/// extra anchors, and — when the host pinned any keys — an SPKI-pin check layered over the ordinary
/// chain verification.
fn wants_client_cert(
    trust: &EgressTrust,
) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert> {
    let mut roots = webpki_roots_store();
    for der in &trust.extra_anchors {
        let _ = roots.add(rustls_pki_types::CertificateDer::from(der.clone()));
    }
    let builder = rustls::ClientConfig::builder();
    if trust.pinned_public_keys.is_empty() {
        builder.with_root_certificates(roots)
    } else {
        let verifier = PinnedKeyVerifier::new(roots, &trust.pinned_public_keys);
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
    }
}

/// THE UNVERIFIED CLIENT CONFIG: the far end's certificate (its chain, its name, its validity) is
/// NOT checked, only that it signed the handshake. The operator's explicit opt-in for one need
/// (`UPGRADE_VERIFY_OFF`, 1.5.5's `rediss://…#insecure`; ARCHITECT ruling 2026-10-03 on Q-L16-4),
/// honoured for an operator-infrastructure need only (`Connector::upgrade_secure`); never a default.
#[must_use]
pub fn unverified_client_config() -> rustls::ClientConfig {
    install_crypto_provider();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptsAnyCertificate(provider)))
        .with_no_client_auth()
}

/// A verifier that accepts any certificate and checks only the handshake's signature with it.
#[derive(Debug)]
struct AcceptsAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptsAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A server-certificate verifier that runs the ordinary chain-and-name check AND then requires the
/// peer's SubjectPublicKeyInfo to hash (SHA-256) to one of the pinned values. The pin is layered
/// OVER the standard verification, never in place of it: a pinned key on an otherwise-invalid chain
/// is still a refusal.
#[derive(Debug)]
struct PinnedKeyVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
}

impl PinnedKeyVerifier {
    fn new(roots: rustls::RootCertStore, pins: &[[u8; 32]]) -> Self {
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("a root store with at least the platform anchors builds a verifier");
        Self {
            inner,
            pins: pins.to_vec(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let key_info = subject_public_key_info(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("peer certificate carries no readable key".into())
        })?;
        let digest = ::ring::digest::digest(&::ring::digest::SHA256, key_info);
        if self
            .pins
            .iter()
            .any(|pin| pin.as_slice() == digest.as_ref())
        {
            Ok(verified)
        } else {
            Err(rustls::Error::General(
                "the peer's key is not one this destination is pinned to".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// THE SubjectPublicKeyInfo of a DER certificate, whole (tag and length included), or `None` when the
/// bytes are not the DER this pin walk expects.
///
/// RFC 5280 section 4.1 read literally: `Certificate` is a `SEQUENCE` whose first member is
/// `TBSCertificate`, itself a `SEQUENCE` whose members up to the key are `[0] version DEFAULT v1`,
/// `serialNumber`, `signature`, `issuer`, `validity`, `subject`, then the SPKI. Nothing here
/// interprets a field it walks past; the TLS stack has already validated the certificate this reads a
/// key off. The pin is taken over the SPKI's whole encoding, so a pinning caller and any other tool
/// compute the same digest for one key.
fn subject_public_key_info(cert_der: &[u8]) -> Option<&[u8]> {
    /// ASN.1 SEQUENCE, constructed — the only tag this walk expects at a structural position.
    const TAG_SEQUENCE: u8 = 0x30;
    /// `[0] EXPLICIT`, the optional context tag carrying `TBSCertificate.version`.
    const TAG_VERSION: u8 = 0xA0;
    /// `serialNumber`, `signature`, `issuer`, `validity`, `subject` — the members before the SPKI.
    const MEMBERS_BEFORE_KEY: usize = 5;

    // (tag, contents, whole) of one DER element off the front of `buf`, DER-strict on length.
    fn element(buf: &[u8]) -> Option<(u8, &[u8])> {
        let (&tag, rest) = buf.split_first()?;
        let (&first_len, rest) = rest.split_first()?;
        let (len, header) = if first_len < 0x80 {
            (usize::from(first_len), 2usize)
        } else if first_len == 0x80 {
            return None; // an indefinite length is BER, not DER
        } else {
            let count = usize::from(first_len & 0x7f);
            if count > 4 {
                return None; // a length wider than any certificate needs
            }
            let bytes = rest.get(..count)?;
            if bytes.first() == Some(&0) {
                return None; // a non-minimal length
            }
            let mut len = 0usize;
            for b in bytes {
                len = (len << 8) | usize::from(*b);
            }
            if len < 0x80 {
                return None; // long form where the short form would have fit
            }
            (len, 2 + count)
        };
        let end = header.checked_add(len)?;
        let whole = buf.get(..end)?;
        Some((tag, whole))
    }

    fn expect_sequence(buf: &[u8]) -> Option<&[u8]> {
        let (tag, whole) = element(buf)?;
        (tag == TAG_SEQUENCE).then_some(whole)
    }

    fn contents(whole: &[u8]) -> Option<&[u8]> {
        // Re-read the header length off the whole element to hand back its contents.
        let first_len = *whole.get(1)?;
        let header = if first_len < 0x80 {
            2
        } else {
            2 + usize::from(first_len & 0x7f)
        };
        whole.get(header..)
    }

    let certificate = expect_sequence(cert_der)?;
    let tbs = expect_sequence(contents(certificate)?)?;
    let mut rest = contents(tbs)?;
    if rest.first() == Some(&TAG_VERSION) {
        let (_, version) = element(rest)?;
        rest = &rest[version.len()..];
    }
    for _ in 0..MEMBERS_BEFORE_KEY {
        let (_, member) = element(rest)?;
        rest = &rest[member.len()..];
    }
    expect_sequence(rest)
}

/// The client-side connection-security wrap: runs the rustls client handshake built by
/// [`build_client_config`] over a dialled stream, offering `server_name` (SNI, and the name the
/// peer's certificate is verified against).
///
/// One per dial: the name is the destination's, so it is held here rather than passed through
/// [`ConnectionSecurity::wrap`], whose one parameter is the stream.
pub struct TlsDial {
    config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl TlsDial {
    /// Wrap an already-built client config and the destination's name for the seam.
    #[must_use]
    pub fn new(
        config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Self {
        Self {
            config,
            server_name,
        }
    }
}

impl ConnectionSecurity for TlsDial {
    fn wrap<'a>(&'a self, io: Box<dyn RawIo>) -> SecuredIoFut<'a> {
        Box::pin(async move {
            let tokio_io = FuturesAsyncReadCompatExt::compat(io);
            let connector = tokio_rustls::TlsConnector::from(self.config.clone());
            let tls_stream = connector
                .connect(self.server_name.clone(), tokio_io)
                .await?;
            let raw: Box<dyn RawIo> = Box::new(TokioAsyncReadCompatExt::compat(tls_stream));
            Ok(raw)
        })
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
