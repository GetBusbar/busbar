// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OUTBOUND half of connection security: the client side of the one TLS path.

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
            let key = rustls_pki_types::PrivateKeyDer::try_from(
                identity
                    .private_key
                    .expose(&busbar_kernel::seal::lend())
                    .clone(),
            )
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

/// The client config for a need whose `trust_from` names an operator CA (`pem`, the PEM the need's
pub fn operator_ca_config(pem: &[u8]) -> Result<rustls::ClientConfig, String> {
    let trust = EgressTrust {
        extra_anchors: operator_ca_anchors(pem)?,
        ..EgressTrust::default()
    };
    build_client_config(&trust).map_err(|e| e.to_string())
}

/// Parse and validate the public certificate roots in an operator PEM bundle.
pub fn operator_ca_anchors(pem: &[u8]) -> Result<Vec<Vec<u8>>, String> {
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
    Ok(certs.into_iter().map(|c| c.to_vec()).collect())
}

/// The verifier half of the client config, before the client-auth choice: platform roots plus any
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
#[must_use]
pub fn unverified_client_config() -> rustls::ClientConfig {
    let crypto = crate::tls::installed_crypto();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptsAnyCertificate(crypto)))
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

type RebasedPolicy = std::sync::Mutex<Option<(EgressTrust, std::sync::Weak<Sealed>)>>;

/// ONE DESTINATION'S TRUST ANCHORS, sealed for dialling (the transport pin): the far end's key pin
/// to hold every connection to, and busbar's client identity, parsed once, to present.
#[derive(Debug, Clone, Default)]
pub struct Sealed {
    /// The far end's key pin, read to its canonical spelling
    /// (`busbar_contract::transport::trust::canonical_key_pin`): what the observed key is held to.
    pub key_pin: Option<String>,
    /// The client identity to present when the far end asks for one.
    pub identity: Option<Arc<rustls::sign::CertifiedKey>>,
    /// Validated member roots; also participate in destination seal equality.
    pub extra_anchors: Vec<Vec<u8>>,
    /// The exact effective policy, with only the member roots added.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub(crate) policy: Option<EgressTrust>,
    rebased: Arc<RebasedPolicy>,
}

/// Anchors that cannot be sealed: a client identity the stack cannot use, or a key pin that names
/// no SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadAnchors {
    /// The client identity does not parse.
    Identity(BadClientIdentity),
    /// Member roots require a known, reconstructible effective TLS policy.
    Trust(String),
    /// The key pin is neither `sha256/<base64>` nor its plain base64 alias of one digest.
    KeyPin(busbar_contract::transport::trust::BadKeyPin),
}

impl std::fmt::Display for BadAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(e) => e.fmt(f),
            Self::Trust(e) => f.write_str(e),
            Self::KeyPin(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BadAnchors {}

/// SEAL `anchors` for dialling under `base` (the connector's client config, whose crypto provider
pub fn seal(
    base: Option<&rustls::ClientConfig>,
    anchors: &busbar_contract::transport::trust::Anchors,
) -> Result<Sealed, BadAnchors> {
    let key_pin = anchors
        .key_pin
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(busbar_contract::transport::trust::canonical_key_pin)
        .transpose()
        .map_err(BadAnchors::KeyPin)?;
    let identity = match &anchors.client_identity {
        None => None,
        Some(identity) => {
            let base = base.ok_or_else(|| {
                BadAnchors::Identity(BadClientIdentity(
                    "the connector secures no connection to present it on".into(),
                ))
            })?;
            let key = rustls_pki_types::PrivateKeyDer::try_from(
                identity
                    .private_key
                    .expose(&busbar_kernel::seal::lend())
                    .clone(),
            )
            .map_err(|e| BadAnchors::Identity(BadClientIdentity(format!("private key: {e}"))))?;
            let chain: Vec<rustls_pki_types::CertificateDer<'static>> = identity
                .cert_chain
                .iter()
                .cloned()
                .map(rustls_pki_types::CertificateDer::from)
                .collect();
            let certified =
                rustls::sign::CertifiedKey::from_der(chain, key, base.crypto_provider()).map_err(
                    |e| BadAnchors::Identity(BadClientIdentity(format!("certificate chain: {e}"))),
                )?;
            Some(Arc::new(certified))
        }
    };
    if !anchors.extra_anchors.is_empty() {
        return Err(BadAnchors::Trust(
            "member CA requires a known effective TLS policy".into(),
        ));
    }
    Ok(Sealed {
        key_pin,
        identity,
        ..Sealed::default()
    })
}

/// The client-certificate resolver of one dial under sealed anchors: it presents the identity when
/// the far end asks for one and records that it did, so the connection's facts say whether busbar
/// proved who it is ([`busbar_contract::transport::ConnFacts::client_identity`]).
#[derive(Debug)]
pub struct Presenting {
    identity: Arc<rustls::sign::CertifiedKey>,
    presented: Arc<std::sync::atomic::AtomicBool>,
}

impl Presenting {
    /// Present `identity`, raising `presented` when the far end asked for it.
    #[must_use]
    pub fn new(
        identity: Arc<rustls::sign::CertifiedKey>,
        presented: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            identity,
            presented,
        }
    }
}

impl rustls::client::ResolvesClientCert for Presenting {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.presented
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Some(Arc::clone(&self.identity))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// THE FAR END'S KEY PIN off its leaf certificate's DER, in the one spelling
#[must_use]
pub fn peer_key_pin(leaf_der: &[u8]) -> Option<String> {
    subject_public_key_info(leaf_der).map(busbar_contract::transport::trust::key_pin)
}

/// THE SubjectPublicKeyInfo of a DER certificate, whole (tag and length included), or `None` when the
fn subject_public_key_info(cert_der: &[u8]) -> Option<&[u8]> {
    /// `[0] EXPLICIT`, the optional context tag carrying `TBSCertificate.version`.
    const TAG_VERSION: u8 = 0xA0;
    /// `serialNumber`, `signature`, `issuer`, `validity`, `subject` — the members before the SPKI.
    const MEMBERS_BEFORE_KEY: usize = 5;

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

/// ASN.1 SEQUENCE, constructed: the only tag the DER walks here expect at a structural position.
const TAG_SEQUENCE: u8 = 0x30;

/// (tag, whole) of one DER element off the front of `buf`, DER-strict on length.
fn element(buf: &[u8]) -> Option<(u8, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first_len, rest) = rest.split_first()?;
    let (len, header) = if first_len < 0x80 {
        (usize::from(first_len), 2usize)
    } else if first_len == 0x80 {
        return None;
    } else {
        let count = usize::from(first_len & 0x7f);
        if count > 4 {
            return None;
        }
        let bytes = rest.get(..count)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        let mut len = 0usize;
        for b in bytes {
            len = (len << 8) | usize::from(*b);
        }
        if len < 0x80 {
            return None;
        }
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    let whole = buf.get(..end)?;
    Some((tag, whole))
}

/// The SEQUENCE off the front of `buf`, whole.
fn expect_sequence(buf: &[u8]) -> Option<&[u8]> {
    let (tag, whole) = element(buf)?;
    (tag == TAG_SEQUENCE).then_some(whole)
}

/// The contents of one whole DER element.
fn contents(whole: &[u8]) -> Option<&[u8]> {
    let first_len = *whole.get(1)?;
    let header = if first_len < 0x80 {
        2
    } else {
        2 + usize::from(first_len & 0x7f)
    };
    whole.get(header..)
}

/// THE CHANNEL-BINDING DIGEST of a DER certificate (RFC 5929 section 4.1, `tls-server-end-point`):
#[must_use]
pub fn end_point_digest(cert_der: &[u8]) -> &'static ring::digest::Algorithm {
    signature_hash(cert_der).unwrap_or(&ring::digest::SHA256)
}

/// The SHA-384 or SHA-512 a certificate's `signatureAlgorithm` names (RSASSA-PSS through its
fn signature_hash(cert_der: &[u8]) -> Option<&'static ring::digest::Algorithm> {
    /// ASN.1 OBJECT IDENTIFIER.
    const TAG_OID: u8 = 0x06;
    /// `[0] EXPLICIT`, `RSASSA-PSS-params.hashAlgorithm`.
    const TAG_PSS_HASH: u8 = 0xA0;
    const SHA384_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
    const SHA512_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
    const RSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
    const ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    const ECDSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
    const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    fn algorithm(identifier: &[u8]) -> Option<(&[u8], &[u8])> {
        let body = contents(expect_sequence(identifier)?)?;
        let (tag, oid) = element(body)?;
        (tag == TAG_OID).then_some((contents(oid)?, &body[oid.len()..]))
    }
    fn hash(oid: &[u8]) -> Option<&'static ring::digest::Algorithm> {
        match oid {
            SHA384_RSA | ECDSA_SHA384 | SHA384 => Some(&ring::digest::SHA384),
            SHA512_RSA | ECDSA_SHA512 | SHA512 => Some(&ring::digest::SHA512),
            _ => None,
        }
    }

    let body = contents(expect_sequence(cert_der)?)?;
    let (_, tbs) = element(body)?;
    let (oid, params) = algorithm(&body[tbs.len()..])?;
    if oid != RSA_PSS {
        return hash(oid);
    }

    let (tag, first) = element(contents(expect_sequence(params)?)?)?;
    if tag != TAG_PSS_HASH {
        return None;
    }
    hash(algorithm(contents(first)?)?.0)
}

/// The client-side connection-security wrap: runs the rustls client handshake built by
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

/// Seal a member against the policy that its connection would otherwise use.
pub fn seal_with_policy(
    base: Option<&rustls::ClientConfig>,
    policy: Option<&EgressTrust>,
    anchors: &busbar_contract::transport::trust::Anchors,
) -> Result<Sealed, BadAnchors> {
    let mut without_roots = anchors.clone();
    without_roots.extra_anchors.clear();
    let mut sealed = seal(base, &without_roots)?;
    if anchors.extra_anchors.is_empty() {
        return Ok(sealed);
    }
    let mut policy = policy.cloned().ok_or_else(|| {
        BadAnchors::Trust("member CA requires a known effective TLS policy".into())
    })?;
    let mut roots = rustls::RootCertStore::empty();
    for der in &anchors.extra_anchors {
        roots
            .add(rustls_pki_types::CertificateDer::from(der.clone()))
            .map_err(|_| BadAnchors::Trust("member CA is not a usable trust anchor".into()))?;
    }
    sealed.policy = Some(policy.clone());
    policy
        .extra_anchors
        .extend(anchors.extra_anchors.iter().cloned());
    sealed.tls = Some(Arc::new(
        build_client_config(&policy).map_err(BadAnchors::Identity)?,
    ));
    sealed.extra_anchors = anchors.extra_anchors.clone();
    Ok(sealed)
}

/// Rebind a retained member seal when the same Need is declared under a changed TLS policy.
pub(crate) fn rebase(
    sealed: &Sealed,
    policy: Option<&EgressTrust>,
) -> Result<Arc<Sealed>, BadAnchors> {
    let mut policy = policy.cloned().ok_or_else(|| {
        BadAnchors::Trust("member CA requires a known effective TLS policy".into())
    })?;
    let mut cached = sealed.rebased.lock().expect("member TLS policy");
    if let Some((held, weak)) = cached.as_ref() {
        if held == &policy {
            if let Some(current) = weak.upgrade() {
                return Ok(current);
            }
        }
    }
    let current = policy.clone();
    let mut refreshed = sealed.clone();
    refreshed.policy = Some(policy.clone());
    policy
        .extra_anchors
        .extend(sealed.extra_anchors.iter().cloned());
    refreshed.tls = Some(Arc::new(
        build_client_config(&policy).map_err(BadAnchors::Identity)?,
    ));
    let refreshed = Arc::new(refreshed);
    *cached = Some((current, Arc::downgrade(&refreshed)));
    Ok(refreshed)
}
