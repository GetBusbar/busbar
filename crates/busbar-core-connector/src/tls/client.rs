// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OUTBOUND half of connection security: the client side of the one TLS path.

use std::sync::Arc;

use busbar_contract::crypto::tls as crypto_tls;
use busbar_contract::transport::trust::EgressTrust;
use busbar_contract::transport::wire::{ConnectionSecurity, RawIo, SecuredIo, SecuredIoFut};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

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
/// Built through the crypto backend (`busbar_contract::crypto::tls`), which approves it; a
/// refusal is reported as the identity error the caller already handles.
pub fn build_client_config(trust: &EgressTrust) -> Result<rustls::ClientConfig, BadClientIdentity> {
    crate::off_path::tls::build_client_config(trust)
}

/// The client config for a need whose `trust_from` names an operator CA (`pem`, the PEM the need's
/// destination holds).
pub fn operator_ca_config(pem: &[u8]) -> Result<rustls::ClientConfig, String> {
    crate::off_path::tls::operator_ca_config(pem)
}

/// Parse and validate the public certificate roots in an operator PEM bundle.
pub fn operator_ca_anchors(pem: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    crate::off_path::tls::operator_ca_anchors(pem)
}

/// THE UNVERIFIED CLIENT CONFIG: the far end's certificate (its chain, its name, its validity) is
/// not checked; built through the crypto backend, which may refuse it.
pub fn unverified_client_config() -> Result<Arc<rustls::ClientConfig>, crypto_tls::TlsError> {
    let verifier = Arc::new(AcceptsAnyCertificate(crypto_tls::signature_algorithms()));
    crypto_tls::client_config(|builder| {
        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth())
    })
}

/// A verifier that accepts any certificate and checks only the handshake's signature with it.
#[derive(Debug)]
struct AcceptsAnyCertificate(rustls::crypto::WebPkiSupportedAlgorithms);

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
        crypto_tls::verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        crypto_tls::verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// A server-certificate verifier that runs the ordinary chain-and-name check AND then requires the
/// peer's SubjectPublicKeyInfo to hash (SHA-256) to one of the pinned values. The pin is layered
/// OVER the standard verification, never in place of it: a pinned key on an otherwise-invalid chain
/// is still a refusal.
#[derive(Debug)]
pub(crate) struct PinnedKeyVerifier {
    pub(crate) inner: Arc<rustls::client::WebPkiServerVerifier>,
    /// The pinned SPKI digests, looked up by the handshake's digest.
    pub(crate) pins: foldhash::HashSet<[u8; 32]>,
}

impl PinnedKeyVerifier {
    /// The verifier over `roots` holding the peer to `pins`, or why it cannot be built (an empty
    /// root store, as `advanced.tls.roots: none` with no anchor gives): a refusal, never a panic.
    pub(crate) fn try_new(roots: rustls::RootCertStore, pins: &[[u8; 32]]) -> Result<Self, String> {
        crate::off_path::tls::pinned_key_verifier(roots, pins)
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
        let digest = busbar_contract::crypto::sha256(key_info);
        if self.pins.contains(&digest) {
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
    let (key_pin, identity) = crate::off_path::tls::seal_parts(base, anchors)?;
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
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // Only mark as presented when the key can actually sign with one of
        // the offered schemes.  If it cannot, rustls sends an empty
        // Certificate message -- setting the flag before that check would
        // make ConnFacts.client_identity report a presentation that never
        // happened.
        self.identity.key.choose_scheme(sigschemes)?;
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

/// A hash RFC 5929 `tls-server-end-point` may pick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256 (also the stand-in for MD5, SHA-1 and unknown algorithms).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlg {
    /// The digest of `data` under this hash, held inline (no allocation per connection).
    #[must_use]
    pub(crate) fn digest(self, data: &[u8]) -> EndPointDigest {
        let mut bytes = [0u8; 64];
        let len = match self {
            Self::Sha256 => {
                bytes[..32].copy_from_slice(&busbar_contract::crypto::sha256(data));
                32
            }
            Self::Sha384 => {
                bytes[..48].copy_from_slice(&busbar_contract::crypto::sha384(data));
                48
            }
            Self::Sha512 => {
                bytes = busbar_contract::crypto::sha512(data);
                64
            }
        };
        EndPointDigest { bytes, len }
    }
}

/// A `tls-server-end-point` digest: the hash's bytes (at most SHA-512's 64), held inline.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EndPointDigest {
    bytes: [u8; 64],
    len: usize,
}

impl AsRef<[u8]> for EndPointDigest {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl std::ops::Deref for EndPointDigest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// THE CHANNEL-BINDING DIGEST of a DER certificate (RFC 5929 section 4.1, `tls-server-end-point`):
#[must_use]
pub fn end_point_digest(cert_der: &[u8]) -> DigestAlg {
    signature_hash(cert_der).unwrap_or(DigestAlg::Sha256)
}

/// The SHA-384 or SHA-512 a certificate's `signatureAlgorithm` names (RSASSA-PSS through its
fn signature_hash(cert_der: &[u8]) -> Option<DigestAlg> {
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
    fn hash(oid: &[u8]) -> Option<DigestAlg> {
        match oid {
            SHA384_RSA | ECDSA_SHA384 | SHA384 => Some(DigestAlg::Sha384),
            SHA512_RSA | ECDSA_SHA512 | SHA512 => Some(DigestAlg::Sha512),
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
            Ok(SecuredIo::anonymous(raw))
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
    let extra_anchors = std::mem::take(&mut without_roots.extra_anchors);
    let mut sealed = seal(base, &without_roots)?;
    if extra_anchors.is_empty() {
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
    sealed.extra_anchors = extra_anchors;
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
