// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! dimpl's DTLS crypto provider over AWS-LC (aws-lc-rs), and the per-session self-signed
//! certificate WebRTC presents. Only `busbar-crypto` calls these. A session key never leaves this
//! module: dimpl carries an opaque handle in its place, which the key provider resolves here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use aws_lc_rs::aead::{self, LessSafeKey, UnboundKey};
use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use aws_lc_rs::{digest, hmac};
use dimpl::crypto::{
    Aad, ActiveKeyExchange, Buf, Cipher, CryptoProvider, Dtls12CipherSuite, Dtls13CipherSuite,
    HashAlgorithm, HashContext, HashProvider, HmacProvider, KeyProvider, NamedGroup, Nonce,
    SecureRandom, SignatureAlgorithm, SignatureVerifier, SigningKey, SupportedDtls12CipherSuite,
    SupportedDtls13CipherSuite, SupportedKxGroup, TmpBuf,
};
use dimpl::{CryptoError, CryptoOperation};
use zeroize::Zeroizing;

use crate::Error;

/// What a key handle starts with; anything else is refused as a private key.
const HANDLE_TAG: &[u8] = b"busbar-dtls-key-handle:";

/// The random id a handle carries after [`HANDLE_TAG`]; the registry is keyed by it.
type KeyId = [u8; 16];

type KeyRegistry = Mutex<HashMap<KeyId, Arc<EcdsaKeyPair>>>;

fn key_registry() -> &'static KeyRegistry {
    static REGISTRY: OnceLock<KeyRegistry> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// The id `handle` names: [`HANDLE_TAG`] then exactly one [`KeyId`].
fn key_id(handle: &[u8]) -> Option<KeyId> {
    handle
        .strip_prefix(HANDLE_TAG)
        .and_then(|id| KeyId::try_from(id).ok())
}

/// Park `pair` and answer the handle dimpl carries in its place.
fn register_key(pair: Arc<EcdsaKeyPair>) -> Result<Vec<u8>, Error> {
    let mut id: KeyId = [0_u8; 16];
    SystemRandom::new().fill(&mut id).map_err(|_| Error::Rng)?;
    let mut handle = HANDLE_TAG.to_vec();
    handle.extend_from_slice(&id);
    key_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id, pair);
    Ok(handle)
}

/// Forget the key a handle names.
fn unregister_key(handle: &[u8]) {
    let Some(id) = key_id(handle) else {
        return;
    };
    key_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&id);
}

/// A per-session self-signed ECDSA P-256 certificate. Its private key stays parked in this
/// backend for the certificate's lifetime; [`DtlsCert::handle`] is what dimpl carries in its place
/// (`DtlsCertificate::private_key`), and only [`dtls_provider`]'s key provider resolves it.
pub struct DtlsCert {
    der: Vec<u8>,
    handle: Vec<u8>,
}

impl core::fmt::Debug for DtlsCert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DtlsCert").finish_non_exhaustive()
    }
}

impl Drop for DtlsCert {
    fn drop(&mut self) {
        unregister_key(&self.handle);
    }
}

impl DtlsCert {
    /// The certificate, DER (public).
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The opaque handle naming the parked private key (not key material).
    #[must_use]
    pub fn handle(&self) -> &[u8] {
        &self.handle
    }
}

/// Mint a fresh self-signed ECDSA P-256 certificate whose key stays in this backend.
pub fn dtls_self_signed() -> Result<DtlsCert, Error> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| Error::Rng)?;
    let pkcs8 = Zeroizing::new(pkcs8.as_ref().to_vec());
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8)
        .map_err(|_| Error::Invalid("DTLS session key"))?;
    let signer = rcgen::KeyPair::try_from(pkcs8.as_slice())
        .map_err(|_| Error::Invalid("DTLS session key for the certificate"))?;
    let cert = rcgen::CertificateParams::new(Vec::<String>::new())
        .and_then(|p| p.self_signed(&signer))
        .map_err(|_| Error::Invalid("DTLS self-signed certificate"))?;
    let der = cert.der().to_vec();
    let handle = register_key(Arc::new(pair))?;
    Ok(DtlsCert { der, handle })
}

/// The dimpl crypto provider every DTLS association is built with. The software backend always
/// provides it.
pub fn dtls_provider() -> Result<CryptoProvider, Error> {
    Ok(CryptoProvider {
        kx_groups: KX_GROUPS,
        signature_verification: &VERIFIER,
        key_provider: &KEYS,
        secure_random: &RNG,
        hash_provider: &HASHES,
        hmac_provider: &HMACS,
        cipher_suites: SUITES_12,
        dtls13_cipher_suites: SUITES_13,
    })
}

const KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &KxGroup(NamedGroup::X25519),
    &KxGroup(NamedGroup::Secp256r1),
    &KxGroup(NamedGroup::Secp384r1),
];
const SUITES_12: &[&dyn SupportedDtls12CipherSuite] = &[
    &Suite12 {
        suite: Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
        hash: HashAlgorithm::SHA256,
        key_len: 16,
    },
    &Suite12 {
        suite: Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
        hash: HashAlgorithm::SHA384,
        key_len: 32,
    },
];
const SUITES_13: &[&dyn SupportedDtls13CipherSuite] = &[&ChaCha13];
static VERIFIER: Verifier = Verifier;
static KEYS: Keys = Keys;
static RNG: Rng = Rng;
static HASHES: Hashes = Hashes;
static HMACS: Hmacs = Hmacs;

/// One AEAD key (AES-GCM or ChaCha20-Poly1305); the nonce and AAD are dimpl's.
struct Aead(LessSafeKey);

impl core::fmt::Debug for Aead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Aead")
    }
}

impl Aead {
    fn new(alg: &'static aead::Algorithm, key: &[u8]) -> Result<Self, CryptoError> {
        UnboundKey::new(alg, key)
            .map(|k| Aead(LessSafeKey::new(k)))
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::CreateCipher))
    }
}

impl Cipher for Aead {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce.0);
        self.0
            .seal_in_place_append_tag(nonce, aead::Aad::from(&aad[..]), plaintext)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Encrypt))
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce.0);
        let len = self
            .0
            .open_in_place(nonce, aead::Aad::from(&aad[..]), ciphertext.as_mut())
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Decrypt))?
            .len();
        ciphertext.truncate(len);
        Ok(())
    }
}

#[derive(Debug)]
struct Suite12 {
    suite: Dtls12CipherSuite,
    hash: HashAlgorithm,
    key_len: usize,
}

impl SupportedDtls12CipherSuite for Suite12 {
    fn suite(&self) -> Dtls12CipherSuite {
        self.suite
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }
    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, self.key_len, 4)
    }
    fn explicit_nonce_len(&self) -> usize {
        8
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        let alg = if key.len() == 16 {
            &aead::AES_128_GCM
        } else {
            &aead::AES_256_GCM
        };
        Ok(Box::new(Aead::new(alg, key)?))
    }
}

#[derive(Debug)]
struct ChaCha13;

impl SupportedDtls13CipherSuite for ChaCha13 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
    fn key_len(&self) -> usize {
        32
    }
    fn iv_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(Aead::new(&aead::CHACHA20_POLY1305, key)?))
    }
    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        let mut out = [0_u8; 16];
        if let Ok(hp) = aead::quic::HeaderProtectionKey::new(&aead::quic::CHACHA20, sn_key) {
            if let Ok(mask) = hp.new_mask(sample) {
                out[..5].copy_from_slice(&mask);
            }
        }
        out
    }
}

fn agreement_of(group: NamedGroup) -> Option<&'static agreement::Algorithm> {
    match group {
        NamedGroup::X25519 => Some(&agreement::X25519),
        NamedGroup::Secp256r1 => Some(&agreement::ECDH_P256),
        NamedGroup::Secp384r1 => Some(&agreement::ECDH_P384),
        _ => None,
    }
}

struct Exchange {
    group: NamedGroup,
    alg: &'static agreement::Algorithm,
    key: EphemeralPrivateKey,
    public: Buf,
}

impl core::fmt::Debug for Exchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Exchange")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl ActiveKeyExchange for Exchange {
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn complete(self: Box<Self>, peer: &[u8], out: &mut Buf) -> Result<(), CryptoError> {
        let group = self.group;
        agreement::agree_ephemeral(
            self.key,
            UnparsedPublicKey::new(self.alg, peer),
            CryptoError::InvalidPublicKey(group),
            |secret| {
                out.clear();
                out.extend_from_slice(secret);
                Ok(())
            },
        )
    }
    fn group(&self) -> NamedGroup {
        self.group
    }
}

#[derive(Debug)]
struct KxGroup(NamedGroup);

impl SupportedKxGroup for KxGroup {
    fn name(&self) -> NamedGroup {
        self.0
    }
    fn start_exchange(&self, mut buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let alg = agreement_of(self.0).ok_or(CryptoError::UnsupportedKeyExchangeGroup(self.0))?;
        let key = EphemeralPrivateKey::generate(alg, &SystemRandom::new())
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::GenerateEphemeralKey))?;
        let public = key
            .compute_public_key()
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputePublicKey))?;
        buf.clear();
        buf.extend_from_slice(public.as_ref());
        Ok(Box::new(Exchange {
            group: self.0,
            alg,
            key,
            public: buf,
        }))
    }
}

struct Signer(Arc<EcdsaKeyPair>);

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Signer")
    }
}

impl SigningKey for Signer {
    fn sign(&mut self, data: &[u8], hash: HashAlgorithm, out: &mut Buf) -> Result<(), CryptoError> {
        if hash != HashAlgorithm::SHA256 {
            return Err(CryptoError::SigningKeyHashMismatch {
                key_hash: HashAlgorithm::SHA256,
                requested: hash,
            });
        }
        let sig = self
            .0
            .sign(&SystemRandom::new(), data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;
        out.clear();
        out.extend_from_slice(sig.as_ref());
        Ok(())
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA256]
    }
}

#[derive(Debug)]
struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, handle: &[u8]) -> Result<Box<dyn SigningKey>, CryptoError> {
        let Some(id) = key_id(handle) else {
            return Err(CryptoError::InvalidPrivateKey);
        };
        key_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .map(|pair| Box::new(Signer(Arc::clone(pair))) as Box<dyn SigningKey>)
            .ok_or(CryptoError::InvalidPrivateKey)
    }
}

#[derive(Debug)]
struct Verifier;

impl SignatureVerifier for Verifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        sig: &[u8],
        hash: HashAlgorithm,
        alg: SignatureAlgorithm,
    ) -> Result<(), CryptoError> {
        if alg != SignatureAlgorithm::ECDSA {
            return Err(CryptoError::UnsupportedSignatureAlgorithm(alg));
        }
        let der = rustls::pki_types::CertificateDer::from(cert_der);
        let leaf = webpki::EndEntityCert::try_from(&der)
            .map_err(|_| CryptoError::CertificateParseFailed)?;
        let candidates: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = match hash {
            HashAlgorithm::SHA256 => &[
                webpki::aws_lc_rs::ECDSA_P256_SHA256,
                webpki::aws_lc_rs::ECDSA_P384_SHA256,
            ],
            HashAlgorithm::SHA384 => &[
                webpki::aws_lc_rs::ECDSA_P256_SHA384,
                webpki::aws_lc_rs::ECDSA_P384_SHA384,
            ],
            _ => return Err(CryptoError::UnsupportedSignatureAlgorithm(alg)),
        };

        if candidates
            .iter()
            .any(|a| leaf.verify_signature(*a, data, sig).is_ok())
        {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed {
                signature: alg,
                hash,
                group: NamedGroup::Secp256r1,
            })
        }
    }
}

struct Hash(digest::Context);

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hash")
    }
}

impl HashContext for Hash {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn clone_and_finalize(&self, out: &mut Buf) {
        out.clear();
        out.extend_from_slice(self.0.clone().finish().as_ref());
    }
}

#[derive(Debug)]
struct Hashes;

impl HashProvider for Hashes {
    fn create_hash(&self, alg: HashAlgorithm) -> Box<dyn HashContext> {
        let alg = match alg {
            HashAlgorithm::SHA256 => &digest::SHA256,
            HashAlgorithm::SHA384 => &digest::SHA384,
            // The trait has no Result path; a silent wrong hash is worse than a
            // clear failure.  Only SHA-256 and SHA-384 are used by DTLS 1.2 suites.
            other => panic!("unsupported DTLS hash algorithm: {other:?}"),
        };
        Box::new(Hash(digest::Context::new(alg)))
    }
}

#[derive(Debug)]
struct Hmacs;

impl HmacProvider for Hmacs {
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let alg = match hash {
            HashAlgorithm::SHA256 => hmac::HMAC_SHA256,
            HashAlgorithm::SHA384 => hmac::HMAC_SHA384,
            _ => return Err(CryptoError::UnsupportedHmacHash(hash)),
        };
        let tag = hmac::sign(&hmac::Key::new(alg, key), data);
        let tag = tag.as_ref();
        out.get_mut(..tag.len())
            .ok_or(CryptoError::OperationFailed(CryptoOperation::Sign))?
            .copy_from_slice(tag);
        Ok(tag.len())
    }
}

#[derive(Debug)]
struct Rng;

impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::FillRandom))
    }
}
