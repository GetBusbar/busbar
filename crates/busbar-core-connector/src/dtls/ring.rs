// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! dimpl's crypto provider on RING — the tree's one crypto backend, the same one rustls runs on
//! (Cargo.toml: "no second crypto backend enters").
//!
//! * DTLS 1.2: `ECDHE_ECDSA_AES128_GCM_SHA256` and `ECDHE_ECDSA_AES256_GCM_SHA384` (ring AEAD).
//! * Key exchange: X25519, P-256, P-384 (ring agreement).
//! * The host's own key: an ECDSA P-256 ring key pair [`super::SessionCert`] generates and keeps.
//!   dimpl never receives the key's bytes: the "private key" it is handed is a HANDLE
//!   ([`register_key`]) this provider resolves to the key pair, so no copy of the key passes
//!   through dimpl's buffers. Only SHA-256 signatures — ring fixes the hash when the key is loaded.
//! * The peer's signature: verified against the leaf certificate through rustls-webpki's ring
//!   algorithms, the same verifier rustls uses.
//! * DTLS 1.3: dimpl refuses a provider without a 1.3 suite. ring's QUIC header protection is
//!   exactly the record-number mask for ChaCha20 (dimpl checks its first 5 bytes), so
//!   `TLS_CHACHA20_POLY1305_SHA256` is offered to satisfy it. The AES-GCM 1.3 suites need a full
//!   16-byte AES-ECB block, which ring does not expose. Associations are built DTLS 1.2
//!   (`Dtls::new_12`), the version every browser's media stack speaks.

use dimpl::crypto::{
    Aad, ActiveKeyExchange, Buf, Cipher, CryptoProvider, Dtls12CipherSuite, Dtls13CipherSuite,
    HashAlgorithm, HashContext, HashProvider, HmacProvider, KeyProvider, NamedGroup, Nonce,
    SecureRandom, SignatureAlgorithm, SignatureVerifier, SigningKey, SupportedDtls12CipherSuite,
    SupportedDtls13CipherSuite, SupportedKxGroup, TmpBuf,
};
use dimpl::{CryptoError, CryptoOperation};
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::{digest, hmac, signature};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// What a key handle starts with; anything else is refused as a private key.
const HANDLE_TAG: &[u8] = b"busbar-dtls-key-handle:";

type KeyRegistry = Mutex<HashMap<Vec<u8>, Arc<signature::EcdsaKeyPair>>>;

fn key_registry() -> &'static KeyRegistry {
    static REGISTRY: OnceLock<KeyRegistry> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// Park `pair` and answer the handle dimpl carries in its place.
pub(crate) fn register_key(pair: Arc<signature::EcdsaKeyPair>) -> Result<Vec<u8>, CryptoError> {
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| CryptoError::OperationFailed(CryptoOperation::FillRandom))?;
    let mut handle = HANDLE_TAG.to_vec();
    handle.extend_from_slice(&id);
    key_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(handle.clone(), pair);
    Ok(handle)
}

/// Forget the key a handle names.
pub(crate) fn unregister_key(handle: &[u8]) {
    key_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(handle);
}

/// The provider every association is built with.
pub(crate) fn provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: KX_GROUPS,
        signature_verification: &VERIFIER,
        key_provider: &KEYS,
        secure_random: &RNG,
        hash_provider: &HASHES,
        hmac_provider: &HMACS,
        cipher_suites: SUITES_12,
        dtls13_cipher_suites: SUITES_13,
    }
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

// ── AEAD ────────────────────────────────────────────────────────────────────────────────────────

/// One ring AEAD key (AES-GCM or ChaCha20-Poly1305); the nonce and AAD are dimpl's.
struct Aead(LessSafeKey);

impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        // (mac key, encryption key, fixed IV): AEAD, so no MAC key; a 4-byte implicit IV.
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
        // The record-number mask is the QUIC header-protection mask (RFC 9147 §4.2.3,
        // RFC 9001 §5.4.4); a DTLS 1.3 record number is at most 2 bytes, well inside the 5 ring
        // returns.
        let mut out = [0_u8; 16];
        if let Ok(hp) = aead::quic::HeaderProtectionKey::new(&aead::quic::CHACHA20, sn_key) {
            if let Ok(mask) = hp.new_mask(sample) {
                out[..5].copy_from_slice(&mask);
            }
        }
        out
    }
}

// ── key exchange ────────────────────────────────────────────────────────────────────────────────

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

impl std::fmt::Debug for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        // ring's agree_ephemeral rejects a non-contributory (all-zero) X25519 secret itself.
        agreement::agree_ephemeral(
            self.key,
            &UnparsedPublicKey::new(self.alg, peer),
            |secret| {
                out.clear();
                out.extend_from_slice(secret);
            },
        )
        .map_err(|_| CryptoError::InvalidPublicKey(group))
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

// ── signing and verification ────────────────────────────────────────────────────────────────────

struct Signer(Arc<signature::EcdsaKeyPair>);

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        if !handle.starts_with(HANDLE_TAG) {
            // Key bytes are never accepted here: the host's keys reach dimpl only as handles.
            return Err(CryptoError::InvalidPrivateKey);
        }
        key_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(handle)
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
        let der = rustls_pki_types::CertificateDer::from(cert_der);
        let leaf = webpki::EndEntityCert::try_from(&der)
            .map_err(|_| CryptoError::CertificateParseFailed)?;
        let candidates: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = match hash {
            HashAlgorithm::SHA256 => &[
                webpki::ring::ECDSA_P256_SHA256,
                webpki::ring::ECDSA_P384_SHA256,
            ],
            HashAlgorithm::SHA384 => &[
                webpki::ring::ECDSA_P256_SHA384,
                webpki::ring::ECDSA_P384_SHA384,
            ],
            _ => return Err(CryptoError::UnsupportedSignatureAlgorithm(alg)),
        };
        // webpki refuses an algorithm whose curve is not the certificate key's own, so exactly
        // the matching candidate can verify.
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

// ── hash, hmac, random ──────────────────────────────────────────────────────────────────────────

struct Hash(digest::Context);

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        let alg = if alg == HashAlgorithm::SHA384 {
            &digest::SHA384
        } else {
            &digest::SHA256
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
