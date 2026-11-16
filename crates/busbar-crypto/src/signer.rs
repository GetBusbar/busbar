// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signer seam (CRYPTO-SEAM §2.6): who signs audit stamps, and the one place their signatures
//! are checked. Encodings are fixed: Ed25519 raw 32/64 bytes; P-256 keys SEC 1 uncompressed (65
//! bytes) and signatures fixed `r || s` (64 bytes) with low S.

use core::fmt;

use crate::{ecdsa_p256, ed25519, map, sha256, Error};

/// A signature algorithm the seam accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigAlg {
    /// Ed25519.
    Ed25519,
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
}

impl SigAlg {
    /// The configuration and stamp spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }
}

/// A signer's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Its algorithm.
    pub alg: SigAlg,
    /// Its encoding (see the module docs).
    pub bytes: Box<[u8]>,
    /// `hex(sha256(bytes)[..8])`.
    pub key_id: Box<str>,
}

impl PublicKey {
    /// The key `bytes` under `alg`, with its key id.
    #[must_use]
    pub fn new(alg: SigAlg, bytes: &[u8]) -> Self {
        let d = sha256(bytes);
        let mut key_id = String::with_capacity(16);
        for b in &d[..8] {
            key_id.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            key_id.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
        }
        Self {
            alg,
            bytes: bytes.into(),
            key_id: key_id.into(),
        }
    }
}

/// Where a signer's private key operation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// In this process, under the linked backend.
    ThisModule,
    /// Outside it (KMS, HSM, Vault); `attested` when the operator attests the external module.
    External {
        /// Whether the operator attested the external module.
        attested: bool,
    },
}

/// Why a signer did not sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The crypto layer refused or failed.
    Crypto(Error),
    /// The signer is unreachable or timed out; nothing was written.
    Unavailable(String),
    /// The signer answered with something that does not verify.
    InvalidSignature,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => e.fmt(f),
            Self::Unavailable(w) => write!(f, "signer unavailable: {w}"),
            Self::InvalidSignature => f.write_str("the signer returned an invalid signature"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<Error> for SignError {
    fn from(e: Error) -> Self {
        Self::Crypto(e)
    }
}

/// A key that signs off the request path.
pub trait Signer: Send + Sync {
    /// The public key.
    fn public_key(&self) -> &PublicKey;
    /// Where the private key operation runs.
    fn boundary(&self) -> Boundary {
        Boundary::ThisModule
    }
    /// Append the signature of `msg` to `out`. Blocking; never on the request path. An
    /// out-of-process signer verifies before returning `Ok`.
    fn sign(&self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), SignError>;
}

/// An in-process Ed25519 signer.
#[derive(Debug)]
pub struct LocalSigner {
    key: ed25519::SigningKey,
    public: PublicKey,
}

impl LocalSigner {
    /// The signer whose Ed25519 seed is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Error> {
        let key = ed25519::SigningKey::from_seed(seed)?;
        let public = PublicKey::new(SigAlg::Ed25519, &key.verifying_key().to_bytes());
        Ok(Self { key, public })
    }

    /// The signing key.
    #[must_use]
    pub fn signing_key(&self) -> &ed25519::SigningKey {
        &self.key
    }
}

impl Signer for LocalSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), SignError> {
        out.extend_from_slice(&self.key.sign(msg));
        Ok(())
    }
}

/// A fresh in-process notary key, private to this boot. The Bootstrap capability certifies its
/// public key; this type never exposes the seed or the backend signing-key object.
pub struct DelegatedSigner {
    local: LocalSigner,
}

impl DelegatedSigner {
    /// Generate a key through the linked backend. The backend wipes its temporary seed on both
    /// success and failure and wipes the retained seed when the key is dropped.
    pub fn generate() -> Result<Self, Error> {
        let key = ed25519::SigningKey::generate()?;
        let public = PublicKey::new(SigAlg::Ed25519, &key.verifying_key().to_bytes());
        Ok(Self {
            local: LocalSigner { key, public },
        })
    }
}

impl fmt::Debug for DelegatedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedSigner")
            .field("key_id", &self.local.public.key_id)
            .finish_non_exhaustive()
    }
}

impl Signer for DelegatedSigner {
    fn public_key(&self) -> &PublicKey {
        self.local.public_key()
    }

    fn sign(&self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), SignError> {
        self.local.sign(msg, out)
    }
}

/// Verify a seam signature: `Err(Mismatch)` for a bad signature, `Err(Invalid)` for any encoding
/// other than the fixed ones (including a high-S P-256 signature).
pub fn verify(key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    match key.alg {
        SigAlg::Ed25519 => {
            let pk: &[u8; 32] = key
                .bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::Invalid("Ed25519 public key is not 32 bytes"))?;
            let sig: &[u8; 64] = sig
                .try_into()
                .map_err(|_| Error::Invalid("Ed25519 signature is not 64 bytes"))?;
            ed25519::VerifyingKey::from_bytes(pk)?.verify_strict(msg, sig)
        }
        SigAlg::EcdsaP256Sha256 => {
            if key.bytes.len() != 65 || key.bytes[0] != 0x04 {
                return Err(Error::Invalid(
                    "P-256 public key is not SEC 1 uncompressed (65 bytes)",
                ));
            }
            let sig: &[u8; 64] = sig
                .try_into()
                .map_err(|_| Error::Invalid("P-256 signature is not fixed r || s (64 bytes)"))?;
            if !ecdsa_p256::is_low_s(sig) {
                return Err(Error::Invalid("P-256 signature has a high S"));
            }
            ecdsa_p256::verify_fixed(&key.bytes, msg, sig)
        }
    }
}

/// Whether `signer` may sign under the linked backend.
pub fn approve_signer(signer: &dyn Signer) -> Result<(), Error> {
    let (external, attested) = match signer.boundary() {
        Boundary::ThisModule => (false, false),
        Boundary::External { attested } => (true, attested),
    };
    busbar_crypto_backend::approve_signer(external, attested).map_err(map)
}
