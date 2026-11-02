// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signature over a sealed record's digest, minted in the process that sealed it.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroize as _;

/// The domain this signature is FOR, and the first bytes of every preimage.

pub const SIGNATURE_DOMAIN: &str = "busbar.audit.record.v1";

/// The domain a LEDGER CHECKPOINT signature is for — the second use of the one audit key.

pub const CHECKPOINT_SIGNATURE_DOMAIN: &str = "busbar.ledger.checkpoint.v1";

/// The signature algorithm, named in the key set so a verifier never has to infer it from a length.
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

/// How many bytes of the public key's SHA-256 make a key identifier. Eight — sixteen hex

const KEY_ID_BYTES: usize = 8;

/// The exact bytes an ed25519 signature over one record's digest is computed over.

#[must_use]
pub fn signing_preimage(digest_hex: &str) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + digest_hex.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(digest_hex.as_bytes());
    preimage
}

/// The exact bytes a checkpoint signature is computed over.

#[must_use]
pub fn checkpoint_preimage(body: &[u8]) -> Vec<u8> {
    let digest_hex = crate::digest::sha256_hex(body);
    let mut preimage = Vec::with_capacity(CHECKPOINT_SIGNATURE_DOMAIN.len() + 1 + digest_hex.len());
    preimage.extend_from_slice(CHECKPOINT_SIGNATURE_DOMAIN.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(digest_hex.as_bytes());
    preimage
}

/// Lowercase hexadecimal, the one spelling everything here reads and writes.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// What went wrong reading a key, said WITHOUT quoting the thing that went wrong.
///
/// Every variant is a whole-input judgement. None of them carries the text, a character from it, or
/// an offset into it, because the input to the signing-key reader is a SECRET and an error message
/// is the least controlled thing in a process — it goes to a log, a terminal, a bug report, a
/// support ticket. "Which character was bad" is a byte of the secret, and "at index 31" narrows the
/// rest. A reader who needs more than "that is not a 64-character lowercase hex seed" is asking the
/// wrong component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The text is not exactly the expected number of hexadecimal characters.
    WrongLength,
    /// The text holds something that is not a lowercase hexadecimal digit.
    NotHex,
    /// The bytes decode, but not to a usable ed25519 public key.
    NotAKey,
    /// A public key on a small-order subgroup: it would verify signatures nobody minted.
    WeakKey,
    /// The signature text is not 128 lowercase hexadecimal characters.
    MalformedSignature,
    /// The signature does not verify against the key.
    BadSignature,
    /// The record does not hash to its own fields: it was edited after it was sealed, whatever its
    /// signature says. A different finding from [`KeyError::BadSignature`], which points at the key.
    DigestMismatch,
    /// The record carries no signature, so there is nothing to check.
    Unsigned,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let said = match self {
            KeyError::WrongLength => "the key text is not the expected number of hex characters",
            KeyError::NotHex => "the key text is not lowercase hexadecimal",
            KeyError::NotAKey => "those bytes are not an ed25519 public key",
            KeyError::WeakKey => {
                "that ed25519 public key is on a small-order subgroup and would verify anything"
            }
            KeyError::MalformedSignature => {
                "the signature is not 128 lowercase hexadecimal characters"
            }
            KeyError::BadSignature => "the signature does not verify against this key",
            KeyError::DigestMismatch => {
                "the record does not hash to its own fields: it was edited after it was sealed"
            }
            KeyError::Unsigned => "the record carries no signature to check",
        };
        f.write_str(said)
    }
}

impl std::error::Error for KeyError {}

/// Decode lowercase hex into exactly `N` bytes, saying nothing about WHAT was wrong with it.

fn from_hex_exact<const N: usize>(text: &str) -> Result<[u8; N], KeyError> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(KeyError::WrongLength);
    }

    let mut out = zeroize::Zeroizing::new([0u8; N]);
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(*out)
}

/// One lowercase hex digit's value, or [`KeyError::NotHex`] — which does not say which digit.
fn nibble(c: u8) -> Result<u8, KeyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(KeyError::NotHex),
    }
}

/// The identifier for one public key: the first [`KEY_ID_BYTES`] bytes of its SHA-256, in lowercase

#[must_use]
pub fn key_id_of(public_key: &VerifyingKey) -> String {
    let digest = crate::digest::sha256_hex(public_key.as_bytes());

    digest[..KEY_ID_BYTES * 2].to_string()
}

/// THE NODE'S AUDIT SIGNING KEY. The secret half never leaves this type.

pub struct AuditSigningKey {
    inner: SigningKey,
    key_id: String,
}

/// PRINTS THE IDENTIFIER AND NOTHING ELSE.

impl std::fmt::Debug for AuditSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSigningKey")
            .field("key_id", &self.key_id)
            .field("algorithm", &SIGNATURE_ALGORITHM)
            .finish_non_exhaustive()
    }
}

impl AuditSigningKey {
    /// Build one from a 32-byte ed25519 seed.

    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = SigningKey::from_bytes(seed);
        let key_id = key_id_of(&inner.verifying_key());
        AuditSigningKey { inner, key_id }
    }

    /// Build one from 64 lowercase hex characters.

    pub fn from_hex_seed(text: &str) -> Result<Self, KeyError> {
        let mut seed = from_hex_exact::<32>(text.trim())?;
        let key = AuditSigningKey::from_seed(&seed);
        seed.zeroize();
        Ok(key)
    }

    /// This key's identifier — the only thing about it that goes into a record.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// A 32-BYTE SECRET DERIVED FROM THIS KEY under `label`: HMAC-SHA256 keyed by the seed, over

    #[must_use]
    pub fn derived_secret(&self, label: &[u8]) -> [u8; 32] {
        let mut seed = self.inner.to_bytes();
        let out = crate::wiped::hmac_sha256(&seed, label);
        seed.zeroize();
        out
    }

    /// The public half, for the key-set verb.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    /// The public half as 64 lowercase hex characters.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        to_hex(self.inner.verifying_key().as_bytes())
    }

    /// Sign one record's digest. The answer is 128 lowercase hex characters.

    #[must_use]
    pub fn sign_digest(&self, digest_hex: &str) -> String {
        to_hex(&self.inner.sign(&signing_preimage(digest_hex)).to_bytes())
    }
}

impl AuditSigningKey {
    /// Sign one ledger checkpoint's body: 64 raw ed25519 signature bytes over

    #[must_use]
    pub fn sign_checkpoint_body(&self, body: &[u8]) -> Vec<u8> {
        self.inner
            .sign(&checkpoint_preimage(body))
            .to_bytes()
            .to_vec()
    }
}

/// The public half of a signing key, as a verifier holds it.
///
/// A thin wrapper rather than a bare `VerifyingKey` so that the identifier is computed once, by the
/// same rule the signer used, instead of at each of a verifier's call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyingKey {
    inner: VerifyingKey,
    key_id: String,
}

impl AuditVerifyingKey {
    /// Read one from 64 lowercase hex characters, refusing a small-order point.

    pub fn from_hex(text: &str) -> Result<Self, KeyError> {
        let bytes = from_hex_exact::<32>(text.trim())?;
        let inner = VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::NotAKey)?;
        if inner.is_weak() {
            return Err(KeyError::WeakKey);
        }
        let key_id = key_id_of(&inner);
        Ok(AuditVerifyingKey { inner, key_id })
    }

    /// The identifier a record names this key by.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The key as 64 lowercase hex characters.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        to_hex(self.inner.as_bytes())
    }

    /// Check one signature over one digest.

    pub fn verify_digest(&self, digest_hex: &str, signature_hex: &str) -> Result<(), KeyError> {
        let raw =
            from_hex_exact::<64>(signature_hex.trim()).map_err(|_| KeyError::MalformedSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&raw);
        self.inner
            .verify_strict(&signing_preimage(digest_hex), &signature)
            .map_err(|_| KeyError::BadSignature)
    }
}

/// THE PUBLIC KEY SET, as the key-set admin verb answers it.
///
/// A set rather than a key, because a node that has rotated has signed records under more than one
/// key and a verifier reading a year of history needs all of them. Keys are only ever ADDED: a key
/// removed from this set makes every record it signed unverifiable, which is indistinguishable from
/// those records having been forged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditKeySet {
    keys: Vec<AuditVerifyingKey>,
}

impl AuditKeySet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        AuditKeySet::default()
    }

    /// Add a key. A key already in the set is not added twice.
    pub fn insert(&mut self, key: AuditVerifyingKey) {
        if !self.keys.iter().any(|k| k.key_id == key.key_id) {
            self.keys.push(key);
        }
    }

    /// The key one identifier names, if the set holds it.
    #[must_use]
    pub fn get(&self, key_id: &str) -> Option<&AuditVerifyingKey> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }

    /// Every key in the set, in the order they were added.
    #[must_use]
    pub fn keys(&self) -> &[AuditVerifyingKey] {
        &self.keys
    }

    /// Check one ledger checkpoint's signature against EVERY key in the set.

    pub fn verify_checkpoint_body(&self, body: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        let raw: [u8; 64] = signature
            .try_into()
            .map_err(|_| KeyError::MalformedSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&raw);
        let preimage = checkpoint_preimage(body);
        if self
            .keys
            .iter()
            .any(|k| k.inner.verify_strict(&preimage, &signature).is_ok())
        {
            Ok(())
        } else {
            Err(KeyError::BadSignature)
        }
    }

    /// Whether the set holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}
