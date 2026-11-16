// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signature over a sealed record's digest, minted in the process that sealed it.

use busbar_contract::crypto::ed25519::{self, SigningKey, VerifyingKey};

/// The domain this signature is FOR, and the first bytes of every preimage.
pub const SIGNATURE_DOMAIN: &str = "busbar.audit.record.v1";

/// The domain a LEDGER CHECKPOINT signature is for — the second use of the one audit key.
pub const CHECKPOINT_SIGNATURE_DOMAIN: &str = "busbar.ledger.checkpoint.v1";

/// The signature algorithm, named in the key set so a verifier never has to infer it from a length.
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

/// How many bytes of the public key's SHA-256 make a key identifier. Eight — sixteen hex
const KEY_ID_BYTES: usize = 8;

// A digest longer than a SHA-256 in hex is framed out of line, in the cold module.
pub use crate::cold::signing_preimage;

/// How long a record preimage over a SHA-256 in hex is: the domain, a NUL, and 64 characters.
const RECORD_PREIMAGE_BYTES: usize = SIGNATURE_DOMAIN.len() + 1 + 64;

/// Hand [`signing_preimage`]'s bytes to `use_it`, framed on the stack when the digest is a SHA-256
/// in hex — which every digest this crate seals is.
fn with_signing_preimage<R>(digest_hex: &str, use_it: impl FnOnce(&[u8]) -> R) -> R {
    let len = SIGNATURE_DOMAIN.len() + 1 + digest_hex.len();
    if len > RECORD_PREIMAGE_BYTES {
        return use_it(&signing_preimage(digest_hex));
    }
    let mut preimage = [0u8; RECORD_PREIMAGE_BYTES];
    preimage[..SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN.as_bytes());
    preimage[SIGNATURE_DOMAIN.len() + 1..len].copy_from_slice(digest_hex.as_bytes());
    use_it(&preimage[..len])
}

/// How long a checkpoint preimage is: the domain, a NUL, and the body's SHA-256 in hex.
pub const CHECKPOINT_PREIMAGE_BYTES: usize = CHECKPOINT_SIGNATURE_DOMAIN.len() + 1 + 64;

/// The exact bytes a checkpoint signature is computed over.
#[must_use]
pub fn checkpoint_preimage(body: &[u8]) -> [u8; CHECKPOINT_PREIMAGE_BYTES] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = busbar_contract::crypto::sha256(body);
    let mut preimage = [0u8; CHECKPOINT_PREIMAGE_BYTES];
    let domain = CHECKPOINT_SIGNATURE_DOMAIN.len();
    preimage[..domain].copy_from_slice(CHECKPOINT_SIGNATURE_DOMAIN.as_bytes());
    for (i, byte) in digest.iter().enumerate() {
        preimage[domain + 1 + 2 * i] = HEX[usize::from(byte >> 4)];
        preimage[domain + 2 + 2 * i] = HEX[usize::from(byte & 0x0f)];
    }
    preimage
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
    from_hex_secret::<N>(text).map(|secret| *secret)
}

/// [`from_hex_exact`], the bytes held where they are wiped when dropped: for a secret seed.
pub(crate) fn from_hex_secret<const N: usize>(
    text: &str,
) -> Result<busbar_contract::secure::SecureArray<N>, KeyError> {
    if text.len() != N * 2 {
        return Err(KeyError::WrongLength);
    }
    if text.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(KeyError::NotHex);
    }
    let mut out = busbar_contract::secure::SecureArray::<N>::zeroed();
    hex::decode_to_slice(text, &mut out[..]).map_err(|_| KeyError::NotHex)?;
    Ok(out)
}

/// The identifier for one public key: the first [`KEY_ID_BYTES`] bytes of its SHA-256, in lowercase
#[must_use]
pub fn key_id_of(public_key: &VerifyingKey) -> String {
    let mut digest = crate::digest::sha256_hex(&public_key.to_bytes());

    digest.truncate(KEY_ID_BYTES * 2);
    digest
}

/// THE NODE'S AUDIT SIGNING KEY. The secret half never leaves this type.
pub struct AuditSigningKey {
    inner: SigningKey,
    key_id: std::sync::Arc<str>,
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
    /// A key from its parts, as loading one built them (see `AuditSigningKey::from_seed`, which runs
    /// once, when the node is configured).
    pub(crate) fn from_parts(inner: SigningKey, key_id: std::sync::Arc<str>) -> Self {
        AuditSigningKey { inner, key_id }
    }

    /// This key's identifier — the only thing about it that goes into a record.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The key id, shared: every record this key signs names it without a copy.
    pub(crate) fn key_id_shared(&self) -> std::sync::Arc<str> {
        std::sync::Arc::clone(&self.key_id)
    }

    /// The seed, for [`AuditSigningKey::into_grants`] alone: the crypto seam's signer is built from
    /// it once, when the key is consumed into its two grants.
    pub(crate) fn seed_bytes(&self) -> &[u8; 32] {
        self.inner.seed()
    }

    /// A 32-BYTE SECRET DERIVED FROM THIS KEY under `label`: HMAC-SHA256 keyed by the seed, over
    #[must_use]
    pub fn derived_secret(&self, label: &[u8]) -> [u8; 32] {
        let seed = self.inner.seed();
        // A 32-byte key: no backend refuses it (FIPS's floor is 14 bytes).
        let out = busbar_contract::crypto::hmac_sha256(seed, label);
        match out {
            Ok(mac) => mac,
            Err(e) => panic!("crypto backend refused HMAC-SHA256 under a 32-byte key: {e}"),
        }
    }

    /// The public half, for the key-set verb.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    /// The public half as 64 lowercase hex characters.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.verifying_key().to_bytes())
    }

    /// Sign one record's digest. The answer is 128 lowercase hex characters.
    #[must_use]
    pub fn sign_digest(&self, digest_hex: &str) -> String {
        hex::encode(with_signing_preimage(digest_hex, |preimage| {
            self.inner.sign(preimage)
        }))
    }
}

impl AuditSigningKey {
    /// The 64 raw ed25519 signature bytes over one ledger checkpoint body's preimage
    /// ([`checkpoint_preimage`]), on the stack.
    pub(crate) fn sign_checkpoint_raw(&self, body: &[u8]) -> [u8; 64] {
        self.inner.sign(&checkpoint_preimage(body))
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
        // A pinned key with no point on the curve is refused here, not first at a verify (QE).
        ed25519::validate_public_key(&bytes).map_err(|_| KeyError::NotAKey)?;
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
        hex::encode(self.inner.to_bytes())
    }

    /// Check one signature over one digest.
    pub fn verify_digest(&self, digest_hex: &str, signature_hex: &str) -> Result<(), KeyError> {
        let raw =
            from_hex_exact::<64>(signature_hex.trim()).map_err(|_| KeyError::MalformedSignature)?;
        with_signing_preimage(digest_hex, |preimage| {
            self.inner.verify_strict(preimage, &raw)
        })
        .map_err(|_| KeyError::BadSignature)
    }

    /// Check one raw 64-byte signature over `message` (a stamp's or a break notice's preimage).
    pub(crate) fn verify_raw(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        let raw: &[u8; 64] = signature
            .try_into()
            .map_err(|_| KeyError::MalformedSignature)?;
        self.inner
            .verify_strict(message, raw)
            .map_err(|_| KeyError::BadSignature)
    }
}

/// THE PUBLIC KEY SET, as the key-set admin verb answers it.
///
/// A set rather than a key, because a node that has rotated has signed records under more than one
/// key and a verifier reading a year of history needs all of them. Keys are only ever ADDED: a key
/// removed from this set makes every record it signed unverifiable, which is indistinguishable from
/// those records having been forged.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuditKeySet {
    keys: Vec<AuditVerifyingKey>,
    /// Where each key sits in `keys`, by its identifier's bytes.
    by_id: foldhash::HashMap<[u8; KEY_ID_BYTES * 2], usize>,
}

impl std::fmt::Debug for AuditKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditKeySet")
            .field("keys", &self.keys)
            .finish()
    }
}

/// A key identifier as the fixed bytes the set indexes it by, or `None` for text no key has.
fn id_bytes(key_id: &str) -> Option<[u8; KEY_ID_BYTES * 2]> {
    key_id.as_bytes().try_into().ok()
}

impl AuditKeySet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        AuditKeySet::default()
    }

    /// Add a key. A key already in the set is not added twice.
    pub fn insert(&mut self, key: AuditVerifyingKey) {
        let Some(id) = id_bytes(&key.key_id) else {
            return;
        };
        if let std::collections::hash_map::Entry::Vacant(slot) = self.by_id.entry(id) {
            slot.insert(self.keys.len());
            self.keys.push(key);
        }
    }

    /// The key one identifier names, if the set holds it.
    #[must_use]
    pub fn get(&self, key_id: &str) -> Option<&AuditVerifyingKey> {
        let at = *self.by_id.get(&id_bytes(key_id)?)?;
        self.keys.get(at)
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
        let preimage = checkpoint_preimage(body);
        if self
            .keys
            .iter()
            .any(|k| k.inner.verify_strict(&preimage, &raw).is_ok())
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
