// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signature over a sealed record's digest, minted in the process that sealed it.
//!
//! ## Why the signature cannot be added later
//!
//! A chain of digests is tamper-EVIDENT: edit a field and the record stops hashing to its own
//! stored hash. What it is not is tamper-PROOF, and more importantly it is not ATTRIBUTABLE — every
//! byte of it was produced by a file the operator controls, so a chain that verifies proves only
//! that the file is internally consistent with itself.
//!
//! A signature is what turns "these bytes agree with each other" into "this node produced these
//! bytes". And it is the half that cannot be retrofitted: a signature applied after the fact by
//! whoever received the records proves that the RECEIVER got those bytes, not that the node made
//! them. So every record sealed before signing exists is permanently unprovable, whatever is built
//! later. That is why this is minted at seal time, in-process, and not by a shipper, an exporter or
//! a cloud.
//!
//! ## What it does NOT close
//!
//! An operator holding the signing key can rewrite the chain and re-sign it. What defeats that is a
//! head recorded somewhere the operator cannot reach, which is an ANCHOR, and a node cannot anchor
//! to itself. So this earns the claim *signed and tamper-evident* — "prove it to yourself and your
//! auditor" — and only an externally anchored head earns *"prove it to a counterparty who trusts
//! neither of us"*. The gap is named here so the claim does not outrun the mechanism.
//!
//! ## Key material never leaves this module
//!
//! [`AuditSigningKey`] has a hand-written [`std::fmt::Debug`] that prints the key IDENTIFIER and
//! nothing else, and [`KeyError`] carries no part of the input it rejected — not the text, not a
//! character, not an offset. Both are deliberate and both are tested. A hex decoder from a general
//! library names the offending character AND its index in its error, which for a 32-byte ed25519
//! seed is a byte of the secret printed into whatever caught the error. The packaging CLI's own
//! `$BUSBAR_SIGN_KEY` reader does exactly that today and is a separate known defect, tracked
//! outside this crate. The decoder here is this module's own for that one reason.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroize as _;

/// The domain this signature is FOR, and the first bytes of every preimage.
///
/// Published contract. A bare signature over a bare digest is a signature over 64 hex characters
/// and nothing else, so the same key used for anything else that signs a SHA-256 — a package
/// manifest, a release artifact — would mint bytes that verify here too. The domain is what makes
/// "this is an audit record digest" part of what was signed rather than part of what the reader
/// assumed.
pub const SIGNATURE_DOMAIN: &str = "busbar.audit.record.v1";

/// The signature algorithm, named in the key set so a verifier never has to infer it from a length.
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

/// How many bytes of the public key's SHA-256 make a key identifier. Eight — sixteen hex
/// characters — which is a name, not a fingerprint to trust: a verifier that cares which key signed
/// something checks the SIGNATURE against the published key, never the identifier.
const KEY_ID_BYTES: usize = 8;

/// The exact bytes an ed25519 signature over one record's digest is computed over.
///
/// PUBLISHED CONTRACT, and it is two concatenated runs and nothing else:
/// [`SIGNATURE_DOMAIN`] in ASCII, one `0x00` byte, then the record's digest as the 64 lowercase
/// hexadecimal characters the record carries in its `hash` field.
///
/// The digest goes in as its HEX TEXT rather than as the 32 raw bytes it spells, because the hex
/// text is what the record actually carries and what a reader actually read. A verifier that had to
/// decode it first would have one more place to differ — case, odd length, a stray space — between
/// two implementations that both believe they are following this recipe.
#[must_use]
pub fn signing_preimage(digest_hex: &str) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + digest_hex.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
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
    /// The record carries no signature, or no key identifier, so there is nothing to check.
    Unsigned,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let said = match self {
            // NOTE the absent value in every one of these. See the type's doc comment.
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
            KeyError::Unsigned => "the record carries no signature to check",
        };
        f.write_str(said)
    }
}

impl std::error::Error for KeyError {}

/// Decode lowercase hex into exactly `N` bytes, saying nothing about WHAT was wrong with it.
///
/// Uppercase is rejected rather than accepted, so there is one spelling of a key and two texts
/// cannot name the same secret. See [`KeyError`] for why the error is this uninformative on
/// purpose.
fn from_hex_exact<const N: usize>(text: &str) -> Result<[u8; N], KeyError> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(KeyError::WrongLength);
    }
    let mut out = [0u8; N];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
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
/// hex.
///
/// PUBLISHED CONTRACT, and it is derived rather than assigned so that a verifier holding the public
/// key can recompute it. An assigned identifier would be one more thing to be told out of band, and
/// the whole point of publishing a key set is that nothing has to be taken on trust from us.
#[must_use]
pub fn key_id_of(public_key: &VerifyingKey) -> String {
    let digest = crate::legacy::sha256_hex(public_key.as_bytes());
    // `sha256_hex` returns 64 lowercase hex characters, so the first 16 are the first 8 bytes.
    digest[..KEY_ID_BYTES * 2].to_string()
}

/// THE NODE'S AUDIT SIGNING KEY. The secret half never leaves this type.
///
/// No `Clone`, no `Copy`, no derived `Debug`, no accessor for the seed and no `Display`. What a
/// caller can get out of it is the key IDENTIFIER, the PUBLIC key, and a signature. Everything else
/// is a way for the secret to reach a log.
pub struct AuditSigningKey {
    inner: SigningKey,
    key_id: String,
}

/// PRINTS THE IDENTIFIER AND NOTHING ELSE.
///
/// Hand-written because the derived one would print `inner`, and `ed25519_dalek::SigningKey`'s own
/// `Debug` prints the secret scalar. A type whose `Debug` leaks is a type that leaks the moment
/// anything containing it is `{:?}`-formatted in an error path — which is the one path nobody
/// rehearses. The test `debug_never_shows_the_secret` formats this, and the chain that holds it,
/// and asserts the seed's hex is absent from both.
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
    ///
    /// The caller's copy of the seed is the caller's to dispose of; the copy this makes is inside
    /// `SigningKey` and goes when this does.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = SigningKey::from_bytes(seed);
        let key_id = key_id_of(&inner.verifying_key());
        AuditSigningKey { inner, key_id }
    }

    /// Build one from 64 lowercase hex characters.
    ///
    /// The decoded seed is wiped before this returns, on both the success and the failure path, so
    /// a seed does not sit in freed heap after a bad read. The error says only that the text was
    /// not a seed — see [`KeyError`].
    ///
    /// # Errors
    ///
    /// The text is not exactly 64 lowercase hexadecimal characters.
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
    ///
    /// Over [`signing_preimage`], not over the digest text alone. Called once per sealed record,
    /// inside the seal, and nowhere else.
    #[must_use]
    pub fn sign_digest(&self, digest_hex: &str) -> String {
        to_hex(&self.inner.sign(&signing_preimage(digest_hex)).to_bytes())
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
    ///
    /// `VerifyingKey::from_bytes` only checks that the point decompresses; a small-order point
    /// decompresses fine and then verifies EVERY signature, which is a key that turns the whole
    /// mechanism into a rubber stamp. Refused here for the same reason
    /// the artifact-signing crate's own public-key reader refuses it.
    ///
    /// # Errors
    ///
    /// The text is not 64 lowercase hex characters, the bytes are not a public key, or the key is
    /// weak.
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
    ///
    /// Through `verify_strict`, which refuses a signature whose `R` component is on a small-order
    /// subgroup — the malleability case where two different signatures both verify.
    ///
    /// # Errors
    ///
    /// The signature is not 128 lowercase hex characters, or it does not verify.
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

    /// The public half of a signing key this node holds, added to the set.
    pub fn insert_signer(&mut self, signer: &AuditSigningKey) {
        self.insert(AuditVerifyingKey {
            inner: signer.verifying_key(),
            key_id: signer.key_id().to_string(),
        });
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
