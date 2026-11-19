// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Sealed byte composition and cryptographic primitives. These operations neither select an
//! authentication method nor authorize a connection. Their outputs remain in custody, and carry
//! the union of their inputs' connection-security requirements.

use crate::secure::SecureVec;
use base64::Engine as _;

use super::{digests, rsa, Refused};
use crate::abi::sdk::cred::{Cred, Seal};

/// An input to sealed composition. No variant exposes an input's secret bytes.
#[expect(
    missing_debug_implementations,
    reason = "a part may name a credential: no Debug, so no secret byte can print"
)]
pub enum CredentialPart<'a> {
    /// Bytes already known to the caller, such as a framing prefix or public challenge.
    Public(&'a [u8]),
    /// A credential or a sealed intermediate result.
    Credential(&'a Cred),
    /// An intermediate that cannot be converted back into an inspectable credential.
    Value(&'a SealedValue),
    /// A previously sealed wire value.
    Sealed(&'a Seal),
}

/// A digest algorithm. Protocol owners decide which algorithms their policy permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    /// MD5 (RFC 1321), for compatibility with explicitly permitted legacy protocols.
    Md5,
    /// SHA-1 (FIPS 180-4), for compatibility with explicitly permitted legacy protocols.
    Sha1,
    /// SHA-256 (FIPS 180-4).
    Sha256,
}

/// Protected intermediate bytes. Unlike an ingested [`Cred`], this type has no text validators,
/// prefix predicates or normalization operations: combining those with chosen transformations
/// could disclose individual bytes. There is no conversion back to `Cred` or readable bytes.
///
/// ```compile_fail
/// use busbar_contract::abi::sdk::{chip::SealedValue, cred::Cred};
/// let value = SealedValue::compose(&[]);
/// let _: Cred = value.into();
/// ```
/// ```compile_fail
/// use busbar_contract::abi::sdk::chip::SealedValue;
/// let value = SealedValue::compose(&[]);
/// let _ = value.is_text();
/// ```
/// ```compile_fail
/// use busbar_contract::abi::sdk::chip::SealedValue;
/// let value = SealedValue::compose(&[]);
/// let _ = value.normalize_ascii_spaces();
/// ```
#[expect(
    missing_debug_implementations,
    reason = "a sealed value is secret: no Debug, so no byte can print"
)]
#[derive(Clone)]
pub struct SealedValue(Cred);

impl SealedValue {
    fn wire(&self) -> &[u8] {
        self.0.wire()
    }

    fn transformed(&self, bytes: SecureVec) -> Self {
        Self(Cred::captured(bytes).require_secure_if(self.secure_required()))
    }

    /// Length for a framing prefix. Supported transforms have public output lengths.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether a secured connector is required to send this value.
    pub fn secure_required(&self) -> bool {
        self.0.secure_required()
    }

    /// Add a requirement; false cannot relax any input's requirement.
    #[must_use]
    pub fn require_secure_if(mut self, required: bool) -> Self {
        self.0 = self.0.require_secure_if(required);
        self
    }

    /// Seal the whole value for the existing checked write path.
    pub fn field(&self) -> Seal {
        self.0.field()
    }

    /// Constant-time equality against an entire public candidate, for proof verification.
    pub fn verify_eq(&self, candidate: &[u8]) -> bool {
        self.0.verify_eq(candidate)
    }

    /// Concatenate public and protected inputs without exposing the result.
    pub fn compose(parts: &[CredentialPart<'_>]) -> Self {
        // Reserve before copying any credential: growing a populated Vec can retire an
        // allocation without zeroizing its credential bytes.
        let total = parts
            .iter()
            .try_fold(0_usize, |total, part| {
                let length = match part {
                    CredentialPart::Public(value) => value.len(),
                    CredentialPart::Credential(value) => value.len(),
                    CredentialPart::Value(value) => value.len(),
                    CredentialPart::Sealed(value) => value.wire().len(),
                };
                total.checked_add(length)
            })
            .expect("sealed composition length exceeds address space");
        // Exact size, filled in place: the wiping buffer never grows (LINT-RULES LR-117).
        let mut bytes = SecureVec::zeroed(total);
        let mut at = 0;
        let mut put = |part: &[u8]| {
            bytes[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        };
        let mut secure = false;
        for part in parts {
            match part {
                CredentialPart::Public(public) => put(&public[..]),
                CredentialPart::Credential(value) => {
                    put(value.wire());
                    secure |= value.secure_required();
                }
                CredentialPart::Value(value) => {
                    put(value.wire());
                    secure |= value.secure_required();
                }
                CredentialPart::Sealed(value) => {
                    put(value.wire());
                    secure |= value.secure_required();
                }
            }
        }
        Self(Cred::captured(bytes).require_secure_if(secure))
    }

    /// Hash this value, keeping the digest sealed.
    pub fn digest(&self, algorithm: Digest) -> Self {
        let bytes = match algorithm {
            Digest::Md5 => SecureVec::from(&digests::md5(&[self.wire()])[..]),
            Digest::Sha1 => SecureVec::from(&digests::sha1(&[self.wire()])[..]),
            Digest::Sha256 => SecureVec::from(&digests::sha256(&[self.wire()])[..]),
        };
        self.transformed(bytes)
    }

    /// HMAC-SHA-256 with this value as the key and a sealed message.
    pub fn hmac_sha256(&self, message: &Self) -> Self {
        let mac = crate::abi::sdk::hmac::hmac_sha256(self.wire(), message.wire());
        self.transformed(SecureVec::from(&mac[..]))
            .require_secure_if(message.secure_required())
    }

    /// Derive 32 bytes with PBKDF2-HMAC-SHA-256. The computational ceiling is independent of
    /// protocol policy: owners must also enforce their own accepted iteration range.
    pub fn pbkdf2_sha256(&self, salt: &[u8], iterations: u32) -> Result<Self, Refused> {
        if !(1..=1_000_000).contains(&iterations) {
            return Err(Refused(
                "PBKDF2 iterations outside the supported work bound",
            ));
        }
        let value = super::pbkdf2_sha256(self.wire(), salt, iterations)?;
        Ok(self.transformed(SecureVec::from(&value[..])))
    }

    /// XOR equally sized sealed values. Only their already-public lengths affect failure.
    pub fn xor(&self, other: &Self) -> Result<Self, Refused> {
        if self.len() != other.len() {
            return Err(Refused("sealed XOR requires equal lengths"));
        }
        // Exact size, filled in place.
        let mut bytes = SecureVec::zeroed(self.len());
        for ((out, a), b) in bytes.iter_mut().zip(self.wire()).zip(other.wire()) {
            *out = a ^ b;
        }
        Ok(self
            .transformed(bytes)
            .require_secure_if(other.secure_required()))
    }

    /// XOR this value with a repeating public mask. An empty mask is refused.
    pub fn xor_repeating(&self, mask: &[u8]) -> Result<Self, Refused> {
        if mask.is_empty() {
            return Err(Refused("sealed XOR requires a nonempty mask"));
        }
        // Exact size, filled in place.
        let mut bytes = SecureVec::zeroed(self.len());
        for ((out, a), b) in bytes.iter_mut().zip(self.wire()).zip(mask.iter().cycle()) {
            *out = a ^ b;
        }
        Ok(self.transformed(bytes))
    }

    /// Lowercase hexadecimal encoding, still sealed.
    pub fn hex_lower(&self) -> Self {
        self.transformed(SecureVec::from(hex::encode(self.wire()).into_bytes()))
    }

    /// Standard padded base64 encoding, still sealed.
    pub fn base64(&self) -> Self {
        self.transformed(SecureVec::from(
            base64::engine::general_purpose::STANDARD
                .encode(self.wire())
                .into_bytes(),
        ))
    }

    /// RSA-OAEP with SHA-1 and a fresh random seed. This does not authenticate the public key;
    /// the owner must establish its trust before using it. Existing security requirements are
    /// retained even though the output is ciphertext.
    pub fn rsa_oaep_sha1(&self, public_key_pem: &[u8]) -> Result<Self, Refused> {
        let ciphertext = rsa::oaep_sha1(self.wire(), public_key_pem)?;
        Ok(self.transformed(SecureVec::from(ciphertext)))
    }
}

impl Cred {
    /// Enter sealed computation. The result cannot regain this credential's text predicates.
    pub fn sealed_value(&self) -> SealedValue {
        SealedValue(self.clone())
    }

    /// Trim ASCII spaces and collapse interior runs to one ASCII space. Only ingested
    /// credentials can be normalized; arbitrary computed values cannot enter this operation.
    pub fn normalize_ascii_spaces(&self) -> SealedValue {
        // At most as long as the input: written in place into one exact allocation and cut to
        // length, so the wiping buffer never grows (LINT-RULES LR-117).
        let mut out = SecureVec::zeroed(self.len());
        let mut n = 0;
        let mut pending = false;
        for &byte in self.wire() {
            if byte == b' ' {
                pending = true;
            } else {
                if pending && n != 0 {
                    out[n] = b' ';
                    n += 1;
                }
                pending = false;
                out[n] = byte;
                n += 1;
            }
        }
        out.truncate(n);
        SealedValue(Cred::captured(out).require_secure_if(self.secure_required()))
    }
}

/// SHA-256 of a public RSA key's DER representation, for owner-controlled pin checks.
pub fn rsa_public_key_sha256(public_key_pem: &[u8]) -> Result<[u8; 32], Refused> {
    rsa::key_sha256(public_key_pem)
}

