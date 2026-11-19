// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Credential custody, sealed composition and cryptographic operations. Protocol owners frame
//! authentication messages and select permitted methods in their own implementation.

pub(crate) mod digests;
mod jws;
mod operations;
pub(crate) mod rsa;
mod scheme;

pub use operations::{rsa_public_key_sha256, CredentialPart, Digest, SealedValue};

use crate::abi::sdk::cred::{Cred, Seal};
use crate::secure::{SecureArray, SecureVec};
use base64::Engine as _;

/// Why a recipe refused: a sentence with no material in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused(pub &'static str);

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

type Bytes = SecureVec;

fn b64(bytes: &[u8]) -> Bytes {
    SecureVec::from(
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes(),
    )
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) of `password` under `salt`, 32 bytes, over the crypto facade.
fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<SecureArray<32>, Refused> {
    let mut out = SecureArray::<32>::zeroed();
    crate::crypto::pbkdf2_hmac_sha256(password, salt, iterations, &mut out[..]).map_err(
        |e| match e {
            crate::crypto::Error::Unsupported(u) => Refused(u.reason),
            _ => Refused("PBKDF2 parameters refused"),
        },
    )?;
    Ok(out)
}

impl Cred {
    /// The credential as a field value, unchanged (an API key header).
    pub fn field(&self) -> Seal {
        self.seal(SecureVec::from(self.wire()))
    }

    /// `Bearer <credential>`.
    pub fn bearer(&self) -> Seal {
        // Exact size in one allocation: the wiping buffer never grows (LR-117).
        self.seal(digests::joined(&[b"Bearer ".as_slice(), self.wire()]))
    }

    /// `Basic base64(user:credential)` (RFC 7617; the user's octets as they are).
    pub fn basic(&self, user: impl AsRef<[u8]>) -> Seal {
        let user = user.as_ref();
        let pair = digests::joined(&[user, b":", self.wire()]);
        self.seal(digests::joined(&[
            b"Basic ".as_slice(),
            b64(&pair).as_slice(),
        ]))
    }

    /// Whether `presented` equals the credential, compared over SHA-256 digests so neither content
    pub fn verify_eq(&self, presented: &[u8]) -> bool {
        let a = digests::sha256(&[self.wire()]);
        let b = digests::sha256(&[presented]);
        crate::constant_time_eq(&a[..], &b[..])
    }

    /// `text` with every occurrence of the credential replaced by `[redacted]`: for a destination
    pub fn redact_echo(&self, text: &str) -> String {
        let needle = self.wire();
        let hay = text.as_bytes();
        let mut out = Vec::with_capacity(hay.len());
        if needle.is_empty() || needle.len() > hay.len() {
            out.extend_from_slice(hay);
        } else {
            let mut i = 0;
            while i < hay.len() {
                if hay[i..].starts_with(needle) {
                    out.extend_from_slice(b"[redacted]");
                    i += needle.len();
                } else {
                    out.push(hay[i]);
                    i += 1;
                }
            }
        }
        String::from_utf8(out)
            .unwrap_or_else(|_| crate::abi::sdk::cold::cred::redaction_split_a_character())
    }
}

