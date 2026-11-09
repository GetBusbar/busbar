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
use crate::abi::sdk::hmac::hmac_sha256;
use base64::Engine as _;
use zeroize::Zeroizing;

/// Why a recipe refused: a sentence with no material in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused(pub &'static str);

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

type Bytes = Zeroizing<Vec<u8>>;

fn b64(bytes: &[u8]) -> Bytes {
    Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes(),
    )
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut first = Zeroizing::new(salt.to_vec());
    first.extend_from_slice(&1_u32.to_be_bytes());
    let mut u = hmac_sha256(password, &first);
    let mut acc = Zeroizing::new(*u);
    for _ in 1..iterations {
        u = hmac_sha256(password, &u[..]);
        for (a, b) in acc.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    acc
}

impl Cred {
    /// The credential as a field value, unchanged (an API key header).
    pub fn field(&self) -> Seal {
        self.seal(Zeroizing::new(self.wire().to_vec()))
    }

    /// `Bearer <credential>`.
    pub fn bearer(&self) -> Seal {
        let mut v = Zeroizing::new(b"Bearer ".to_vec());
        v.extend_from_slice(self.wire());
        self.seal(v)
    }

    /// `Basic base64(user:credential)` (RFC 7617; the user's octets as they are).
    pub fn basic(&self, user: impl AsRef<[u8]>) -> Seal {
        let user = user.as_ref();
        let mut pair = Zeroizing::new(Vec::with_capacity(user.len() + 1 + self.len()));
        pair.extend_from_slice(user);
        pair.push(b':');
        pair.extend_from_slice(self.wire());
        let mut v = Zeroizing::new(b"Basic ".to_vec());
        v.extend_from_slice(&b64(&pair));
        self.seal(v)
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
        if needle.is_empty() || needle.len() > text.len() {
            return text.to_owned();
        }
        let hay = text.as_bytes();
        let mut out = Vec::with_capacity(hay.len());
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
        String::from_utf8(out).unwrap_or_else(|_| "[redacted]".to_owned())
    }
}

#[cfg(test)]
#[path = "../tests/chip_tests.rs"]
mod tests;
