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

/// PBKDF2-HMAC-SHA256 (RFC 8018) of `password` under `salt`, 32 bytes, over the crypto facade.
fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, Refused> {
    let mut out = Zeroizing::new([0_u8; 32]);
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
        self.seal(Zeroizing::new(self.wire().to_vec()))
    }

    /// `Bearer <credential>`.
    pub fn bearer(&self) -> Seal {
        // Exact size in one allocation (`concat`): the wiping buffer never grows (LR-117).
        self.seal(Zeroizing::new(
            [b"Bearer ".as_slice(), self.wire()].concat(),
        ))
    }

    /// `Basic base64(user:credential)` (RFC 7617; the user's octets as they are).
    pub fn basic(&self, user: impl AsRef<[u8]>) -> Seal {
        let user = user.as_ref();
        let pair = Zeroizing::new([user, b":", self.wire()].concat());
        self.seal(Zeroizing::new(
            [b"Basic ".as_slice(), b64(&pair).as_slice()].concat(),
        ))
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
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a far end's error text, copied once on its way to a diagnostic"
            )]
            let echo = text.to_owned();
            return echo;
        }
        let hay = text.as_bytes();
        // busbar:expect(bp::fresh_buffer, reason = "error: a far end's error text, redacted once on its way to a diagnostic")
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
        #[expect(
            clippy::disallowed_methods,
            reason = "error: a far end's error text whose redaction split a character"
        )]
        let echo = String::from_utf8(out).unwrap_or_else(|_| "[redacted]".to_owned());
        echo
    }
}

#[cfg(test)]
#[path = "../tests/chip_tests.rs"]
mod tests;
