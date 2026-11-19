// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HMAC-SHA256, HMAC-SHA1 and SHA-256 for authentication material, over the crypto facade
//! (decision 224: no hand-written primitive). AWS-LC cleanses its own digest and HMAC contexts;
//! the results and any concatenated message copy are wiped on drop here.
//!
//! These keep their infallible plugin-facing signatures until the plugin wave moves every caller
//! to the fallible facade calls (CRYPTO-SEAM §2.5, §8 steps 5-7). Core's software backend refuses
//! nothing, so the refusal arm below is unreachable in a core build.

use crate::secure::{SecureArray, SecureVec};

use super::cred::Cred;
use crate::crypto;

/// The backend refused an algorithm this infallible SDK call cannot report.
#[cold]
fn refused(e: crypto::Error) -> ! {
    panic!(
        "crypto backend {} refused an SDK digest: {e}",
        crypto::BACKEND
    )
}

/// An HMAC-SHA256 key prepared once for many MACs under it (PBKDF2, a webhook verifier built once
/// per instance; WASTE-AUTH-SECRETS W7): the backend keeps the keyed state, so a MAC does not
/// re-derive the pads, and a message given in parts is handed over as parts, never joined here.
pub struct HmacSha256Key(crypto::HmacSha256Key);

impl HmacSha256Key {
    /// The key schedule of `key` (RFC 2104; a key past the block size is hashed first).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self(crypto::HmacSha256Key::new(key).unwrap_or_else(|e| refused(e)))
    }

    /// HMAC-SHA256 of `data` under this key, equal to [`hmac_sha256`].
    #[must_use]
    pub fn mac(&self, data: &[u8]) -> SecureArray<32> {
        SecureArray::from(self.0.sign(data))
    }

    /// HMAC-SHA256 of the concatenation of `parts` under this key, equal to [`hmac_sha256`] of the
    /// joined message.
    #[must_use]
    pub fn mac_parts(&self, parts: &[&[u8]]) -> SecureArray<32> {
        SecureArray::from(self.0.sign_parts(parts))
    }
}

impl core::fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha256Key(..)")
    }
}

/// An HMAC-SHA1 key held for many MACs under it (see [`HmacSha256Key`]). The key copy is wiped on
/// drop.
pub struct HmacSha1Key(SecureVec);

impl HmacSha1Key {
    /// The key of the opaque credential `key` (RFC 2104).
    #[must_use]
    pub fn new(key: &Cred) -> Self {
        Self(SecureVec::from(key.wire()))
    }

    /// HMAC-SHA1 of the concatenation of `parts` under this key, equal to [`hmac_sha1`].
    #[must_use]
    pub fn mac_parts(&self, parts: &[&[u8]]) -> SecureArray<20> {
        hmac_sha1_raw(&self.0, parts)
    }
}

impl core::fmt::Debug for HmacSha1Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha1Key(..)")
    }
}

/// HMAC-SHA256 of `data` under `key` (RFC 2104). The returned MAC is wiped on drop.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> SecureArray<32> {
    SecureArray::from(crypto::hmac_sha256(key, data).unwrap_or_else(|e| refused(e)))
}

/// HMAC-SHA1 of the concatenation of `parts` under `key` (RFC 2104). The message copy and the
/// returned MAC are wiped on drop.
pub fn hmac_sha1(key: &Cred, parts: &[&[u8]]) -> SecureArray<20> {
    hmac_sha1_raw(key.wire(), parts)
}

fn hmac_sha1_raw(key: &[u8], parts: &[&[u8]]) -> SecureArray<20> {
    let message = super::chip::digests::joined(parts);
    SecureArray::from(crypto::legacy::hmac_sha1(key, &message).unwrap_or_else(|e| refused(e)))
}

/// SHA-256 of the concatenation of `parts`. The returned digest is wiped on drop.
pub fn sha256(parts: &[&[u8]]) -> SecureArray<32> {
    SecureArray::from(crypto::sha256_parts(parts))
}

