// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HMAC-SHA256, HMAC-SHA1 and SHA-256 for authentication material, over the crypto facade
//! (decision 224: no hand-written primitive). AWS-LC cleanses its own digest and HMAC contexts;
//! the results and any concatenated message copy are wiped on drop here.
//!
//! These keep their infallible plugin-facing signatures until the plugin wave moves every caller
//! to the fallible facade calls (CRYPTO-SEAM §2.5, §8 steps 5-7). Core's software backend refuses
//! nothing, so the refusal arm below is unreachable in a core build.

use zeroize::Zeroizing;

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

/// HMAC-SHA256 of `data` under `key` (RFC 2104). The returned MAC is wiped on drop.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crypto::hmac_sha256(key, data).unwrap_or_else(|e| refused(e)))
}

/// HMAC-SHA1 of the concatenation of `parts` under `key` (RFC 2104). The message copy and the
/// returned MAC are wiped on drop.
pub fn hmac_sha1(key: &Cred, parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    let message = Zeroizing::new(parts.concat());
    Zeroizing::new(crypto::legacy::hmac_sha1(key.wire(), &message).unwrap_or_else(|e| refused(e)))
}

/// SHA-256 of the concatenation of `parts`. The returned digest is wiped on drop.
pub fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crypto::sha256_parts(parts))
}

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
mod tests;
