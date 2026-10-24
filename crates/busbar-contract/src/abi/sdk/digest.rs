// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DIGEST A PLUGIN TAKES (ARCHITECT ruling fold-a2a-push-card-crypto (b), 2026-10-01): a
//! plane stays pure and links no crypto crate, so a document fingerprint is the contract's SHA-256,
//! the same `sha2` the contract already carries for [`crate::sha256_hex`], which is this digest in
//! lower-case hex. Judging a signature is the kernel's (`trust.verify`), never a plugin's.
//!
//! THE TAG, rendered here too (ARCHITECT card-fingerprint ruling, option 1): a fingerprint a plane
//! shows an operator is `sha256/<standard base64>`, the spelling 1.5.5 wrote, so no plane links an
//! encoder of its own.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// The SHA-256 digest of `data`, raw.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The tag a SHA-256 digest is shown under: `sha256/`.
pub const SHA256_TAG: &str = "sha256/";

/// The SHA-256 digest of `data`, tagged: `sha256/<standard base64>`.
#[must_use]
pub fn sha256_tagged(data: &[u8]) -> String {
    tagged(&sha256(data))
}

/// A SHA-256 `digest`, tagged: `sha256/<standard base64, padded>`. The ONE place a tagged digest is
/// spelled: a document fingerprint and a key pin (`transport::trust::key_pin`) alike.
#[must_use]
pub fn tagged(digest: &[u8; 32]) -> String {
    format!("{SHA256_TAG}{}", STANDARD.encode(digest))
}

/// `bytes` as lower-case hex, two digits a byte: the one spelling a plugin renders a digest or a
/// signature in, so no plugin writes an encoder of its own.
#[must_use]
pub fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
#[path = "tests/digest_tests.rs"]
mod tests;
