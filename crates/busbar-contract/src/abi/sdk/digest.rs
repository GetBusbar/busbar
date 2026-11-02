// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED PLUGIN DIGEST is SHA-256: a

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
#[must_use]
pub fn tagged(digest: &[u8; 32]) -> String {
    format!("{SHA256_TAG}{}", STANDARD.encode(digest))
}

/// `bytes` as lower-case hex, two digits a byte: the one spelling a plugin renders a digest or a
#[must_use]
pub fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
#[path = "tests/digest_tests.rs"]
mod tests;
