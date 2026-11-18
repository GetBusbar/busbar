// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED PLUGIN DIGEST is SHA-256: a

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
/// The SHA-256 digest of `data`, raw.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Stream::new();
    hash.update(data);
    hash.finish()
}

/// Incremental SHA-256 through the crypto facade (`crate::crypto::Sha256`).
#[derive(Clone)]
pub struct Sha256Stream(crate::crypto::Sha256);

impl std::fmt::Debug for Sha256Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha256Stream")
    }
}

impl Default for Sha256Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Stream {
    /// An empty SHA-256 state.
    #[must_use]
    pub fn new() -> Self {
        Self(crate::crypto::Sha256::new())
    }

    /// Feed `data`.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// The digest of everything fed.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

/// The tag a SHA-256 digest is shown under: `sha256/`.
pub const SHA256_TAG: &str = "sha256/";

/// The SHA-256 digest of `data`, tagged: `sha256/<standard base64>`, appended to `out`.
pub fn sha256_tagged(data: &[u8], out: &mut String) {
    tagged(&sha256(data), out);
}

/// The length of a tagged digest: the tag and 44 base64 characters.
pub const TAGGED_LEN: usize = SHA256_TAG.len() + 44;

/// A SHA-256 `digest`, tagged: `sha256/<standard base64, padded>`. The ONE place a tagged digest is
///
/// Appended to `out` (the caller's buffer; [`TAGGED_LEN`] bytes).
pub fn tagged(digest: &[u8; 32], out: &mut String) {
    out.push_str(SHA256_TAG);
    STANDARD.encode_string(digest, out);
}

/// `bytes` as lower-case hex, two digits a byte: the one spelling a plugin renders a digest or a
#[must_use]
pub fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
#[path = "tests/digest_tests.rs"]
mod tests;
