// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DIGEST A PLUGIN TAKES (ARCHITECT ruling fold-a2a-push-card-crypto (b), 2026-10-01): a
//! plane stays pure and links no crypto crate, so a document fingerprint is the contract's SHA-256,
//! the same `sha2` the contract already carries for [`crate::sha256_hex`], which is this digest in
//! lower-case hex. Judging a signature is the kernel's (`trust.verify`), never a plugin's.

use sha2::{Digest as _, Sha256};

/// The SHA-256 digest of `data`, raw.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
#[path = "tests/digest_tests.rs"]
mod tests;
