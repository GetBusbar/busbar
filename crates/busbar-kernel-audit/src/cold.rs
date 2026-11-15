// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT CRATE'S COLD CODE (LINT-RULES LR-167): what its request-path modules reach only on a
//! rare path, out of line.

use crate::sign::SIGNATURE_DOMAIN;

/// The exact bytes an ed25519 signature over one record's digest is computed over. Sealing frames a
/// SHA-256 in hex on the stack; only a longer digest is framed here.
#[must_use]
#[cold]
pub fn signing_preimage(digest_hex: &str) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + digest_hex.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(digest_hex.as_bytes());
    preimage
}
