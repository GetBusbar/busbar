// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One digest, in one place.
//!
//! There is exactly one hash FUNCTION in this crate, and every digest the crate takes goes through
//! it. It has several callers, and that is fine: what keeps two things that must hash the same way
//! from drifting is that they share one PREIMAGE and one call, not that the hash has one caller.
//! The pair that matters is a checkpoint's seal and its verify, and both go through
//! `Checkpoint::body_digest` over `Checkpoint::signed_body` — one encoder call, one digest call
//! (pinned by `the_seal_and_the_verify_share_one_preimage_and_one_digest`, item 438).

use sha2::{Digest as _, Sha256};

/// The digest of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The digest as lowercase hexadecimal, for anything that has to print one.
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
