// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One digest, in one place.
//!
//! There is exactly one hash function in this crate and exactly one function that calls it. A
//! second call site is how two things that are supposed to hash the same way stop doing so.

use sha2::{Digest as _, Sha256};

/// The digest of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The digest as lowercase hexadecimal, for anything that has to print one.
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
