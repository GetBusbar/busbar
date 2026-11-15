// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHA-1, MD5 and SHA-256 of concatenated parts for the credential recipes, over the crypto
//! facade (decision 224). Message copies and results are wiped on drop. Infallible until the
//! plugin wave (see `sdk::hmac`); core's software backend refuses neither legacy digest.

use crate::secure::{SecureArray, SecureVec};

use crate::crypto;

/// The concatenation of `parts` in one exact-size custody block: it never grows, so no copy of
/// the message is left behind unwiped.
pub(crate) fn joined(parts: &[&[u8]]) -> SecureVec {
    let total = parts
        .iter()
        .fold(0_usize, |n, part| n.saturating_add(part.len()));
    let mut out = SecureVec::with_capacity(total).unwrap_or_default();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

#[cold]
fn refused(e: crypto::Error) -> ! {
    panic!(
        "crypto backend {} refused a credential digest: {e}",
        crypto::BACKEND
    )
}

/// SHA-1 of the concatenation of `parts`.
pub(crate) fn sha1(parts: &[&[u8]]) -> SecureArray<20> {
    SecureArray::from(crypto::legacy::sha1(&joined(parts)).unwrap_or_else(|e| refused(e)))
}

/// MD5 of the concatenation of `parts` (Postgres md5 authentication only).
pub(crate) fn md5(parts: &[&[u8]]) -> SecureArray<16> {
    SecureArray::from(crypto::legacy::md5(&joined(parts)).unwrap_or_else(|e| refused(e)))
}

/// SHA-256 of the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> SecureArray<32> {
    SecureArray::from(crypto::sha256_parts(parts))
}
