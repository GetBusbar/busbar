// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHA-2 over AWS-LC. AWS-LC cleanses its digest contexts when they are dropped.

use aws_lc_rs::digest;

fn fixed<const N: usize>(d: digest::Digest) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-256 of `data` (FIPS 180-4).
#[inline]
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    fixed(digest::digest(&digest::SHA256, data))
}

/// SHA-384 of `data` (FIPS 180-4).
#[inline]
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    fixed(digest::digest(&digest::SHA384, data))
}

/// SHA-512 of `data` (FIPS 180-4).
#[inline]
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    fixed(digest::digest(&digest::SHA512, data))
}

/// A streaming SHA-256.
#[derive(Clone)]
pub struct Sha256State(digest::Context);

impl core::fmt::Debug for Sha256State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256State").finish_non_exhaustive()
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    /// An empty SHA-256.
    #[must_use]
    pub fn new() -> Self {
        Self(digest::Context::new(&digest::SHA256))
    }

    /// Absorb `data`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything absorbed.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        fixed(self.0.finish())
    }
}

/// Fallible SHA-256 contract for authority-bound verification.
pub fn sha256_checked(data: &[u8]) -> Result<[u8; 32], crate::Error> {
    Ok(sha256(data))
}
