// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HMAC over AWS-LC (RFC 2104) and constant-time comparison. AWS-LC cleanses its HMAC contexts.

use aws_lc_rs::{constant_time, hmac};

use crate::Error;

fn mac<const N: usize>(alg: hmac::Algorithm, key: &[u8], msg: &[u8]) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(hmac::sign(&hmac::Key::new(alg, key), msg).as_ref());
    out
}

/// HMAC-SHA256 of `msg` under `key`. The software backend refuses no key length.
#[inline]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], Error> {
    Ok(mac(hmac::HMAC_SHA256, key, msg))
}

/// HMAC-SHA512 of `msg` under `key`.
#[inline]
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> Result<[u8; 64], Error> {
    Ok(mac(hmac::HMAC_SHA512, key, msg))
}

/// Verify `tag` as HMAC-SHA256 of `msg` under `key`, in constant time.
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), Error> {
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), msg, tag).map_err(|_| Error::Mismatch)
}

/// An HMAC-SHA256 key, for many MACs under one key.
#[derive(Clone)]
pub struct HmacSha256Key(hmac::Key);

impl core::fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmacSha256Key").finish_non_exhaustive()
    }
}

impl HmacSha256Key {
    /// A key from `key`'s bytes. The software backend refuses no key length.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, key)))
    }

    /// HMAC-SHA256 of `msg`.
    #[inline]
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out.copy_from_slice(hmac::sign(&self.0, msg).as_ref());
        out
    }

    /// HMAC-SHA256 of the concatenation of `parts`.
    #[must_use]
    pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&self.0);
        for p in parts {
            ctx.update(p);
        }
        let mut out = [0_u8; 32];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }

    /// Verify `tag` over `msg`, in constant time.
    pub fn verify(&self, msg: &[u8], tag: &[u8]) -> Result<(), Error> {
        hmac::verify(&self.0, msg, tag).map_err(|_| Error::Mismatch)
    }
}

/// Whether `a` equals `b`, in time that depends only on the lengths.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// HMAC-SHA384 of `msg` under `key`.
#[inline]
pub fn hmac_sha384(key: &[u8], msg: &[u8]) -> Result<[u8; 48], Error> {
    Ok(mac(hmac::HMAC_SHA384, key, msg))
}
