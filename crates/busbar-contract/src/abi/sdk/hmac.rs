// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HMAC-SHA256, HMAC-SHA1 and SHA-256 for authentication material, over the crypto facade
//! (decision 224: no hand-written primitive). AWS-LC cleanses its own digest and HMAC contexts;
//! the results and any concatenated message copy are wiped on drop here.
//!
//! These keep their infallible plugin-facing signatures until the plugin wave moves every caller
//! to the fallible facade calls (CRYPTO-SEAM §2.5, §8 steps 5-7). Core's software backend refuses
//! nothing, so the refusal arm below is unreachable in a core build.

use zeroize::Zeroizing;

use super::cred::Cred;
use crate::crypto;

/// The backend refused an algorithm this infallible SDK call cannot report.
#[cold]
fn refused(e: crypto::Error) -> ! {
    panic!(
        "crypto backend {} refused an SDK digest: {e}",
        crypto::BACKEND
    )
}

/// SHA-256 of `prefix` (one whole block, or none) followed by `data`. The chaining state and the
pub(crate) fn sha256_wiped(prefix: Option<&[u8; BLOCK]>, data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut state = Zeroizing::new(SHA256_IV);
    let mut consumed = 0;
    if let Some(p) = prefix {
        compress(&mut state, p);
        consumed = BLOCK as u64;
    }
    sha256_resume(state, consumed, data)
}

/// SHA-256 of the concatenation of `parts`, streamed through one wiped stack block
/// ([`digests::absorb`]): the message is never copied whole.
pub(crate) fn sha256_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Zeroizing<[u8; 32]> {
    let mut state = Zeroizing::new(SHA256_IV);
    digests::absorb(parts, true, 0, |block| compress(&mut state, block));
    let mut out = Zeroizing::new([0_u8; 32]);
    for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(state.iter()) {
        *o = w.to_be_bytes();
    }
    out
}

/// SHA-256 finished from a chaining `state` that has already absorbed `consumed` bytes (whole blocks).
fn sha256_resume(state: Zeroizing<[u32; 8]>, consumed: u64, data: &[u8]) -> Zeroizing<[u8; 32]> {
    sha256_resume_parts(state, consumed, &[data])
}

/// [`sha256_resume`] over the concatenation of `parts`, streamed through one wiped block buffer:
/// no part is copied whole.
fn sha256_resume_parts(
    mut state: Zeroizing<[u32; 8]>,
    consumed: u64,
    parts: &[&[u8]],
) -> Zeroizing<[u8; 32]> {
    let mut buf = Zeroizing::new([0_u8; BLOCK]);
    let (fill, total) = stream_blocks(&mut buf, consumed, parts, |b| compress(&mut state, b));
    let mut tail = Zeroizing::new([0_u8; 2 * BLOCK]);
    tail[..fill].copy_from_slice(&buf[..fill]);
    tail[fill] = 0x80;
    let end = if fill + 9 <= BLOCK { BLOCK } else { 2 * BLOCK };
    tail[end - 8..end].copy_from_slice(&total.wrapping_mul(8).to_be_bytes());
    for c in tail[..end].as_chunks::<BLOCK>().0 {
        compress(&mut state, c);
    }
    let mut out = Zeroizing::new([0_u8; 32]);
    for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(state.iter()) {
        *o = w.to_be_bytes();
    }
    out
}

/// An HMAC-SHA256 key with its ipad/opad blocks already compressed, for many MACs under one key
/// (PBKDF2, a webhook verifier built once per instance): two compressions per short MAC instead of
/// four, and a message given in parts is streamed, never joined. The states are wiped on drop.
pub struct HmacSha256Key {
    inner: Zeroizing<[u32; 8]>,
    outer: Zeroizing<[u32; 8]>,
}

impl HmacSha256Key {
    /// The key schedule of `key` (RFC 2104; a key past the block size is hashed first).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut k0 = Zeroizing::new([0_u8; BLOCK]);
        if key.len() > BLOCK {
            k0[..32].copy_from_slice(&sha256_wiped(None, key)[..]);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut pad = Zeroizing::new([0_u8; BLOCK]);
        let mut inner = Zeroizing::new(SHA256_IV);
        for (p, k) in pad.iter_mut().zip(k0.iter()) {
            *p = k ^ 0x36;
        }
        compress(&mut inner, &pad);
        let mut outer = Zeroizing::new(SHA256_IV);
        for (p, k) in pad.iter_mut().zip(k0.iter()) {
            *p = k ^ 0x5c;
        }
        compress(&mut outer, &pad);
        Self { inner, outer }
    }

    /// HMAC-SHA256 of `data` under this key, equal to [`hmac_sha256`].
    #[must_use]
    pub fn mac(&self, data: &[u8]) -> Zeroizing<[u8; 32]> {
        self.mac_parts(&[data])
    }

    /// HMAC-SHA256 of the concatenation of `parts` under this key, equal to [`hmac_sha256`] of the
    /// joined message. The parts are streamed through a wiped block buffer.
    #[must_use]
    pub fn mac_parts(&self, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        let inner = sha256_resume_parts(self.inner.clone(), BLOCK as u64, parts);
        sha256_resume(self.outer.clone(), BLOCK as u64, &inner[..])
    }

    /// [`Self::mac`] of the concatenation of `parts`, streamed: the message is never copied whole.
    pub(crate) fn mac_parts<'a>(
        &self,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Zeroizing<[u8; 32]> {
        let mut state = self.inner.clone();
        digests::absorb(parts, true, BLOCK as u64, |block| {
            compress(&mut state, block)
        });
        let mut inner = Zeroizing::new([0_u8; 32]);
        for (o, w) in inner.as_chunks_mut::<4>().0.iter_mut().zip(state.iter()) {
            *o = w.to_be_bytes();
        }
        sha256_resume(self.outer.clone(), BLOCK as u64, &inner[..])
    }
}

impl core::fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha256Key(..)")
    }
}

/// An HMAC-SHA1 key with its ipad/opad blocks already compressed (see [`HmacSha256Key`]): two
/// compressions per short MAC, parts streamed. The states are wiped on drop.
pub struct HmacSha1Key {
    inner: Zeroizing<[u32; 5]>,
    outer: Zeroizing<[u32; 5]>,
}

impl HmacSha1Key {
    /// The key schedule of the opaque credential `key` (RFC 2104; a key past the block size is
    /// hashed first).
    #[must_use]
    pub fn new(key: &Cred) -> Self {
        let key = key.wire();
        let mut k0 = Zeroizing::new([0_u8; BLOCK]);
        if key.len() > BLOCK {
            k0[..20].copy_from_slice(&digests::sha1(&[key])[..]);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut pad = Zeroizing::new([0_u8; BLOCK]);
        let mut inner = Zeroizing::new(digests::SHA1_IV);
        for (p, k) in pad.iter_mut().zip(k0.iter()) {
            *p = k ^ 0x36;
        }
        digests::sha1_compress(&mut inner, &pad);
        let mut outer = Zeroizing::new(digests::SHA1_IV);
        for (p, k) in pad.iter_mut().zip(k0.iter()) {
            *p = k ^ 0x5c;
        }
        digests::sha1_compress(&mut outer, &pad);
        Self { inner, outer }
    }

    /// HMAC-SHA1 of the concatenation of `parts` under this key, equal to [`hmac_sha1`].
    #[must_use]
    pub fn mac_parts(&self, parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
        let inner = digests::sha1_resume_parts(self.inner.clone(), BLOCK as u64, parts);
        digests::sha1_resume_parts(self.outer.clone(), BLOCK as u64, &[&inner[..]])
    }
}

impl core::fmt::Debug for HmacSha1Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha1Key(..)")
    }
}

/// HMAC-SHA256 of `data` under `key` (RFC 2104; a key past the block size is hashed first). HMAC
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crypto::hmac_sha256(key, data).unwrap_or_else(|e| refused(e)))
}

/// HMAC-SHA1 of the concatenation of `parts` under `key` (RFC 2104). The message copy and the
/// returned MAC are wiped on drop.
pub fn hmac_sha1(key: &Cred, parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    let key = key.wire();
    let mut k0 = Zeroizing::new([0_u8; BLOCK]);
    if key.len() > BLOCK {
        k0[..20].copy_from_slice(&digests::sha1(&[key])[..]);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0_u8; BLOCK]);
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x36;
    }
    let inner = digests::sha1_of(std::iter::once(&pad[..]).chain(parts.iter().copied()));
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x5c;
    }
    digests::sha1(&[&pad[..], &inner[..]])
}

/// SHA-256 of the concatenation of `parts`. The returned digest is wiped on drop.
pub fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crypto::sha256_parts(parts))
}

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
mod tests;
