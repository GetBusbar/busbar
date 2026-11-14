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
fn sha256_resume(
    mut state: Zeroizing<[u32; 8]>,
    consumed: u64,
    data: &[u8],
) -> Zeroizing<[u8; 32]> {
    let total = data.len() as u64 + consumed;
    let (blocks, rest) = data.as_chunks::<BLOCK>();
    for c in blocks {
        compress(&mut state, c);
    }
    let mut tail = Zeroizing::new([0_u8; 2 * BLOCK]);
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let end = if rest.len() + 9 <= BLOCK {
        BLOCK
    } else {
        2 * BLOCK
    };
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
/// (PBKDF2): two compressions per MAC instead of four. The states are wiped on drop.
pub(crate) struct HmacSha256Key {
    inner: Zeroizing<[u32; 8]>,
    outer: Zeroizing<[u32; 8]>,
}

impl HmacSha256Key {
    pub(crate) fn new(key: &[u8]) -> Self {
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

    pub(crate) fn mac(&self, data: &[u8]) -> Zeroizing<[u8; 32]> {
        let inner = sha256_resume(self.inner.clone(), BLOCK as u64, data);
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
