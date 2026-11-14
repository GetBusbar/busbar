// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Wiped HMAC-SHA256, HMAC-SHA1 and SHA-256 for authentication material. Padded keys, pad blocks,

use zeroize::Zeroizing;

use super::chip::digests;
use super::cred::Cred;

/// SHA-256's block size, in bytes.
pub(crate) const BLOCK: usize = 64;

/// SHA-256's initial chaining state (FIPS 180-4, 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256's round constants (FIPS 180-4, 4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[cfg(test)]
thread_local! {
    /// Compressions (SHA-256 and SHA-1) run on this thread, for the count tests.
    static COMPRESSIONS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Compressions run on this thread so far (test builds only).
#[cfg(test)]
pub(crate) fn compressions() -> u64 {
    COMPRESSIONS.with(core::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn count_compression() {
    COMPRESSIONS.with(|c| c.set(c.get() + 1));
}

/// Run SHA-256's compression function (FIPS 180-4, 6.2.2) over one whole `block` into `state`.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
    #[cfg(test)]
    count_compression();
    let mut w = Zeroizing::new([0_u32; 64]);
    for (t, word) in block.as_chunks::<4>().0.iter().enumerate() {
        w[t] = u32::from_be_bytes(*word);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let mut v = Zeroizing::new(*state);
    for t in 0..64 {
        let [a, b, c, d, e, f, g, h] = *v;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        *v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (s, x) in state.iter_mut().zip(v.iter()) {
        *s = s.wrapping_add(*x);
    }
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

/// Feed the concatenation of `parts` to `block` one whole block at a time, buffering a partial
/// block in `buf`. Returns how many bytes `buf` holds at the end and the total length absorbed
/// (`consumed` + every part). Shared by the SHA-256 and SHA-1 streams.
pub(crate) fn stream_blocks(
    buf: &mut [u8; BLOCK],
    consumed: u64,
    parts: &[&[u8]],
    mut block: impl FnMut(&[u8; BLOCK]),
) -> (usize, u64) {
    let mut fill = 0_usize;
    let mut total = consumed;
    for part in parts {
        let mut p = *part;
        total = total.wrapping_add(p.len() as u64);
        if fill > 0 {
            let take = (BLOCK - fill).min(p.len());
            buf[fill..fill + take].copy_from_slice(&p[..take]);
            fill += take;
            p = &p[take..];
            if fill < BLOCK {
                continue;
            }
            block(&*buf);
            fill = 0;
        }
        let (blocks, rest) = p.as_chunks::<BLOCK>();
        for c in blocks {
            block(c);
        }
        buf[..rest.len()].copy_from_slice(rest);
        fill = rest.len();
    }
    (fill, total)
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
    let (fill, total) = stream_blocks(&mut *buf, consumed, parts, |b| compress(&mut state, b));
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
    let mut k0 = Zeroizing::new([0_u8; BLOCK]);
    if key.len() > BLOCK {
        k0[..32].copy_from_slice(&sha256_wiped(None, key)[..]);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0_u8; BLOCK]);
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x36;
    }
    let inner = sha256_wiped(Some(&*pad), data);
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x5c;
    }
    sha256_wiped(Some(&*pad), &inner[..])
}

/// HMAC-SHA1 of the concatenation of `parts` under `key` (RFC 2104). Keys longer than the block
pub fn hmac_sha1(key: &Cred, parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    HmacSha1Key::new(key).mac_parts(parts)
}

/// SHA-256 of the concatenation of `parts`. Message copies, digest states and the returned digest
pub fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    digests::sha256(parts)
}

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
mod tests;
