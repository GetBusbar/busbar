// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE WIPED HMAC-SHA256: an HMAC whose every key-derived byte is zeroised before it returns.
//!
//! [`crate::sign::AuditSigningKey::derived_secret`] keys an HMAC with the audit seed. `ring`'s
//! `hmac::Key` pads that key into a buffer it never clears and keeps the inner and outer block
//! states in the key value, which is dropped unwiped; those states are enough to compute the HMAC
//! under the seed for any label. THE DESIGN §6 (`BUSBAR-1.6.0.md` l.871, "auth material is
//! zeroised") takes precedence over the one-crypto-backend rule for this one primitive, so the HMAC
//! here is FIPS 198-1 over a FIPS 180-4 SHA-256 whose state, message schedule and block buffers are
//! all wiped: the padded key, the inner and outer pads, the chaining state after each block and the
//! inner digest.
//!
//! Nothing else in the workspace may hash with it: it exists for the seed-keyed derivation alone.

use zeroize::Zeroize as _;

/// SHA-256's round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256's initial hash value (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256's block length in bytes.
const BLOCK: usize = 64;

/// A SHA-256 in progress whose every byte is wiped on drop.
struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK],
    filled: usize,
    total: u64,
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
        self.filled.zeroize();
        self.total.zeroize();
    }
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            state: H0,
            block: [0; BLOCK],
            filled: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.total = self.total.wrapping_add(bytes.len() as u64);
        while !bytes.is_empty() {
            let take = (BLOCK - self.filled).min(bytes.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&bytes[..take]);
            self.filled += take;
            bytes = &bytes[take..];
            if self.filled == BLOCK {
                compress(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    /// The digest, written into `out`. Consumes the hash; everything it held is wiped on drop.
    fn finish(mut self, out: &mut [u8; 32]) {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.filled != BLOCK - 8 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

/// One SHA-256 compression of `block` into `state` (FIPS 180-4 §6.2.2). The message schedule and
/// the working variables are wiped before it returns.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut v = *state;
    for (k, wi) in K.iter().zip(w.iter()) {
        let [a, b, c, d, e, f, g, h] = v;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(*wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (s, x) in state.iter_mut().zip(v.iter()) {
        *s = s.wrapping_add(*x);
    }
    w.zeroize();
    v.zeroize();
}

/// HMAC-SHA256 of `message` under `key` (FIPS 198-1), with every key-derived byte wiped before it
/// returns. `key` is at most one block: the one caller keys with a 32-byte seed.
///
/// # Panics
///
/// `key` is longer than 64 bytes, which no caller of this module passes.
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    assert!(
        key.len() <= BLOCK,
        "the wiped HMAC keys with at most one block"
    );
    let mut pad = [0u8; BLOCK];
    pad[..key.len()].copy_from_slice(key);
    for b in &mut pad {
        *b ^= 0x36;
    }
    let mut inner_digest = [0u8; 32];
    let mut inner = Sha256::new();
    inner.update(&pad);
    inner.update(message);
    inner.finish(&mut inner_digest);
    // The outer pad from the inner one: 0x36 ^ 0x5c, so the key itself is never re-copied.
    for b in &mut pad {
        *b ^= 0x36 ^ 0x5c;
    }
    let mut out = [0u8; 32];
    let mut outer = Sha256::new();
    outer.update(&pad);
    outer.update(&inner_digest);
    outer.finish(&mut out);
    pad.zeroize();
    inner_digest.zeroize();
    out
}
