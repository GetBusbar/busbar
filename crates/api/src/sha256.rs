// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHA-256 and HMAC-SHA256, in this crate and in plain Rust, because a CONTRACT crate must reach no
//! OS primitive on any target.
//!
//! `busbar-api` is the crate every plugin builds against — "no I/O, no engine state, no transport" —
//! and the digest every credential compare in the tree routes through ([`super::auth::sha256_hex`])
//! lives here. So does the HMAC the Bedrock SigV4 signer chains, because the crate that owns SigV4
//! names this crate and this crate may not name it back. The `sha2` crate that
//! used to compute both carries `cpufeatures` as an UNCONDITIONAL target dependency on aarch64 and
//! x86, and `cpufeatures` reaches `libc` for its runtime detection (`getauxval`/`sysctl`). That edge
//! was one of the two roots by which `libc` reached the plane's and the dialect crates'
//! transitive closure — a closure ARCHITECTURE.md section 1.2 says performs no I/O and reaches no
//! `libc` — and a plane was green against that ban only by a dated waiver. This module is the fix
//! rather than the waiver: FIPS 180-4's construction, no feature detection, no `unsafe`, no
//! dependency, so `sha2` leaves the closure's dependency graph entirely.
//!
//! PROOF. `tests/sha256_tests.rs` pins this implementation against the NIST FIPS 180-4 / CAVP
//! known-answer vectors (the one-, two- and four-block messages and the million-`a` message),
//! against RFC 4231's seven HMAC-SHA-256 cases (short, long and block-sized keys, truncation
//! excluded), against AWS's published SigV4 worked example (the canonical-request digest and the
//! four-step signing chain), and BYTE-FOR-BYTE against the RustCrypto `sha2`/`hmac` crates — as
//! DEV-dependencies, off every shipped target — over a corpus that crosses every block and
//! length-padding boundary (each length 0..=320 plus the 55/56/63/64/119/120 edges) and the
//! sigv4-shaped inputs the signer actually hashes.
//!
//! COST. One 64-byte block is 64 rounds of 32-bit arithmetic; `sha2`'s portable path is the same
//! arithmetic, and its SHA-NI/ARMv8 intrinsics path (the thing `cpufeatures` selects) is the only
//! thing given up. The inputs on any hot path here are a credential (tens of bytes) and a SigV4
//! canonical request (hundreds); the digest is not where either path spends its time.

/// The first 32 bits of the fractional parts of the cube roots of the first 64 primes — FIPS
/// 180-4 section 4.2.2.
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

/// The initial hash value — the first 32 bits of the fractional parts of the square roots of the
/// first eight primes — FIPS 180-4 section 5.3.3.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The message block size in bytes (512 bits).
pub const BLOCK_BYTES: usize = 64;
/// The digest size in bytes (256 bits).
pub const DIGEST_BYTES: usize = 32;

/// A streaming SHA-256: feed it any number of slices, then take the digest.
///
/// Streaming because HMAC's inner hash is `key-pad || message` and the SigV4 signer's inputs are
/// assembled from parts; one-shot callers use [`sha256`].
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; BLOCK_BYTES],
    buffered: usize,
    /// Total message length in BYTES so far. The padding writes it in bits; `u64` bytes is 2^67
    /// bits, past the 2^64-bit ceiling FIPS 180-4 defines the function for, so the shift below can
    /// never wrap an input this crate could hold.
    len_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub const fn new() -> Sha256 {
        Sha256 {
            state: H0,
            buf: [0u8; BLOCK_BYTES],
            buffered: 0,
            len_bytes: 0,
        }
    }

    /// Absorb `data`. Whole blocks are compressed straight from the input; only a trailing partial
    /// block is copied into the buffer.
    pub fn update(&mut self, data: &[u8]) {
        self.len_bytes = self.len_bytes.wrapping_add(data.len() as u64);
        let mut rest = data;
        if self.buffered > 0 {
            let take = (BLOCK_BYTES - self.buffered).min(rest.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered < BLOCK_BYTES {
                return;
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }
        let (blocks, tail) = rest.as_chunks::<BLOCK_BYTES>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        self.buf[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// The digest: pad per FIPS 180-4 section 5.1.1 (a `1` bit, zeros to 448 mod 512, the message
    /// length in bits as a big-endian u64), compress the last block(s), emit the state big-endian.
    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        let bit_len = self.len_bytes << 3;
        let mut block = self.buf;
        block[self.buffered] = 0x80;
        if self.buffered + 1 > BLOCK_BYTES - 8 {
            // No room for the length in this block: zero-fill, compress, and pad a second one.
            block[self.buffered + 1..].fill(0);
            compress(&mut self.state, &block);
            block = [0u8; BLOCK_BYTES];
        } else {
            block[self.buffered + 1..BLOCK_BYTES - 8].fill(0);
        }
        block[BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &block);

        let mut out = [0u8; DIGEST_BYTES];
        for (slot, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *slot = word.to_be_bytes();
        }
        out
    }
}

/// One compression round over a 64-byte block — FIPS 180-4 section 6.2.2.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_BYTES]) {
    let mut w = [0u32; 64];
    for (slot, chunk) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *slot = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wi) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(v);
    }
}

/// One-shot SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// HMAC-SHA256 of `data` under `key` — RFC 2104 over [`Sha256`].
///
/// A key longer than one block is first hashed down to a digest; a shorter one is zero-padded to
/// the block. Infallible by construction: HMAC accepts a key of ANY length, which is why the SigV4
/// signer that chains four of these has no failure arm to carry.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut padded = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        padded[..DIGEST_BYTES].copy_from_slice(&sha256(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut ipad = padded;
    let mut opad = padded;
    for (i, o) in ipad.iter_mut().zip(opad.iter_mut()) {
        *i ^= 0x36;
        *o ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}

#[cfg(test)]
#[path = "tests/sha256_tests.rs"]
mod tests;
