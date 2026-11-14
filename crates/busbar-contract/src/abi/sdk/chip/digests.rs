// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHA-1, MD5 and SHA-256 of concatenated parts for the credential recipes, over the crypto
//! facade (decision 224). Message copies and results are wiped on drop. Infallible until the
//! plugin wave (see `sdk::hmac`); core's software backend refuses neither legacy digest.

use zeroize::Zeroizing;

/// Feed the concatenation of `parts`, then its Merkle-Damgard padding (`0x80`, zeros, the bit
/// length in the digest's byte order), to `compress` one 64-byte block at a time, through one wiped
/// block on the stack: the message is never copied whole. `already` counts the bytes the state has
/// absorbed before (whole blocks), for the length.
pub(crate) fn absorb<'a>(
    parts: impl IntoIterator<Item = &'a [u8]>,
    big_endian: bool,
    already: u64,
    mut compress: impl FnMut(&[u8; 64]),
) {
    let mut block = Zeroizing::new([0_u8; 64]);
    let mut fill = 0;
    let mut total = already;
    for part in parts {
        total = total.wrapping_add(part.len() as u64);
        let mut rest = part;
        while !rest.is_empty() {
            let n = (64 - fill).min(rest.len());
            block[fill..fill + n].copy_from_slice(&rest[..n]);
            fill += n;
            rest = &rest[n..];
            if fill == 64 {
                compress(&block);
                fill = 0;
            }
        }
    }
    block[fill] = 0x80;
    block[fill + 1..].fill(0);
    if fill >= 56 {
        compress(&block);
        block.fill(0);
    }
    let bits = total.wrapping_mul(8);
    block[56..].copy_from_slice(&if big_endian {
        bits.to_be_bytes()
    } else {
        bits.to_le_bytes()
    });
    compress(&block);
}

/// SHA-1 of the concatenation of `parts`.
pub(crate) fn sha1(parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    sha1_of(parts.iter().copied())
}

/// SHA-1 of the concatenation of `parts`, streamed ([`absorb`]).
pub(crate) fn sha1_of<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Zeroizing<[u8; 20]> {
    let mut h = Zeroizing::new([
        0x6745_2301_u32,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ]);
    let mut w = Zeroizing::new([0_u32; 80]);
    absorb(parts, true, 0, |block| {
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*c);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let mut s = Zeroizing::new(*h);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((s[1] & s[2]) | (!s[1] & s[3]), 0x5A82_7999),
                20..=39 => (s[1] ^ s[2] ^ s[3], 0x6ED9_EBA1),
                40..=59 => ((s[1] & s[2]) | (s[1] & s[3]) | (s[2] & s[3]), 0x8F1B_BCDC),
                _ => (s[1] ^ s[2] ^ s[3], 0xCA62_C1D6),
            };
            let t = s[0]
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(s[4])
                .wrapping_add(k)
                .wrapping_add(*wi);
            s[4] = s[3];
            s[3] = s[2];
            s[2] = s[1].rotate_left(30);
            s[1] = s[0];
            s[0] = t;
        }
        for (hi, si) in h.iter_mut().zip(s.iter()) {
            *hi = hi.wrapping_add(*si);
        }
    });
    let mut out = Zeroizing::new([0_u8; 20]);
    for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h.iter()) {
        *o = v.to_be_bytes();
    }
    out
}

/// MD5 of the concatenation of `parts` (Postgres md5 authentication only).
pub(crate) fn md5(parts: &[&[u8]]) -> Zeroizing<[u8; 16]> {
    let mut h = Zeroizing::new([0x6745_2301_u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]);
    let mut x = Zeroizing::new([0_u32; 16]);
    absorb(parts.iter().copied(), false, 0, |block| {
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            x[i] = u32::from_le_bytes(*c);
        }
        let mut s = Zeroizing::new(*h);
        for (i, shift) in MD5_S.iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((s[1] & s[2]) | (!s[1] & s[3]), i),
                1 => ((s[3] & s[1]) | (!s[3] & s[2]), (5 * i + 1) % 16),
                2 => (s[1] ^ s[2] ^ s[3], (3 * i + 5) % 16),
                _ => (s[2] ^ (s[1] | !s[3]), (7 * i) % 16),
            };
            let t = s[3];
            s[3] = s[2];
            s[2] = s[1];
            s[1] = s[1].wrapping_add(
                s[0].wrapping_add(f)
                    .wrapping_add(md5_k(i))
                    .wrapping_add(x[g])
                    .rotate_left(*shift),
            );
            s[0] = t;
        }
        for (hi, si) in h.iter_mut().zip(s.iter()) {
            *hi = hi.wrapping_add(*si);
        }
    });
    let mut out = Zeroizing::new([0_u8; 16]);
    for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h.iter()) {
        *o = v.to_le_bytes();
    }
    out
}

/// SHA-256 of the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    crate::abi::sdk::hmac::sha256_parts(parts.iter().copied())
}
