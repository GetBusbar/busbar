// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHA-1 (FIPS 180-4) and MD5 (RFC 1321) whose every state and padding buffer is wiped, for the
//! legacy database auth recipes keyed over a password. The same reasoning as `sdk::hmac`: a
//! library digest frees its chaining state unwiped.

use zeroize::Zeroizing;

fn padded(data: &[u8], big_endian: bool) -> Zeroizing<Vec<u8>> {
    let mut m = Zeroizing::new(Vec::with_capacity(data.len() + 72));
    m.extend_from_slice(data);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    let bits = (data.len() as u64).wrapping_mul(8);
    if big_endian {
        m.extend_from_slice(&bits.to_be_bytes());
    } else {
        m.extend_from_slice(&bits.to_le_bytes());
    }
    m
}

/// SHA-1 of the concatenation of `parts`.
pub(crate) fn sha1(parts: &[&[u8]]) -> Zeroizing<[u8; 20]> {
    let data = Zeroizing::new(parts.concat());
    let m = padded(&data, true);
    let mut h = Zeroizing::new([
        0x6745_2301_u32,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ]);
    let mut w = Zeroizing::new([0_u32; 80]);
    for block in m.as_chunks::<64>().0 {
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
    }
    let mut out = Zeroizing::new([0_u8; 20]);
    for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h.iter()) {
        *o = v.to_be_bytes();
    }
    out
}

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

fn md5_k(i: usize) -> u32 {
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    K[i]
}

/// MD5 of the concatenation of `parts`.
pub(crate) fn md5(parts: &[&[u8]]) -> Zeroizing<[u8; 16]> {
    let data = Zeroizing::new(parts.concat());
    let m = padded(&data, false);
    let mut h = Zeroizing::new([0x6745_2301_u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]);
    let mut x = Zeroizing::new([0_u32; 16]);
    for block in m.as_chunks::<64>().0 {
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
    }
    let mut out = Zeroizing::new([0_u8; 16]);
    for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h.iter()) {
        *o = v.to_le_bytes();
    }
    out
}

/// SHA-256 of the concatenation of `parts`, wiped (`sdk::hmac`'s primitive).
pub(crate) fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let data = Zeroizing::new(parts.concat());
    crate::abi::sdk::hmac::sha256_wiped(None, &data)
}
