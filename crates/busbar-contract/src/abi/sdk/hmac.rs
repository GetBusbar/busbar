// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE WIPED HMAC-SHA256 (coordinator ruling 2026-10-18, Q128 auth-sigv4 round 2 (a)): the HMAC
//! an auth plugin keys over secret material ([`hmac_sha256`]). Every key-derived value — the padded
//! key, the inner and outer pad blocks, the SHA-256 chaining states and the inner digest — lives in
//! a buffer wiped on drop, and so does the answer (THE DESIGN section 6: "auth material is
//! zeroised").
//!
//! WHY IT IS NOT `ring`. A library HMAC keeps its key's inner and outer pad states in a value it
//! frees unwiped (`ring::hmac::Key`), and a library digest context does not wipe its chaining state
//! either, so keying `ring` here would move the leak, not close it. This one primitive is the
//! ledgered exception to THE DESIGN section 2's single crypto backend: section 6's zeroisation
//! over section 2's rule, for HMAC-SHA256 over key material only; every other primitive stays on `ring`. Moved unchanged
//! in substance from `busbar-auth-sigv4` (`sigv4.rs`), whose copy is deleted; any other auth plugin
//! with an HMAC over secret keys moves to it in its next sync.

use zeroize::Zeroizing;

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

/// Run SHA-256's compression function (FIPS 180-4, 6.2.2) over one whole `block` into `state`.
/// Written here rather than taken from a library's feature: the message schedule and the working
/// variables carry key-derived words, so they live in wiped buffers too, and the binary's
/// unified dependency features stay the ones every linked plugin declares.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
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
/// padded final blocks (which carry `data`'s tail) are wiped on drop, and so is the digest.
pub(crate) fn sha256_wiped(prefix: Option<&[u8; BLOCK]>, data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut state = Zeroizing::new(SHA256_IV);
    let mut total = data.len() as u64;
    if let Some(p) = prefix {
        compress(&mut state, p);
        total += BLOCK as u64;
    }
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

/// HMAC-SHA256 of `data` under `key` (RFC 2104; a key past the block size is hashed first). HMAC
/// accepts a key of any length, so there is no error arm. Every key-derived value — the padded key,
/// the inner and outer pad blocks, the chaining states and the inner digest — lives in a buffer
/// wiped on drop, and so does the answer: no key state outlives the call unwiped.
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

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
mod tests;
