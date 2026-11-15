// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fingerprint: `fp`, `fp_parts` and `CORE_FP` (IF §7.5). W0-ABI stub: frozen signatures, `todo!()` bodies; A1 fills it.

/// FNV-1a 64 that skips ASCII whitespace (r10 layout::ident). Offset 0xcbf29ce484222325, prime 0x100000001b3.
pub const fn fp(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if !byte.is_ascii_whitespace() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        i += 1;
    }
    hash
}
/// Folds several parts with a 0xFF separator between them.
pub const fn fp_parts(parts: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut p = 0;
    while p < parts.len() {
        if p > 0 {
            hash ^= 0xFF;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let part = parts[p];
        let mut i = 0;
        while i < part.len() {
            let byte = part[i];
            if !byte.is_ascii_whitespace() {
                hash ^= byte as u64;
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            i += 1;
        }
        p += 1;
    }
    hash
}
/// The fingerprint of the `mechanism! { .. }` block in types.rs + records.rs + host.rs + need.rs + plugin.rs.
// W0-ABI stub value; A1 sets it (the `mechanism!` block computes it).
pub const CORE_FP: u64 = 0;
