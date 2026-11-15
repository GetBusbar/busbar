// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fingerprint: `fp`, `fp_parts` and `CORE_FP` (IF §7.5).

const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64 that skips ASCII whitespace (r10 layout::ident). Offset 0xcbf29ce484222325, prime 0x100000001b3.
pub const fn fp(bytes: &[u8]) -> u64 {
    fold(OFFSET, bytes)
}
/// Folds several parts with a 0xFF separator between them.
pub const fn fp_parts(parts: &[&[u8]]) -> u64 {
    let mut hash = OFFSET;
    let mut p = 0;
    while p < parts.len() {
        if p > 0 {
            hash = separate(hash);
        }
        hash = fold(hash, parts[p]);
        p += 1;
    }
    hash
}
/// The fingerprint of the `mechanism! { .. }` block in types.rs + records.rs + host.rs + need.rs + plugin.rs.
///
/// `fp_parts` over the five blocks in that order, folded one block per constant so no single const evaluation
/// walks all of them (`a_block_chain_is_fp_parts` below checks the two agree).
pub const CORE_FP: u64 = fold(
    separate(AFTER_NEED),
    crate::plugin::MECHANISM_BLOCK.as_bytes(),
);
const AFTER_TYPES: u64 = fold(OFFSET, crate::types::MECHANISM_BLOCK.as_bytes());
const AFTER_RECORDS: u64 = fold(
    separate(AFTER_TYPES),
    crate::records::MECHANISM_BLOCK.as_bytes(),
);
const AFTER_HOST: u64 = fold(
    separate(AFTER_RECORDS),
    crate::host::MECHANISM_BLOCK.as_bytes(),
);
const AFTER_NEED: u64 = fold(
    separate(AFTER_HOST),
    crate::need::MECHANISM_BLOCK.as_bytes(),
);

/// FNV-1a over `bytes` from `hash`, skipping the ASCII whitespace bytes (space, \t, \n, \x0C, \r).
const fn fold(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if !matches!(byte, b' ' | b'\t' | b'\n' | b'\x0C' | b'\r') {
            hash = (hash ^ byte as u64).wrapping_mul(PRIME);
        }
        i += 1;
    }
    hash
}

/// The 0xFF byte `fp_parts` puts between two parts.
const fn separate(hash: u64) -> u64 {
    (hash ^ 0xFF).wrapping_mul(PRIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_chain_is_fp_parts() {
        let blocks = [
            crate::types::MECHANISM_BLOCK.as_bytes(),
            crate::records::MECHANISM_BLOCK.as_bytes(),
            crate::host::MECHANISM_BLOCK.as_bytes(),
            crate::need::MECHANISM_BLOCK.as_bytes(),
            crate::plugin::MECHANISM_BLOCK.as_bytes(),
        ];
        assert_eq!(CORE_FP, fp_parts(&blocks));
        // Every block is hashed: each one holds its frozen items (a doc line or token change moves CORE_FP).
        assert!(crate::types::MECHANISM_BLOCK.contains("TOKEN_SESSION"));
        assert!(crate::records::MECHANISM_BLOCK.contains("D_ERRORS"));
        assert!(crate::host::MECHANISM_BLOCK.contains("crypto_status"));
        assert!(crate::need::MECHANISM_BLOCK.contains("NeedResRec"));
        assert!(crate::plugin::MECHANISM_BLOCK.contains("former_names"));
    }

    #[test]
    fn whitespace_never_moves_a_fingerprint() {
        assert_eq!(fp(b"pub const A: u32 = 1;"), fp(b"pub const A:u32=1;"));
        assert_ne!(fp(b"pub const A: u32 = 1;"), fp(b"pub const A: u32 = 2;"));
    }
}
