// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The wire fingerprints (interface revision C.4, C.7): FNV-1a over a contract's tokens, whitespace-blind
//! and **comment-blind**. A fingerprint covers names, numbers, field types and order. A wording fix in a
//! doc comment moves no fingerprint, refuses no plugin and moves no pin (the lock file's separate `text`
//! hash is what makes a change of meaning visible).

const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// The fingerprint of one text.
pub const fn fp(bytes: &[u8]) -> u64 {
    fold(OFFSET, bytes)
}
/// The fingerprint of several texts, each separated from the next (so `["ab", "c"]` is not `["a", "bc"]`).
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
/// The core contract's wire fingerprint: this crate's three core blocks (records, host, need), then
/// busbar-ffi's three (raw types, header, the call record and entry aliases). It contains no kind's items:
/// single-kind tags, steps and host services live in their kind's own fingerprint, and the vocabularies two
/// or three kinds share are versioned modules with fingerprints of their own (`crate::vocab`), folded into
/// the kinds that use them. So a change to one kind's contract cannot move it.
pub const CORE_FP: u64 = fold(
    separate(AFTER_FFI_HEADER),
    busbar_ffi::MECHANISM[2].as_bytes(),
);
const AFTER_RECORDS: u64 = fold(OFFSET, crate::records::MECHANISM_BLOCK.as_bytes());
const AFTER_HOST: u64 = fold(
    separate(AFTER_RECORDS),
    crate::host::MECHANISM_BLOCK.as_bytes(),
);
const AFTER_NEED: u64 = fold(
    separate(AFTER_HOST),
    crate::need::MECHANISM_BLOCK.as_bytes(),
);
const AFTER_FFI_RAW: u64 = fold(separate(AFTER_NEED), busbar_ffi::MECHANISM[0].as_bytes());
const AFTER_FFI_HEADER: u64 = fold(separate(AFTER_FFI_RAW), busbar_ffi::MECHANISM[1].as_bytes());

const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0C' | b'\r')
}

/// The index after any whitespace at `i`.
const fn skip_space(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && is_space(bytes[i]) {
        i += 1;
    }
    i
}

/// If a doc attribute as `stringify!` spells a comment (`#[doc = "..."]`, with any spacing, the string
/// plain or raw) starts at `i`, the index after its closing `]`; otherwise `i`.
const fn skip_doc(bytes: &[u8], i: usize) -> usize {
    if i >= bytes.len() || bytes[i] != b'#' {
        return i;
    }
    let mut at = skip_space(bytes, i + 1);
    if at < bytes.len() && bytes[at] == b'!' {
        at = skip_space(bytes, at + 1);
    }
    if at >= bytes.len() || bytes[at] != b'[' {
        return i;
    }
    at = skip_space(bytes, at + 1);
    if at + 3 > bytes.len() || bytes[at] != b'd' || bytes[at + 1] != b'o' || bytes[at + 2] != b'c' {
        return i;
    }
    at = skip_space(bytes, at + 3);
    if at >= bytes.len() || bytes[at] != b'=' {
        return i;
    }
    at = skip_space(bytes, at + 1);
    // A raw string: r, then n hashes, then the quote; it ends at a quote followed by n hashes.
    let mut hashes = 0;
    let mut raw = false;
    if at < bytes.len() && bytes[at] == b'r' {
        raw = true;
        at += 1;
        while at < bytes.len() && bytes[at] == b'#' {
            hashes += 1;
            at += 1;
        }
    }
    if at >= bytes.len() || bytes[at] != b'"' {
        return i;
    }
    at += 1;
    loop {
        if at >= bytes.len() {
            return i;
        }
        if !raw && bytes[at] == b'\\' {
            at += 2;
            continue;
        }
        if bytes[at] == b'"' {
            let mut seen = 0;
            while seen < hashes && at + 1 + seen < bytes.len() && bytes[at + 1 + seen] == b'#' {
                seen += 1;
            }
            if seen == hashes {
                at += 1 + hashes;
                break;
            }
        }
        at += 1;
    }
    at = skip_space(bytes, at);
    if at < bytes.len() && bytes[at] == b']' {
        at + 1
    } else {
        i
    }
}

const fn fold(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        // Only a `#` can open a doc attribute: every other byte costs nothing extra here.
        if byte == b'#' {
            let after = skip_doc(bytes, i);
            if after != i {
                i = after;
                continue;
            }
        }
        if !is_space(byte) {
            hash = (hash ^ byte as u64).wrapping_mul(PRIME);
        }
        i += 1;
    }
    hash
}

const fn separate(hash: u64) -> u64 {
    (hash ^ 0xFF).wrapping_mul(PRIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_chain_is_fp_parts() {
        let [ffi_raw, ffi_header, ffi_vt] = busbar_ffi::MECHANISM.map(str::as_bytes);
        let blocks = [
            crate::records::MECHANISM_BLOCK.as_bytes(),
            crate::host::MECHANISM_BLOCK.as_bytes(),
            crate::need::MECHANISM_BLOCK.as_bytes(),
            ffi_raw,
            ffi_header,
            ffi_vt,
        ];
        assert_eq!(CORE_FP, fp_parts(&blocks));
        assert!(busbar_ffi::MECHANISM[0].contains("TOKEN_SESSION"));
        assert!(crate::records::MECHANISM_BLOCK.contains("D_ERRORS"));
        assert!(crate::host::MECHANISM_BLOCK.contains("crypto_status"));
        assert!(crate::need::MECHANISM_BLOCK.contains("NeedResRec"));
        assert!(busbar_ffi::MECHANISM[1].contains("former_names"));
        assert!(busbar_ffi::MECHANISM[2].contains("Call"));
    }

    #[test]
    fn whitespace_never_moves_a_fingerprint() {
        assert_eq!(fp(b"pub const A: u32 = 1;"), fp(b"pub const A:u32=1;"));
        assert_ne!(fp(b"pub const A: u32 = 1;"), fp(b"pub const A: u32 = 2;"));
    }

    #[test]
    fn a_comment_never_moves_a_fingerprint() {
        let bare = fp(b"pub const A: u32 = 1; pub struct S { pub a: u32 }");
        assert_eq!(
            fp(br##"#[doc = " The first."] pub const A: u32 = 1; pub struct S { #[doc = r#" a "quoted" word"#] pub a: u32 }"##),
            bare
        );
        assert_eq!(
            fp(br#"# [doc = " an escaped \" quote ] here"] pub const A: u32 = 1; pub struct S { pub a: u32 }"#),
            bare
        );
        assert_eq!(
            fp(stringify!(
                /// A doc comment as the compiler spells it.
                pub const A: u32 = 1;
                pub struct S {
                    /// A field's.
                    pub a: u32,
                }
            )
            .as_bytes()),
            bare
        );
        // Any other attribute is wire.
        assert_ne!(
            fp(b"#[repr(C)] pub struct S { pub a: u32 }"),
            fp(b"pub struct S { pub a: u32 }")
        );
    }
}
