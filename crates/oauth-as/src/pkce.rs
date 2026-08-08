// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PKCE (RFC 7636), `S256` only per OAuth 2.1. The derivation is
//! `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` with no padding
//! (section 4.2), and `tests/rfc_vectors.rs` locks it against the appendix B vector.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Compute the `S256` challenge for a verifier (RFC 7636 section 4.2).
pub fn code_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Verify a presented verifier against a stored challenge (RFC 7636 section 4.6): recompute and
/// compare. The comparison is constant time in the challenge length; an S256 challenge is a fixed
/// 43 characters so length itself leaks nothing.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    let computed = code_challenge_s256(verifier);
    let (a, b) = (computed.as_bytes(), challenge.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Whether a string is a well-formed `code_verifier` (RFC 7636 section 4.1): 43 to 128 characters
/// of `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
pub fn verifier_is_valid(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_grammar_bounds() {
        let ok = "a".repeat(43);
        assert!(verifier_is_valid(&ok));
        assert!(verifier_is_valid(&"a".repeat(128)));
        assert!(!verifier_is_valid(&"a".repeat(42)), "below 43 chars");
        assert!(!verifier_is_valid(&"a".repeat(129)), "above 128 chars");
        assert!(
            !verifier_is_valid(&format!("{}+", "a".repeat(43))),
            "'+' outside unreserved set"
        );
    }

    #[test]
    fn challenge_shape() {
        let c = code_challenge_s256(&"x".repeat(43));
        assert_eq!(
            c.len(),
            43,
            "SHA-256 is 32 bytes; unpadded base64url of 32 bytes is 43 chars"
        );
        assert!(!c.contains('='), "no padding per RFC 7636 appendix A");
    }
}
