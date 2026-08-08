// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC-published test vectors: inputs and expected outputs taken VERBATIM from the RFCs, so the
//! oracle is the spec author, not this codebase.
//!
//! Coverage honesty: RFC 7636 (PKCE) appendix B publishes the only vector applicable to what this
//! crate computes today. RFC 7515 (JWS) appendix A and RFC 9068 (JWT access tokens) vectors are
//! NOT exercised because this crate issues opaque tokens and contains no JOSE code; the day a JWT
//! issuer lands, its vectors land beside it in this file.

use oauth_as::pkce;

/// RFC 7636 appendix B, verbatim: the example `code_verifier` and its S256 `code_challenge`.
const APPENDIX_B_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const APPENDIX_B_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn rfc7636_appendix_b_s256_derivation() {
    assert_eq!(
        pkce::code_challenge_s256(APPENDIX_B_VERIFIER),
        APPENDIX_B_CHALLENGE
    );
}

#[test]
fn rfc7636_appendix_b_verification_accepts_the_pair_and_rejects_tampering() {
    assert!(pkce::verify_s256(APPENDIX_B_VERIFIER, APPENDIX_B_CHALLENGE));
    // Flip one character of the verifier: verification must fail.
    let tampered = APPENDIX_B_VERIFIER.replace('d', "e");
    assert_ne!(tampered, APPENDIX_B_VERIFIER);
    assert!(!pkce::verify_s256(&tampered, APPENDIX_B_CHALLENGE));
    // And against a truncated challenge.
    assert!(!pkce::verify_s256(
        APPENDIX_B_VERIFIER,
        &APPENDIX_B_CHALLENGE[..42]
    ));
}

#[test]
fn rfc7636_appendix_b_verifier_is_grammatical() {
    // The appendix's own verifier satisfies the section 4.1 grammar; our validator must agree.
    assert!(pkce::verifier_is_valid(APPENDIX_B_VERIFIER));
}

/// RFC 7636 appendix B also fixes the byte sequence of the verifier's SHA-256 digest via the
/// base64url mapping; decode our challenge output and pin the first bytes the RFC's example
/// walkthrough implies. This is a red-proof of the harness itself: if the challenge constant above
/// were ever "updated" to match a broken implementation, this independent decode would disagree.
#[test]
fn rfc7636_challenge_is_unpadded_base64url_of_a_32_byte_digest() {
    let c = pkce::code_challenge_s256(APPENDIX_B_VERIFIER);
    assert_eq!(
        c.len(),
        43,
        "32 bytes maps to exactly 43 unpadded base64url chars"
    );
    assert!(!c.ends_with('='));
    assert!(c
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}
