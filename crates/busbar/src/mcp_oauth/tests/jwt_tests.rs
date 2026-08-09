// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit coverage for the compact-JWS parser and the `ring` signature verifiers, at the level below
//! [`super::ResourceServer::admit`]. The admission battery proves the resource server refuses the
//! right tokens; these prove the primitive it refuses them WITH behaves the way the refusals assume.

use super::jwt;
use super::support::*;

/// The accepted algorithm set, stated as a test rather than only as a constant, because every
/// algorithm outside it is a rejection with security consequences.
#[test]
fn only_rs256_and_es256_are_accepted() {
    assert!(jwt::supported_alg("RS256"));
    assert!(jwt::supported_alg("ES256"));
    for forbidden in [
        "none", "None", "NONE", "HS256", "HS384", "HS512", "RS384", "RS512", "ES384", "PS256",
        "EdDSA", "",
    ] {
        assert!(
            !jwt::supported_alg(forbidden),
            "{forbidden:?} must not be an accepted signature algorithm"
        );
    }
}

/// A compact JWS is exactly three segments, and the signed bytes are the transmitted `header.payload`
/// substring rather than a re-encoding of the decoded parts — a re-encoding would verify a token
/// whose base64 differs from what the signer signed.
#[test]
fn split_takes_three_segments_and_signs_over_the_transmitted_bytes() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let token = idp.mint(&good_claims());
    let parts = jwt::split(&token).expect("well-formed token splits");
    assert_eq!(parts.header.alg, "ES256");
    assert_eq!(parts.header.kid.as_deref(), Some("k1"));
    assert_eq!(
        parts.signing_input,
        &token[..token.rfind('.').expect("two dots")]
    );

    for junk in ["a.b", "a.b.c.d", "", "abc"] {
        assert!(jwt::split(junk).is_err(), "{junk:?} is not a compact JWS");
    }
}

/// The alg/key-type guard: an ES256 header must not be verified against an RSA key and vice versa.
/// Without it, `alg` becomes a caller-chosen dispatch into whichever verifier is most convenient.
#[test]
fn an_algorithm_that_does_not_match_the_key_type_is_refused() {
    let ec = TestIdp::ec(ISSUER, "k1");
    let rsa = TestIdp::rsa(ISSUER, "k1");
    let ec_keys = parse_jwks(&ec.jwks());
    let rsa_keys = parse_jwks(&rsa.jwks());

    let ec_token = ec.mint(&good_claims());
    let parts = jwt::split(&ec_token).expect("splits");
    let err = jwt::verify_signature(&parts, &rsa_keys.keys[0]).expect_err("must not verify");
    assert!(err.contains("alg/key-type mismatch"), "{err}");

    let rsa_token = rsa.mint(&good_claims());
    let parts = jwt::split(&rsa_token).expect("splits");
    let err = jwt::verify_signature(&parts, &ec_keys.keys[0]).expect_err("must not verify");
    assert!(err.contains("alg/key-type mismatch"), "{err}");
}

/// RFC 7517 §4.2: a key published as encryption-only must never verify a signature, however valid
/// its material. Checked before the signature math, so a real signature from an `enc` key still
/// fails.
#[test]
fn an_encryption_only_key_never_verifies_a_signature() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let mut set: serde_json::Value =
        serde_json::from_str(&idp.jwks()).expect("fixture JWKS is JSON");
    set["keys"][0]["use"] = serde_json::json!("enc");
    let keys = parse_jwks(&set.to_string());
    let token = idp.mint(&good_claims());
    let parts = jwt::split(&token).expect("splits");
    let err = jwt::verify_signature(&parts, &keys.keys[0]).expect_err("must not verify");
    assert!(err.contains("encryption-only"), "{err}");
}

/// RFC 7515 §4.1.11: an unimplemented critical header parameter is a refusal, and it is checked
/// BEFORE the signature — a valid signature over a token we would then misprocess is worse than no
/// signature at all.
#[test]
fn a_critical_header_parameter_is_refused_before_the_signature_is_checked() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let keys = parse_jwks(&idp.jwks());
    let token = idp.mint_with_header(
        &serde_json::json!({"alg": "ES256", "kid": "k1", "crit": ["b64"]}),
        &good_claims(),
    );
    let parts = jwt::split(&token).expect("splits");
    let err = jwt::verify_signature(&parts, &keys.keys[0]).expect_err("must not verify");
    assert!(err.contains("critical extension"), "{err}");
}

/// The positive control for this file: the fixture's own key verifies the fixture's own token. If
/// this ever fails, every negative test above is passing for the wrong reason.
#[test]
fn the_fixtures_own_key_verifies_its_own_token() {
    for keys_and_token in [
        {
            let idp = TestIdp::ec(ISSUER, "k1");
            (idp.jwks(), idp.mint(&good_claims()))
        },
        {
            let idp = TestIdp::rsa(ISSUER, "k1");
            (idp.jwks(), idp.mint(&good_claims()))
        },
    ] {
        let (jwks, token) = keys_and_token;
        let keys = parse_jwks(&jwks);
        let parts = jwt::split(&token).expect("splits");
        jwt::verify_signature(&parts, &keys.keys[0]).expect("fixture verifies itself");
    }
}
