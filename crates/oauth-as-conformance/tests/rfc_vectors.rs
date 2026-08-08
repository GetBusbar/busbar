//! Hermetic RFC test-vector suite. No network, no AS required: this half proves the harness's
//! own checkers against the PUBLISHED vectors, so a green from the black-box half means
//! something. Every expected value comes from `vectors/rfc_vectors.json`, vendored verbatim
//! from the RFC Editor text and citing its appendix.
//!
//! RED-proof knob: setting `OAUTH_CONFORMANCE_SELFTEST_BREAK=pkce` corrupts the expected PKCE
//! challenge so this suite MUST fail; `scripts/oauth-conformance.sh --selftest` uses it to
//! prove the gate can go red before anyone trusts a green.

use hmac::{Hmac, Mac as _};
use oauth_as_conformance as conf;
use serde_json::{json, Value};
use sha2::Sha256;

fn octets(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("vector octet field must be an array")
        .iter()
        .map(|n| u8::try_from(n.as_u64().expect("octet")).expect("octet fits u8"))
        .collect()
}

/// RFC 7636 Appendix B: verifier octets -> code_verifier -> S256 -> code_challenge.
#[test]
fn pkce_s256_rfc7636_appendix_b() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["pkce_s256"];
    let verifier_octets = octets(&v["verifier_octets"]);
    let verifier = v["code_verifier"].as_str().unwrap();
    let mut challenge = v["code_challenge"].as_str().unwrap().to_string();
    if std::env::var("OAUTH_CONFORMANCE_SELFTEST_BREAK").as_deref() == Ok("pkce") {
        // Deliberate corruption used by --selftest to prove this suite can fail.
        challenge = format!("BROKEN{challenge}");
    }
    assert_eq!(
        conf::b64url(&verifier_octets),
        verifier,
        "RFC 7636 App B: base64url(verifier octets) must equal the published code_verifier"
    );
    assert_eq!(
        conf::pkce_s256_challenge(verifier),
        challenge,
        "RFC 7636 App B: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) must equal the \
         published code_challenge"
    );
    let challenge_octets = octets(&v["challenge_octets"]);
    assert_eq!(
        conf::b64url(&challenge_octets),
        v["code_challenge"].as_str().unwrap(),
        "RFC 7636 App B: the published SHA-256 octets must base64url-encode to the challenge"
    );
}

/// RFC 7515 Appendix A.1: HMAC-SHA256 JWS, byte-exact recompute and verify.
#[test]
fn jws_rfc7515_a1_hs256() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["jws_a1_hs256"];
    let header_octets = octets(&v["header_octets"]);
    let payload_octets = octets(&v["payload_octets"]);
    let header_b64 = v["header_b64"].as_str().unwrap();
    let payload_b64 = v["payload_b64"].as_str().unwrap();
    assert_eq!(
        conf::b64url(&header_octets),
        header_b64,
        "RFC 7515 A.1 header encoding"
    );
    assert_eq!(
        conf::b64url(&payload_octets),
        payload_b64,
        "RFC 7515 A.1 payload encoding"
    );

    let key = conf::b64url_decode(v["jwk_k"].as_str().unwrap()).unwrap();
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    assert_eq!(
        conf::b64url(&sig),
        v["signature_b64"].as_str().unwrap(),
        "RFC 7515 A.1: HMAC-SHA256(signing input) must equal the published JWS signature"
    );
    assert_eq!(sig.as_slice(), octets(&v["signature_octets"]).as_slice());
}

/// RFC 7515 Appendix A.2: RS256 JWS verified with the published RSA public key (n, e).
#[test]
fn jws_rfc7515_a2_rs256_verifies() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["jws_a2_rs256"];
    let token = format!(
        "{}.{}.{}",
        v["header_b64"].as_str().unwrap(),
        v["payload_b64"].as_str().unwrap(),
        v["signature_b64"].as_str().unwrap()
    );
    let jwks = json!({ "keys": [{ "kty": "RSA", "n": v["jwk_n"], "e": v["jwk_e"] }] });
    conf::verify_jwt_against_jwks(&token, &jwks)
        .expect("RFC 7515 A.2: published RS256 signature must verify with the published key");

    // Negative control: flipping the last signature character must fail verification.
    let mut broken = token.clone();
    let last = broken.pop().unwrap();
    broken.push(if last == 'w' { 'x' } else { 'w' });
    assert!(
        conf::verify_jwt_against_jwks(&broken, &jwks).is_err(),
        "a corrupted RS256 signature must NOT verify; if it does the verifier is broken"
    );
}

/// RFC 7515 Appendix A.3: ES256 JWS verified with the published EC public key (x, y).
#[test]
fn jws_rfc7515_a3_es256_verifies() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["jws_a3_es256"];
    let token = format!(
        "{}.{}.{}",
        v["header_b64"].as_str().unwrap(),
        v["payload_b64"].as_str().unwrap(),
        v["signature_b64"].as_str().unwrap()
    );
    let jwks = json!({
        "keys": [{ "kty": "EC", "crv": "P-256", "x": v["jwk_x"], "y": v["jwk_y"] }]
    });
    conf::verify_jwt_against_jwks(&token, &jwks)
        .expect("RFC 7515 A.3: published ES256 signature must verify with the published key");
}

/// RFC 9068 s2.1/s2.2: the validator must accept a conforming token and must name every
/// missing required claim. An AS validator that never rejects anything is worthless.
#[test]
fn rfc9068_validator_accepts_conforming_and_rejects_each_missing_claim() {
    let vecs = conf::rfc_vectors();
    let required: Vec<String> = vecs["rfc9068"]["required_claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();

    let header = json!({ "typ": "at+jwt", "alg": "RS256", "kid": "k1" });
    let claims = json!({
        "iss": "https://as.example",
        "exp": 1_900_000_000u64,
        "aud": "https://rs.example",
        "sub": "user-1",
        "client_id": "client-1",
        "iat": 1_800_000_000u64,
        "jti": "id-1"
    });
    let tok = |h: &Value, c: &Value| {
        format!(
            "{}.{}.{}",
            conf::b64url(h.to_string().as_bytes()),
            conf::b64url(c.to_string().as_bytes()),
            conf::b64url(b"sig")
        )
    };
    assert!(
        conf::validate_rfc9068_access_token(&tok(&header, &claims)).is_empty(),
        "validator must accept a token carrying every RFC 9068 s2.2 required claim"
    );

    for missing in &required {
        let mut c = claims.clone();
        c.as_object_mut().unwrap().remove(missing);
        let violations = conf::validate_rfc9068_access_token(&tok(&header, &c));
        assert!(
            violations.iter().any(|m| m.contains(missing.as_str())),
            "dropping required claim \"{missing}\" must be reported; got {violations:?}"
        );
    }

    // typ header wrong (RFC 9068 s2.1) and alg none must both be rejected.
    let bad_typ = json!({ "typ": "JWT", "alg": "RS256" });
    assert!(!conf::validate_rfc9068_access_token(&tok(&bad_typ, &claims)).is_empty());
    let alg_none = json!({ "typ": "at+jwt", "alg": "none" });
    assert!(!conf::validate_rfc9068_access_token(&tok(&alg_none, &claims)).is_empty());
}

/// RFC 8414 s2: metadata validator accepts a conforming document, rejects a broken one, and
/// enforces issuer match (s3.3).
#[test]
fn rfc8414_metadata_validator() {
    let good = json!({
        "issuer": "http://127.0.0.1:8914",
        "authorization_endpoint": "http://127.0.0.1:8914/authorize",
        "token_endpoint": "http://127.0.0.1:8914/token",
        "device_authorization_endpoint": "http://127.0.0.1:8914/device_authorization",
        "jwks_uri": "http://127.0.0.1:8914/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "code_challenge_methods_supported": ["S256"]
    });
    assert!(
        conf::validate_as_metadata(&good, "http://127.0.0.1:8914").is_empty(),
        "validator must accept a document with every RFC 8414 required field"
    );

    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "response_types_supported",
        "code_challenge_methods_supported",
    ] {
        let mut broken = good.clone();
        broken.as_object_mut().unwrap().remove(field);
        assert!(
            !conf::validate_as_metadata(&broken, "http://127.0.0.1:8914").is_empty(),
            "removing \"{field}\" must be reported (RFC 8414 s2 / RFC 8628 s4)"
        );
    }
    assert!(
        !conf::validate_as_metadata(&good, "http://other.example").is_empty(),
        "issuer mismatch with the retrieval URL must be reported (RFC 8414 s3.3)"
    );
}

/// RFC 6749 s5.2 / RFC 8628 s3.5: error-shape validator accepts each legal device error and
/// rejects wrong shapes.
#[test]
fn error_shape_validator() {
    for code in [
        "authorization_pending",
        "slow_down",
        "expired_token",
        "access_denied",
    ] {
        assert!(
            conf::validate_error_body(&json!({ "error": code })).is_empty(),
            "RFC 8628 s3.5 error code \"{code}\" must be accepted"
        );
    }
    assert!(!conf::validate_error_body(&json!({ "error": "not_a_registered_code" })).is_empty());
    assert!(!conf::validate_error_body(&json!({ "message": "nope" })).is_empty());
    assert!(!conf::validate_error_body(&json!({ "error": 42 })).is_empty());
    assert!(!conf::validate_error_body(&json!("just a string")).is_empty());
    assert!(!conf::validate_error_body(
        &json!({ "error": "invalid_request", "error_description": "smart \u{201c}quotes\u{201d}" })
    )
    .is_empty());
}

/// RFC 6749 s5.1: token-response validator accepts the RFC shape and rejects broken ones.
#[test]
fn token_response_shape_validator() {
    let good = json!({
        "access_token": "abc",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "def",
        "scope": "read"
    });
    assert!(conf::validate_token_response(&good).is_empty());
    assert!(!conf::validate_token_response(&json!({ "token_type": "Bearer" })).is_empty());
    assert!(!conf::validate_token_response(&json!({ "access_token": "x" })).is_empty());
    assert!(!conf::validate_token_response(
        &json!({ "access_token": "x", "token_type": "Bearer", "expires_in": "3600" })
    )
    .is_empty());
    assert!(
        !conf::validate_token_response(&json!({ "access_token": "x", "token_type": "mac" }))
            .is_empty()
    );
}

/// RFC 8628 s3.2: device-authorization-response validator.
#[test]
fn device_authorization_response_shape_validator() {
    let good = json!({
        "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://example.com/device",
        "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
        "expires_in": 1800,
        "interval": 5
    });
    assert!(conf::validate_device_authorization_response(&good).is_empty());
    for field in ["device_code", "user_code", "verification_uri", "expires_in"] {
        let mut broken = good.clone();
        broken.as_object_mut().unwrap().remove(field);
        assert!(
            !conf::validate_device_authorization_response(&broken).is_empty(),
            "removing \"{field}\" must be reported (RFC 8628 s3.2)"
        );
    }
}
