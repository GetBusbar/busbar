// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/egress_auth/jwt_bearer.rs`.

use super::*;

#[test]
fn pem_to_pkcs8_der_strips_armor_and_decodes() {
    // The function only strips the PEM armor and base64-decodes the body — it does not require a
    // real key, so a known base64 payload round-trips to its bytes.
    let pem = "-----BEGIN PRIVATE KEY-----\nSGVsbG8sIFBLQ1M4\n-----END PRIVATE KEY-----\n";
    assert_eq!(pem_to_pkcs8_der(pem).unwrap(), b"Hello, PKCS8");
}

#[test]
fn pem_to_pkcs8_der_rejects_empty_and_garbage() {
    assert!(pem_to_pkcs8_der("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----").is_err());
    assert!(pem_to_pkcs8_der(
        "-----BEGIN PRIVATE KEY-----\n!!!not base64!!!\n-----END PRIVATE KEY-----"
    )
    .is_err());
}

#[test]
fn b64url_is_url_safe_and_unpadded() {
    // 0xFB 0xFF encodes to "+/8=" in standard base64; url-safe-no-pad must yield "-_8".
    assert_eq!(b64url(&[0xFB, 0xFF]), "-_8");
}

#[test]
fn read_credential_passes_inline_json_through() {
    let json = r#"{"client_email":"x@y.iam.gserviceaccount.com"}"#;
    assert_eq!(read_credential(json).unwrap(), json);
    assert_eq!(read_credential("  {\"a\":1}").unwrap(), "  {\"a\":1}");
}

/// The default (no operator carve-out) SSRF posture used by most tests.
fn deny() -> super::super::MetadataSsrfPolicy<'static> {
    super::super::MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: false,
        blocked_hosts: &[],
    }
}

// The SA JSON's token_uri is the POST target for the signed assertion,
// so it gets the same https + cloud-metadata guards as oauth-client-credentials' token_url.
#[test]
fn validate_token_uri_requires_https_for_public_and_blocks_metadata() {
    assert!(validate_token_uri("https://oauth2.googleapis.com/token", &deny()).is_ok());
    // plaintext http to a public host would expose the assertion on the wire
    assert!(validate_token_uri("http://oauth2.googleapis.com/token", &deny()).is_err());
    // http to a loopback/private endpoint is permitted (a local token endpoint)
    assert!(validate_token_uri("http://127.0.0.1:8080/token", &deny()).is_ok());
    // cloud-metadata / IMDS is denied even over https (SSRF to the direct target)
    assert!(validate_token_uri("https://metadata.google.internal/token", &deny()).is_err());
    assert!(validate_token_uri("https://169.254.169.254/token", &deny()).is_err());
}

// jwt-bearer must honor the operator's DEPLOYMENT-global metadata posture
// symmetrically with oauth-client-credentials — a global `blocked_metadata_hosts` deny is enforced on
// the token_uri, and `allow_all_metadata` / an allow-override unblocks an otherwise-denied host.
#[test]
fn validate_token_uri_honors_operator_metadata_posture() {
    // allow_all disables the guard uniformly (IMDS token_uri now permitted).
    let nuclear = super::super::MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: true,
        blocked_hosts: &[],
    };
    assert!(validate_token_uri("https://169.254.169.254/token", &nuclear).is_ok());
    // An explicit allow-override unblocks just that host.
    let allowed = ["169.254.169.254".to_string()];
    let override_one = super::super::MetadataSsrfPolicy {
        allow_overrides: &allowed,
        allow_all: false,
        blocked_hosts: &[],
    };
    assert!(validate_token_uri("https://169.254.169.254/token", &override_one).is_ok());
    // A global extra-deny is now ENFORCED on the token_uri (was ignored before the fix).
    let extra_block = ["evil.example.com".to_string()];
    let blocked = super::super::MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: false,
        blocked_hosts: &extra_block,
    };
    assert!(validate_token_uri("https://evil.example.com/token", &blocked).is_err());
}

// validate_credential is the config `--validate` dry-run entry point; it
// must catch a malformed SA JSON and an SSRF token_uri without constructing the provider.
#[test]
fn validate_credential_rejects_malformed_json_and_ssrf_token_uri() {
    assert!(validate_credential("not json", &deny()).is_err());
    // Valid JSON, but token_uri targets IMDS → rejected before the key is even parsed.
    let imds = r#"{"client_email":"x@y.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nSGVsbG8=\n-----END PRIVATE KEY-----\n","token_uri":"https://169.254.169.254/token"}"#;
    let e = validate_credential(imds, &deny()).expect_err("IMDS token_uri must be rejected");
    assert!(e.contains("metadata") || e.contains("169.254"), "got: {e}");
}

/// The `scope` threaded from provider config lands VERBATIM in the assertion claims (this is
/// the value `main.rs` now passes through as `scope_override` instead of a hardcoded `None`), and
/// iss/aud/iat/exp are placed correctly.
#[test]
fn jwt_claims_place_scope_and_fields() {
    let json = jwt_claims_json(
        "svc@proj.iam.gserviceaccount.com",
        "https://www.googleapis.com/auth/cloud-platform.read-only",
        "https://oauth2.googleapis.com/token",
        1000,
        4600,
        None,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v["scope"], "https://www.googleapis.com/auth/cloud-platform.read-only",
        "the configured scope must appear verbatim in the claims"
    );
    assert_eq!(v["iss"], "svc@proj.iam.gserviceaccount.com");
    assert_eq!(v["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(v["iat"], 1000);
    assert_eq!(v["exp"], 4600);
}

/// RFC 7523 §3: with `subject` UNSET (the default — every existing Vertex AI config, which never
/// sets it), the claim set must contain NO `sub` key at all. This is the regression guard:
/// unconditionally setting `sub = iss` would break every plain (non-delegated) service account,
/// because Google service-account OAuth treats the mere PRESENCE of `sub` as a
/// domain-wide-delegation/impersonation switch, regardless of value.
#[test]
fn jwt_claims_omit_sub_when_subject_unset() {
    let json = jwt_claims_json(
        "svc@proj.iam.gserviceaccount.com",
        DEFAULT_SCOPE,
        "https://oauth2.googleapis.com/token",
        1000,
        4600,
        None,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        v.as_object().unwrap().get("sub").is_none(),
        "no `sub` key must be present when subject is unset: {v}"
    );
    assert_eq!(
        v.as_object().unwrap().len(),
        5,
        "exactly iss/scope/aud/iat/exp — no sub — when subject is unset: {v}"
    );
}

/// RFC 7523 §3: with `subject` explicitly configured, the claim set MUST contain `sub` set to that
/// exact value — the opt-in RFC-7523-conformant / Google-delegation-correct path.
#[test]
fn jwt_claims_include_sub_with_exact_value_when_subject_set() {
    let json = jwt_claims_json(
        "svc@proj.iam.gserviceaccount.com",
        DEFAULT_SCOPE,
        "https://oauth2.googleapis.com/token",
        1000,
        4600,
        Some("impersonated-user@example.com"),
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["sub"], "impersonated-user@example.com");
}

/// A quote/backslash/control char in an operator-controlled claim value is ESCAPED, not
/// spliced — the claims are always valid JSON and the value round-trips exactly. This is what the
/// serde serializer buys over string interpolation (which would emit malformed JSON / inject).
#[test]
fn jwt_claims_escape_hostile_values() {
    let nasty = "a\"b\\c\nd\tsneaky\":\"injected";
    let json = jwt_claims_json(nasty, nasty, "aud", 1, 2, None).unwrap();
    // Parses as valid JSON (string interpolation would have produced a parse error here)...
    let v: serde_json::Value = serde_json::from_str(&json).expect("claims must be valid JSON");
    // ...and the value round-trips exactly, with no injected keys.
    assert_eq!(v["iss"], nasty);
    assert_eq!(v["scope"], nasty);
    assert_eq!(
        v.as_object().unwrap().len(),
        5,
        "exactly iss/scope/aud/iat/exp — no injected claim: {v}"
    );
}

/// A test-only 2048-bit PKCS#8 RSA private key (generated for this test suite only; not used
/// anywhere else and grants no real access) so [`Signer::mint`] can actually sign an assertion
/// and exercise the real HTTP exchange against a mock token endpoint.
const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu2RTBghXyuvqd\n\
v/4AIq1NcPzdRUCr0wyjEH35avOM9vSW+fuira0UtCQcyTHJZswoJqgwcdO2SRav\n\
/QMZhnjB/sCzuvHrbILd/T0nK19Fdld/wKMQlQlqz94OpS5b0J/nEc7/IOTxszbq\n\
4B2geG7lJc5wm3dMjKwr7IPbnWs5fMEVyZFaFsctrejOTURx8duff8eM2L+Lf5No\n\
H2k0h+6blyDTq1Iu+9UM5/AfycgvdhPlcKCL1VZq9+YY5zW5GuXj997TnEWEeiam\n\
ZfaHklhdSX3zzSUkShqayzaxX6YRdlUvE6yEIkjq/AVRVrMZDynyD7J0nsyjykhx\n\
WVh79c5fAgMBAAECggEALHaz2onUPwfhl6AtXadz3s+u3i4wRgHDouwcvQK/sMdU\n\
Z9hmb3YvH6a30EIx0P+9RzCdcMRhjGeFx3dWBHW3282G/624u5+6n+04Ue+rqKRx\n\
l+FLFnpwDKOT2rGS2nJxV3el5iddUUG743rezeISgV9d4jEG44aaegkJdx3PGKz/\n\
E76BIyi9H4oUgiqIyPW2trPEeg5n/1oVMHLGDBhotuM7VPUCegh/J3e1jSxcYvi8\n\
0CutgOLynZAS1xSatbbp8nWrUSRHOUYrgE9OYbS7TSgGz1PjzdcmLEsHEGcor0wm\n\
cT4oePDjZmuxICFBSg96Ffb82t6UGXC7xLQbglsfQQKBgQDlBOBtVQafWVJiEj83\n\
fG2YfKTMx1neGO/6ftBMn7XUt4D/AbL0Kx0/Z5lfxm2cixlxcGWT6e96CmZmEsyA\n\
RFSyuG/bvbTF1c0vaKXcjghtPH5TaB6MjgP3VmjOHR5V5o3JMQX0Xayxf/kBP//f\n\
wfolsPUM5hcB7pMjVDQz0OZacQKBgQDDcm0i42UA1wrh4XUTNAbVHfacTm/zBhVB\n\
zvtEC3WGkBCRdU9JSwFAJitPmxrVS3+w2fxO47IiSngeQEyC2neew/H5FrWSNs+L\n\
xV9Jystubq6oTCulEGBP4gb99FkDY2RToNYOjVrEQDsmiijv3CeZyHnes0/8uMQq\n\
5ekEveH9zwKBgBZvR9zt+1wYz+0zhGXXFpVdgHde//q1zqxnR9h5vMI9x7EzZWht\n\
4MuZRnkPYyV2quNl801uGTuHUUimhsn556IqVyrbhp3qt9LxGW5lq4Wn62gYRwXV\n\
06WjHVkzmQkpMLKIzuCFXKl2s9nffx1YTzzp/Ndqos5ZpKhNU1/QEwDBAoGAfVvA\n\
WldFqmNDbJwCTp3ZIAqG6bx5m4O0ULBkg0FiUTvIFLQMdbMxCycwMnAGpvY04Yb/\n\
iM4MrGfdYXHWYTuk6+U8J4sETNLxDfI7awYysxM03Wd1uvqk+7e6ylpWWZD/gZAw\n\
m8bYh/W2usJ0/VvU3pMyb7/NNwh/chBjBBKSiAsCgYEAsTCMDD6CYdncyFWMtWpK\n\
vaTrTko3xPDigybk5520jK5UkEaZr0meRn1CFYFAnfUs0sKB4EbWkcmkZOayPPtQ\n\
su3l06s8o+WrP8Bp2GikIg+jVz9sdz9Vph0Vr0VOPwdBKbWUT4As0r6Muceq+sH6\n\
oy3z0wnL4GXkIelYmU1zCk0=\n\
-----END PRIVATE KEY-----\n";

fn test_signer(token_uri: String) -> Signer {
    let der = pem_to_pkcs8_der(TEST_PRIVATE_KEY_PEM).expect("test key parses");
    let key_pair =
        ring::signature::RsaKeyPair::from_pkcs8(&der).expect("test key is valid PKCS#8 RSA");
    Signer {
        key_pair,
        rng: ring::rand::SystemRandom::new(),
        issuer: "svc@proj.iam.gserviceaccount.com".to_string(),
        token_uri,
        scope: DEFAULT_SCOPE.to_string(),
        subject: None,
        http: super::super::minter_client().unwrap(),
    }
}

/// The token endpoint is an untrusted network peer (its `expires_in` is already treated as
/// attacker-influenced in `mint`), so `mint()` must read the response body under a size cap
/// rather than `resp.text()`'s unbounded read: a hijacked/misbehaving token endpoint returning a
/// body past the `upstream_error_body_max_bytes()` cap must surface a clear error, never
/// silently buffer the whole thing or attempt a partial JSON parse of a truncated fragment.
#[tokio::test]
async fn mint_rejects_a_response_body_over_the_cap() {
    let state = std::sync::Arc::new(crate::test_support::MockServerState::new());
    let oversized_token = "a".repeat(300 * 1024);
    state.push(crate::test_support::MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({ "access_token": oversized_token, "expires_in": 3600 }),
    });
    let server = crate::test_support::MockServer::new(state).await;

    let signer = test_signer(server.base_url());
    let result = signer.mint().await;
    server.shutdown().await;

    let err = match result {
        Ok(_) => {
            panic!("an over-cap token response must be a clear error, not a buffered success")
        }
        Err(e) => e,
    };
    assert!(
        err.contains("cap") || err.contains("truncat"),
        "expected an error naming the size cap / truncation, got: {err}"
    );
}
