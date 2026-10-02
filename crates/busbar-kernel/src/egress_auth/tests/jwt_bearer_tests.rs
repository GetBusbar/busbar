// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/egress_auth/jwt_bearer.rs`.

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

/// THE SIGNING KEY MUST NOT REACH THE ERROR TEXT.
///
/// The ONLY thing that tells the two credential forms apart is a leading `{`, so an operator who
/// pasted the service-account key body — or a secret ref (`env:`/`file:`) that resolved to key
/// material rather than to a filename — reaches the `fs::read_to_string` arm with the whole signing
/// key in hand. That error is not swallowed: it reaches `--validate`'s printed report (via
/// `config_validate`'s `errors` list) and the boot/apply `panic!` in the llm engine's runtime build,
/// so interpolating the argument published an RSA private key to a terminal, a CI log and a crash
/// report.
///
/// The key here is a planted marker and its ABSENCE is what is asserted — the test never prints a
/// real key to fail informatively. `not-a-real-key-b4d7e2` is unique in this file, so a regression
/// that reinstates `'{credential}'` fails on the very first assertion.
#[test]
fn read_credential_never_echoes_the_key_material_it_could_not_read() {
    const PASTED_KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-b4d7e2\n-----END PRIVATE KEY-----\n";

    let e = read_credential(PASTED_KEY)
        .expect_err("key material is not a readable path, so this must fail");
    assert!(
        !e.contains("not-a-real-key-b4d7e2"),
        "the credential must never be interpolated into this error, got: {e}"
    );
    assert!(
        !e.contains("BEGIN PRIVATE KEY"),
        "not even the armor — it names the argument as key material, got: {e}"
    );
    // What the operator IS owed still arrives: which read failed, and why. The lane and the
    // secret's configured source are named by the caller (`config_validate` prints
    // "provider '<name>' jwt-bearer credential (from <source>) is invalid: <this>"), so this layer
    // owes the io failure and nothing else.
    assert!(
        e.contains("could not read service-account key file"),
        "the io failure must still be reported, got: {e}"
    );

    // AND THROUGH THE ENTRY POINT THAT ACTUALLY RUNS ON THE `--validate` PATH, so the assertion is
    // anchored to the reachable call and not only to the private helper underneath it.
    let e = validate_credential(PASTED_KEY, &deny())
        .expect_err("pasted key material is not a readable path");
    assert!(
        !e.contains("not-a-real-key-b4d7e2"),
        "the --validate report must not carry the key either, got: {e}"
    );
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
    // Serve a single oversized token response on a real loopback socket through substrate's own
    // egress fixture (the App-saturated busbar-core `MockServer` is not reachable from here). A
    // 300 KiB body overruns the 256 KiB default cap, so the shared capped read must trip.
    let oversized_token = "a".repeat(300 * 1024);
    let body =
        serde_json::json!({ "access_token": oversized_token, "expires_in": 3600 }).to_string();
    let server =
        crate::egress::fixtures::spawn_http(crate::egress::fixtures::CannedResponse::ok(&body), 1);

    let signer = test_signer(format!("http://{}", server.addr));
    let result = signer.mint().await;

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

/// THE PRIVATE KEY'S OWN BYTES MUST NOT REACH THE `config/validate` RESPONSE.
///
/// This is a PRIVILEGE BOUNDARY, not log hygiene. `validate_credential` is the config `--validate`
/// dry-run entry point, and `config_validate` puts whatever it returns in the `errors` list that
/// the admin `config/validate` endpoint RETURNS TO ITS CALLER. A read-scope admin is allowed to ask
/// whether the configuration is valid; they are not allowed to be told what the service account's
/// RSA key contains. `base64::DecodeError` answers the second question: its `Display` renders the
/// offending byte AND its offset, and for `InvalidLastSymbol` that byte is a symbol OF THE KEY BODY
/// — a base64 character carrying six bits of the key — not some foreign character that got mixed in.
///
/// Both leaking variants are driven, because they render differently — and the spelling matters,
/// because an earlier cut of this test asserted on a DECIMAL byte value for both and so could only
/// ever have caught one of them:
///   * `Az==` is canonically-padded, and its final symbol's discarded bits are non-zero, so base64
///     reports `InvalidLastSymbol { offset: 1, symbol: b'z', .. }` — whose `Display` prints the
///     symbol as HEX **and as the character itself** (`Invalid last symbol 0x7a ('z') at offset 1,
///     decoded as 0b00110011.`). `z` is a REAL character of the key body, printed verbatim, plus
///     its exact offset and its decoded bits. (The unpadded `Az` this case used to carry never
///     reached that variant at all: `STANDARD` requires canonical padding, so it failed earlier
///     with a length/padding error that names no key byte — the case passed while leaking nothing,
///     which is a test that proves nothing.)
///   * `AAAA~AAA` carries a character outside the alphabet, so base64 reports
///     `InvalidByte(4, 126)`, whose `Display` prints the DECIMAL byte value and the position
///     within the key body (`Invalid symbol 126, offset 4.`).
///
/// The markers are planted and their ABSENCE is what is asserted; the test never prints a real key
/// to fail informatively.
#[test]
fn validate_never_echoes_a_byte_of_the_service_account_key() {
    // (armored body, the exact fragment of it base64's Display would have named, what that is)
    let cases = [
        ("Az==", "'z'", "the final symbol of the key body itself"),
        (
            "AAAA~AAA",
            "126",
            "a byte at a named offset inside the key body",
        ),
    ];
    for (body, leaked_byte, what) in cases {
        let sa = serde_json::json!({
            "client_email": "svc@proj.iam.gserviceaccount.com",
            "private_key": format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string();

        // THE LIVE PATH: the same entry point `config_validate` calls, whose `Err` string is
        // copied verbatim into the `errors` array of the `config/validate` response.
        let e = validate_credential(&sa, &deny())
            .expect_err("a private_key that is not base64 must be refused");
        assert!(
            !e.contains(leaked_byte),
            "the response must not carry {what} ({leaked_byte}), got: {e}"
        );
        assert!(
            !e.contains("Invalid symbol") && !e.contains("Invalid last symbol"),
            "the base64 crate's byte-naming Display must not be interpolated, got: {e}"
        );
        // What the caller IS owed still arrives: WHICH field failed and THAT it failed to decode,
        // so a malformed key is still distinguishable from a missing one.
        assert!(
            e.contains("private_key") && e.contains("base64"),
            "the failing field and the failure must still be named, got: {e}"
        );
    }

    // The private helper underneath it, same discipline, so a future caller that reaches
    // `pem_to_pkcs8_der` by another route inherits the redaction rather than re-introducing it.
    let e = pem_to_pkcs8_der("-----BEGIN PRIVATE KEY-----\nAz\n-----END PRIVATE KEY-----\n")
        .expect_err("`Az` is not decodable base64");
    assert!(
        !e.contains("122"),
        "the helper must not name a byte of the key either, got: {e}"
    );
}
