// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `mint/jwt_bearer.rs`, ported from the kernel's `egress_auth/tests/jwt_bearer_tests.rs`.
//! The `token_uri` https/metadata vetting tests stay with the kernel (ARCHITECT ruling Q2 (a)).

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
/// `config_validate`'s `errors` list) and the boot/apply `panic!` in a plane's runtime build,
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
    let e = build(PASTED_KEY, None, None)
        .err()
        .expect("pasted key material is not a readable path");
    assert!(
        !e.contains("not-a-real-key-b4d7e2"),
        "the --validate report must not carry the key either, got: {e}"
    );
}

/// A service-account JSON that does not parse is refused before any key is read.
#[test]
fn build_rejects_malformed_json() {
    let e = build("{not json", None, None)
        .err()
        .expect("malformed JSON");
    assert!(e.starts_with("service-account JSON is invalid: "), "{e}");
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
/// and exercise the exchange against a scripted token endpoint.
const TEST_PRIVATE_KEY_PEM: &str = include_str!("fixtures/test_sa_key.pem");

pub(crate) fn test_signer(token_uri: &str, subject: Option<&str>) -> Signer {
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": TEST_PRIVATE_KEY_PEM,
        "token_uri": token_uri,
    })
    .to_string();
    build(&sa, None, subject).expect("the test service account builds")
}

/// THE RFC 7523 ASSERTION, BYTE-IDENTICAL TO 1.5.5's (BUSBAR-1.6.0.md THE DESIGN, §6's proof). RS256 over PKCS#1
/// v1.5 is deterministic, so for a fixed key, issuer, scope, audience and `iat` the assertion is one
/// string. The golden was produced by 1.5.5's own `mint` code (`v1.5.5:crates/busbar/src/egress_auth/
/// jwt_bearer.rs`: the header, `jwt_claims_json`, `b64url` and the `RSA_PKCS1_SHA256` signature,
/// extracted verbatim into a scratch program and run over this key at `iat` 1_700_000_000).
#[test]
fn the_rfc_7523_assertion_is_byte_identical_to_1_5_5() {
    let signer = test_signer("https://oauth2.googleapis.com/token", None);
    assert_eq!(
        signer.assertion(1_700_000_000).unwrap(),
        include_str!("fixtures/jwt_assertion_1_5_5.txt").trim_end()
    );
}

/// The token request for that assertion: a form POST to the SA's `token_uri`, the grant type and
/// the assertion encoded by `serde_urlencoded` as reqwest's `.form()` did.
#[test]
fn the_token_request_is_the_form_1_5_5_posted() {
    let signer = test_signer("https://oauth2.googleapis.com/token", None);
    let req = signer.request(1_700_000_000).unwrap();
    assert_eq!(req.target, "https://oauth2.googleapis.com/token");
    assert_eq!(
        req.fields,
        vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "*/*"),
        ]
    );
    let assertion = signer.assertion(1_700_000_000).unwrap();
    assert_eq!(
        req.body.expose_secret(),
        &format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        )
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
        let e = build(&sa, None, None)
            .err()
            .expect("a private_key that is not base64 must be refused");
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
