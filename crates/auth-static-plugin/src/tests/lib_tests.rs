// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/auth-static-plugin/src/lib.rs`.

use super::*;

/// The plugin validates its OWN license: absent is fine (free tier), the well-known demo value
/// loads, and any other present value is a load error — the plugin, not the core, decides.
#[test]
fn plugin_validates_its_own_license() {
    assert!(validate_license(None).is_ok(), "absent license = free tier");
    assert!(
        validate_license(Some(DEMO_VALID_LICENSE)).is_ok(),
        "the delivered valid key loads"
    );
    let err = validate_license(Some("LICENSE-WRONG")).unwrap_err();
    assert!(err.contains("not valid"), "invalid license refuses: {err}");
}

/// `open` delivers the (already-resolved) licenseKey into validation: a valid key loads the
/// module; an invalid one refuses. Proves the plugin reads `licenseKey` from its settings.
#[test]
fn open_reads_and_validates_delivered_license_key() {
    let base =
        |lic: &str| format!(r#"{{ "token": "t", "id": "a", "roles": [], "licenseKey": "{lic}" }}"#);
    assert!(open(&base(DEMO_VALID_LICENSE)).is_ok(), "valid key loads");
    match open(&base("LICENSE-WRONG")) {
        Err(e) => assert!(e.contains("not valid"), "refuses invalid license: {e}"),
        Ok(_) => panic!("an invalid delivered license must refuse load"),
    }
    // No licenseKey at all still loads (unlicensed tier).
    assert!(open(r#"{ "token": "t", "id": "a" }"#).is_ok());
}

/// `authenticate` must compare the caller's credential to configured secret material under a
/// DIGEST (`busbar_api::sha256_hex`), never raw-vs-raw — mirroring `auth-admin-tokens`, the
/// template this plugin follows. A timing leak cannot be asserted directly in a unit test, so
/// this is a STRUCTURAL guard: it constructs the module directly (same-module private-field
/// access) and asserts its stored comparison material is `sha256_hex("sekret")` exactly, a
/// 64-hex-char digest, which a raw-string field could never satisfy.
/// Behaviorally, matching and non-matching credentials of any length still resolve to
/// `Identify`/`Pass` exactly as before — hashing changes nothing observable about the auth
/// outcome, only removes the raw comparison's length oracle.
#[test]
fn credential_is_compared_under_a_digest() {
    let m = StaticModule {
        token_hash: busbar_api::sha256_hex(b"sekret"),
        id: "alice".to_string(),
        roles: vec!["platform".to_string()],
    };

    // Structural: the field literally named `token_hash` holds a 64-hex-char SHA-256 digest of
    // the token, never the raw token string.
    assert_eq!(
        m.token_hash.len(),
        64,
        "must be a hex digest, not raw material"
    );
    assert_eq!(m.token_hash, busbar_api::sha256_hex(b"sekret"));
    assert_ne!(m.token_hash, "sekret", "must never store the raw token");

    // Behavioral: the correct credential still identifies, a wrong one of the SAME length still
    // passes through (never rejects — `StaticModule`'s contract), and a wrong one of DIFFERENT
    // length also still just passes. Hashing is invisible to the outcome.
    assert!(matches!(
        m.authenticate(Some("sekret")),
        AuthOutcome::Identify(_)
    ));
    assert!(matches!(m.authenticate(Some("wrongo")), AuthOutcome::Pass)); // same length (6)
    assert!(matches!(m.authenticate(Some("x")), AuthOutcome::Pass)); // different length
    assert!(matches!(m.authenticate(None), AuthOutcome::Pass));
}
