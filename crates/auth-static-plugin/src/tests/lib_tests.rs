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
    // The LITERAL digest, not `sha256_hex(b"sekret")` again. `token_hash` was assigned from that
    // exact call twelve lines up, so comparing it back to the same expression could not fail for
    // any implementation of `sha256_hex` -- including one that returned a constant. Spelled out,
    // this pins that the field holds the digest of the token and not of something else.
    assert_eq!(
        m.token_hash,
        "bb757689c39373a6cac9ef6ba55616c6249d7500ca4d443f1130c4766453a412"
    );
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

/// THE MODULE'S RUNTIME NAME IS PART OF ITS CONTRACT, not an incidental string.
/// `role_bindings.<module>` and `auth.modules.<module>` key off it, so `name()` returning `""` or
/// any other literal breaks policy wiring while every auth OUTCOME stays exactly what it was —
/// which is why no behaviour-only test in this file can observe it, and why this one asserts the
/// name itself.
#[test]
fn module_name_is_static_auth() {
    let m = StaticModule {
        token_hash: busbar_api::sha256_hex(b"sekret"),
        id: "alice".to_string(),
        roles: vec![],
    };
    assert_eq!(m.name(), "static-auth");
}

/// THE REFUSAL IS `||`, AND ONLY A HALF-EMPTY CONFIG CAN TELL. `c.token.is_empty() ||
/// c.id.is_empty()` and the same expression with `&&` agree on both-present and on both-empty, so
/// the crate's other cases cannot distinguish them. With `&&`, a config carrying an empty `token`
/// and a non-empty `id` (or the reverse) would LOAD instead of being refused.
#[test]
fn open_refuses_when_only_one_of_token_or_id_is_empty() {
    match open(r#"{"token":"","id":"alice"}"#) {
        Err(e) => assert!(e.contains("non-empty"), "empty token must refuse: {e}"),
        Ok(_) => panic!("empty token with a non-empty id must refuse to load"),
    }
    match open(r#"{"token":"sekret","id":""}"#) {
        Err(e) => assert!(e.contains("non-empty"), "empty id must refuse: {e}"),
        Ok(_) => panic!("empty id with a non-empty token must refuse to load"),
    }
}

/// The check above builds `StaticModule` by hand, which means it proves the COMPARISON is done under
/// a digest without ever proving `open` puts a digest there. Nothing in this file connected the
/// config the engine passes to the outcome the chain sees, so a build that stored the raw token in
/// `token_hash` still went green here — and then failed for real, because the candidate is hashed
/// before the compare and a raw configured token can never equal a digest. Same seam the engine
/// drives: config in, outcome out.
#[test]
fn a_module_opened_from_config_identifies_its_configured_token() {
    let m = open(r#"{"token":"sekret","id":"alice"}"#).expect("a well-formed config loads");
    match m.authenticate(Some("sekret")) {
        AuthOutcome::Identify(p) => assert_eq!(p.id, "alice"),
        other => panic!("the configured token must identify as the configured id, got {other:?}"),
    }
    assert!(
        matches!(m.authenticate(Some("nope")), AuthOutcome::Pass),
        "a wrong credential defers to the next module in the chain, never rejects"
    );
}
