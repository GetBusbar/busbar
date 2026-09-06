// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/auth-admin-tokens/src/lib.rs`.

use super::*;

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

#[test]
fn no_configured_token_passes() {
    assert_eq!(
        authenticate_admin_tokens(None, Some("x"), None),
        AuthOutcome::Pass
    );
}

#[test]
fn no_credential_passes() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, None),
        AuthOutcome::Pass
    );
}

#[test]
fn either_carrier_identifies() {
    let h = hash("secret");
    for (b, hd) in [
        (Some("secret"), None),
        (None, Some("secret")),
        (Some("secret"), Some("wrong")),
        (Some("wrong"), Some("secret")),
    ] {
        match authenticate_admin_tokens(Some(&h), b, hd) {
            AuthOutcome::Identify(p) => assert_eq!(p.id, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}

#[test]
fn wrong_credential_rejects() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("nope"), None),
        AuthOutcome::Reject
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, Some("nope")),
        AuthOutcome::Reject
    );
}

/// THE THIRD ANSWER. A credential carrying another issuer's minted form (a JWS compact
/// serialization — what an OIDC/AD arm is handed) is not this module's to refuse: it PASSES so the
/// next arm is asked, on either carrier. Before this, any non-matching credential was a terminal
/// Reject and a second `admin_auth:` arm could never be reached.
#[test]
fn foreign_credential_form_passes() {
    let h = hash("secret");
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some(jwt), None),
        AuthOutcome::Pass
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, Some(jwt)),
        AuthOutcome::Pass
    );
}

/// The Pass is FAIL-CLOSED in its direction: only a credential positively attributable elsewhere
/// defers. Anything the grammar cannot claim for another issuer stays MINE and stays a terminal
/// Reject — including near-misses of the compact serialization (too few or too many segments, an
/// empty segment, a byte outside the base64url alphabet) and a carrier pair where only one side
/// is foreign.
#[test]
fn unattributable_credential_still_rejects() {
    let h = hash("secret");
    for candidate in [
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9", // two segments
        "a.b.c.d",                                   // four segments
        "a..c",                                      // empty middle segment
        "a.b+c.d",                                   // '+' is base64, not base64url
        "a.b.c=",                                    // JWS forbids padding
        "shadow-oracle-admin",                       // an ordinary opaque operator secret
    ] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(candidate), None),
            AuthOutcome::Reject,
            "{candidate:?} is not attributable to another issuer; it must stay a terminal Reject"
        );
    }
    // One foreign carrier does not excuse the other: the presentation as a whole is still mine.
    assert_eq!(
        authenticate_admin_tokens(
            Some(&h),
            Some("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"),
            Some("nope")
        ),
        AuthOutcome::Reject
    );
}

/// Validation runs BEFORE the form test, so an operator who chose a JWT-shaped admin secret still
/// identifies. No shape rule can turn a valid operator credential away.
#[test]
fn valid_credential_identifies_even_in_a_foreign_form() {
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    let h = hash(jwt);
    match authenticate_admin_tokens(Some(&h), Some(jwt), None) {
        AuthOutcome::Identify(p) => assert_eq!(p.id, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("expected Identify, got {other:?}"),
    }
}
