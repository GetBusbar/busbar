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

// ── THE CHAIN HAS TO COMPOSE ──────────────────────────────────────────────────────────────────
//
// `Reject` is TERMINAL in the admin chain: the first module that returns one denies the request
// and no later arm runs. This module's grammar is an OPAQUE token compared by hash — it does not
// parse structured tokens — so a JWS/JWT-shaped candidate was never addressed to it. Rejecting one
// denied a credential meant for a later `admin_auth:` arm (an OIDC/AD module sharing the
// `Authorization: Bearer` carrier) before that arm was ever asked. It must DEFER instead.

#[test]
fn a_jws_shaped_candidate_defers_to_the_next_chain_arm() {
    let h = hash("secret");
    // Three dot-separated non-empty segments: the compact JWS serialization every OIDC/AD admin
    // module speaks. Presented on either carrier, on both, and mixed with an absent one.
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln";
    for (b, hd) in [(Some(jws), None), (None, Some(jws)), (Some(jws), Some(jws))] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), b, hd),
            AuthOutcome::Pass,
            "a JWS-shaped candidate is another scheme's grammar and must reach the next arm \
             ({b:?}, {hd:?})"
        );
    }
}

#[test]
fn a_non_jws_wrong_credential_still_terminally_rejects() {
    let h = hash("secret");
    // Shapes that are NOT a compact JWS: no dots, too few segments, too many, and an empty
    // segment. Each is a genuine wrong-credential attempt against THIS module's grammar, and the
    // door stays shut on it.
    for candidate in ["nope", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b."] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(candidate), None),
            AuthOutcome::Reject,
            "`{candidate}` is addressed to this module and wrong; it must deny, not defer"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(candidate)),
            AuthOutcome::Reject,
            "`{candidate}` on the header carrier must deny too"
        );
    }
}

#[test]
fn deferring_never_admits_and_never_widens_the_door() {
    let h = hash("secret");
    // The deferral is a PASS, never an Identify: this module admits exactly one thing, the
    // configured token, and a shape check may not become a second way in.
    let jws = "aaa.bbb.ccc";
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some(jws), None),
        AuthOutcome::Pass
    );
    // And the real token is still recognised on either carrier even when the OTHER carries a JWS
    // meant for a later arm — the both-carriers fold is untouched by the shape check.
    for (b, hd) in [(Some("secret"), Some(jws)), (Some(jws), Some("secret"))] {
        match authenticate_admin_tokens(Some(&h), b, hd) {
            AuthOutcome::Identify(p) => assert_eq!(p.id, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}
