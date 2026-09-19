// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening tests for `busbar-auth-admin-tokens`.
//!
//! ## Fold operator: `bearer_match | header_match` must stay bitwise-OR, not XOR
//!
//! No existing test presented BOTH carriers matching the configured token at once, so the fold's
//! operator (bitwise-OR vs XOR) was unobserved: OR and XOR only disagree when both operands are 1.
//! This file closes that gap directly.
//!
//! ## Non-JWT-shaped-credential invariant
//!
//! This module does not parse JWTs at all (it hashes an opaque bearer/header string and
//! constant-time-compares the digest against the configured admin-token hash). The invariant that
//! applies: no malformed/adversarial candidate string — regardless of shape — may ever be
//! `Identify`d (accepted) without its SHA-256 digest exactly matching the configured hash. The
//! tests below drive that with empty strings, random-looking bytes-as-string, JWT-shaped-but-wrong
//! strings, and other garbage, all of which must fall through to `Pass`/`Reject`, never `Identify`.
//!
//! ## S12: JWS-shaped mismatch defers (`Pass`), it does not terminally `Reject`
//!
//! A candidate shaped like a JWS/JWT compact serialization (three non-empty dot-separated
//! segments) is never admin-tokens' own credential grammar — it belongs to a different scheme
//! (e.g. an OIDC/AD admin module later in the same `admin_auth:` chain, sharing the
//! `Authorization: Bearer` carrier). Such a candidate must `Pass` (defer) so that later chain arm
//! stays reachable, not `Reject` and short-circuit the whole chain. A non-JWS-shaped wrong
//! candidate is still a genuine "addressed to this module and wrong" attempt and must `Reject`.

use busbar_api::{sha256_hex, AuthOutcome};
use busbar_auth_admin_tokens::{authenticate_admin_tokens, ADMIN_TOKENS_PRINCIPAL_ID};

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

/// Closes the surviving `|` → `^` mutant: when BOTH carriers match the configured token, OR and XOR
/// disagree (OR says 1, matched; XOR says 0, unmatched). Only a test presenting both-correct carriers
/// distinguishes them — a real deployment could present a Bearer AND an `X-Admin-Token` that are both
/// the (same) correct admin token, and that must still `Identify`, not silently fail.
#[test]
fn both_carriers_correct_still_identifies() {
    let h = hash("secret");
    match authenticate_admin_tokens(Some(&h), Some("secret"), Some("secret")) {
        AuthOutcome::Identify(p) => assert_eq!(p.id, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("both carriers correct must Identify, got {other:?}"),
    }
}

/// A NON-JWT-shaped (indeed, any-shaped) credential that does not hash-match the configured token
/// must never be `Accept`ed/`Identify`d. This module never inspects structure — it hashes and
/// compares — so the property to prove is: garbage in, `Pass` or `Reject` out, NEVER `Identify`,
/// across a battery of malformed/adversarial shapes on both carriers.
#[test]
fn non_matching_credentials_of_any_shape_never_identify() {
    let h = hash("the-real-admin-token");
    let bad_candidates = [
        "",                                 // empty string
        "\0\x01\x02\x7f-random-bytes-ish",  // control-byte garbage (as UTF-8-lossy text)
        "a.b",                              // JWT-like but missing a segment (2 parts, not 3)
        "a.b.c.d",                          // too many dot-separated parts
        "not-a-jwt-at-all-just-plain-text", // no dots at all
        "not base64!!! ####",               // garbage, not valid base64
        "eyJhbGciOiJub25lIn0..",            // JWT-shaped header but empty payload/sig segments
        "the-real-admin-token-but-longer",  // near-miss, wrong length
        "the-real-admin-toke",              // near-miss, truncated by one char
        "the-real-admin-tokfn",             // near-miss, single-byte diff, same length
    ];
    for cred in bad_candidates {
        // As the Bearer carrier alone.
        match authenticate_admin_tokens(Some(&h), Some(cred), None) {
            AuthOutcome::Identify(_) => {
                panic!("non-matching bearer candidate {cred:?} must never Identify")
            }
            AuthOutcome::Pass | AuthOutcome::Reject => {}
        }
        // As the X-Admin-Token carrier alone.
        match authenticate_admin_tokens(Some(&h), None, Some(cred)) {
            AuthOutcome::Identify(_) => {
                panic!("non-matching header candidate {cred:?} must never Identify")
            }
            AuthOutcome::Pass | AuthOutcome::Reject => {}
        }
        // As BOTH carriers simultaneously (the both-carrier fold under test).
        match authenticate_admin_tokens(Some(&h), Some(cred), Some(cred)) {
            AuthOutcome::Identify(_) => {
                panic!("non-matching both-carrier candidate {cred:?} must never Identify")
            }
            AuthOutcome::Pass | AuthOutcome::Reject => {}
        }
    }
}

/// A mismatched, NON-JWS-shaped credential presented against a configured token must specifically
/// `Reject` (a credential WAS presented, addressed to THIS module's grammar, and it's just wrong)
/// — never silently `Pass`, which would make a wrong credential indistinguishable from "no
/// credential", and never `Identify`.
#[test]
fn wrong_credential_of_any_shape_rejects_not_passes() {
    let h = hash("secret");
    for cred in ["", "wrong", "\0\x01garbage"] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(cred), None),
            AuthOutcome::Reject,
            "candidate {cred:?} on bearer carrier must Reject"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(cred)),
            AuthOutcome::Reject,
            "candidate {cred:?} on header carrier must Reject"
        );
    }
}

/// S12 boundary: candidates that are ONE segment-count away from JWS-shaped (2 segments, 4
/// segments) or that have an empty segment inside a 3-dot-count split must still `Reject`, not
/// defer. `non_matching_credentials_of_any_shape_never_identify` already drives these shapes but
/// only asserts non-`Identify` (`Pass` or `Reject` both pass); that leaves the segment-count and
/// empty-segment boundaries in `is_jws_shaped` unlocked — a mutant that widens the 3-segment check
/// to accept 2, 4, or an empty segment would defer these instead of rejecting and nothing here
/// would catch it. Pin `Reject` explicitly for every boundary shape.
#[test]
fn near_jws_shaped_boundary_still_rejects() {
    let h = hash("secret");
    for cred in ["a.b", "a.b.c.d", "a..c", ".b.c", "a.b."] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(cred), None),
            AuthOutcome::Reject,
            "near-JWS-boundary candidate {cred:?} on bearer carrier must Reject, not defer"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(cred)),
            AuthOutcome::Reject,
            "near-JWS-boundary candidate {cred:?} on header carrier must Reject, not defer"
        );
    }
}

/// S12: a mismatched but JWS-SHAPED credential (three non-empty dot-separated segments — the
/// compact-serialization shape a real JWT/JWS uses) must `Pass` (defer), never `Reject`. It is
/// not admin-tokens' credential grammar, so a terminal `Reject` here would short-circuit the
/// `admin_auth:` chain before a later, JWT-consuming module (e.g. OIDC/AD) ever sees it.
#[test]
fn jws_shaped_mismatch_defers_not_rejects() {
    let h = hash("secret");
    for cred in ["a.b.c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.sig", "x.y.z"] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(cred), None),
            AuthOutcome::Pass,
            "JWS-shaped candidate {cred:?} on bearer carrier must Pass (defer), not Reject"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(cred)),
            AuthOutcome::Pass,
            "JWS-shaped candidate {cred:?} on header carrier must Pass (defer), not Reject"
        );
    }
}

/// A non-JWS-shaped wrong credential on one carrier must still `Reject` the whole verdict even
/// when the OTHER carrier independently carries a JWS-shaped (deferring) candidate — the
/// non-JWS-shaped carrier genuinely addressed this module and was wrong; that must not be masked
/// by the other carrier's defer.
#[test]
fn mixed_carriers_non_jws_wrong_still_rejects() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("wrong"), Some("a.b.c")),
        AuthOutcome::Reject,
        "non-JWS-shaped wrong bearer must still Reject even with a JWS-shaped header"
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("a.b.c"), Some("wrong")),
        AuthOutcome::Reject,
        "non-JWS-shaped wrong header must still Reject even with a JWS-shaped bearer"
    );
}
