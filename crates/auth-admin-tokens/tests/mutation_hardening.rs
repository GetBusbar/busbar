// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening tests for `busbar-auth-admin-tokens`, added after a `cargo mutants` pass.
//!
//! ## Surviving mutant: `bearer_match | header_match` → `bearer_match ^ header_match`
//!
//! No existing test presented BOTH carriers matching the configured token at once, so the fold's
//! operator (bitwise-OR vs XOR) was unobserved: OR and XOR only disagree when both operands are 1.
//! This file closes that gap directly.
//!
//! ## Non-JWT-shaped-credential invariant
//!
//! This module does not parse JWTs at all (it hashes an opaque bearer/header string and
//! constant-time-compares the digest against the configured admin-token hash), so there is no
//! "JWT-shaped" structural check to bypass. The analogous, and stronger, invariant that DOES apply
//! here: no malformed/adversarial candidate string — regardless of shape — may ever be `Identify`d
//! (accepted) without its SHA-256 digest exactly matching the configured hash. The tests below drive
//! that with empty strings, random-looking bytes-as-string, JWT-shaped-but-wrong strings, and other
//! garbage, all of which must fall through to `Pass`/`Reject`, never `Identify`.

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

/// A mismatched credential presented against a configured token must specifically `Reject`
/// (a credential WAS presented, it's just wrong) — never silently `Pass`, which would make a wrong
/// credential indistinguishable from "no credential", and never `Identify`.
///
/// `Pass` has exactly one meaning on the miss path, and the split that gave it that meaning closed a
/// real hole: a chain arm owes three answers, and an arm that collapses `Pass` into `Reject` makes
/// every arm after it unreachable — with `admin_auth: [admin-tokens, corp-oidc]` an OIDC bearer JWT
/// was refused here before `corp-oidc` was ever asked, and the second arm was configured, resolved
/// at boot, and dead. So a miss now asks ONE question — is this candidate PROVABLY another issuer's
/// credential? — and the direction is fail-closed:
///
/// * a candidate this arm cannot positively attribute elsewhere stays MINE, and mine-and-wrong is
///   the terminal `Reject` it always was;
/// * a candidate carrying the JWS Compact Serialization an OIDC/AD arm is handed (three
///   `.`-separated non-empty base64url segments) is provably foreign, so this arm steps aside with
///   `Pass` and the NEXT arm answers. A chain that runs out of arms after a `Pass` denies, so the
///   third answer cannot open the admin surface by exhaustion.
///
/// This cell asserts both halves. Asserting only the first — which is what it did before the split,
/// with `"a.b.c"` in the reject row — would re-plant the hole the split closed.
#[test]
fn wrong_credential_of_any_shape_rejects_not_passes() {
    let h = hash("secret");
    // Not attributable to any other issuer ⇒ still MINE ⇒ terminal Reject, never Identify.
    for cred in [
        "",
        "wrong",
        "\0\x01garbage",
        "a.b",
        "a.b.c.d",
        "a..c",
        "a.b.$",
    ] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(cred), None),
            AuthOutcome::Reject,
            "candidate {cred:?} is not provably another issuer's, so it stays mine: the bearer \
             carrier must Reject"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(cred)),
            AuthOutcome::Reject,
            "candidate {cred:?} is not provably another issuer's, so it stays mine: the header \
             carrier must Reject"
        );
    }
    // Provably another issuer's ⇒ not mine ⇒ Pass, so the next arm is asked.
    for cred in [
        "a.b.c",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcHMifQ.c2ln",
        "-_-.-_-.-_-",
    ] {
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some(cred), None),
            AuthOutcome::Pass,
            "candidate {cred:?} is a JWS compact serialization, so this arm is not the one that \
             refuses it: the bearer carrier must Pass to the next arm"
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some(cred)),
            AuthOutcome::Pass,
            "candidate {cred:?} is a JWS compact serialization, so this arm is not the one that \
             refuses it: the header carrier must Pass to the next arm"
        );
    }
    // One unattributable carrier keeps the WHOLE presentation mine: a foreign-shaped bearer beside
    // a garbage header still stops here rather than stepping aside.
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("a.b.c"), Some("wrong")),
        AuthOutcome::Reject,
        "one unattributable carrier keeps the presentation mine, so this must Reject"
    );
}
