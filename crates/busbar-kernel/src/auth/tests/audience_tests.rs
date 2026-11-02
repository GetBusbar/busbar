// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{inspect_bearer, Binding};
use base64::Engine as _;

const RESOURCE: &str = "https://gateway.example.com/plane";

fn jwt(claims: serde_json::Value) -> String {
    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    format!(
        "{}.{}.{}",
        b64(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64(claims.to_string().as_bytes()),
        b64(b"not-a-real-signature")
    )
}

#[test]
fn a_busbar_token_is_deferred_to_the_verifier() {
    let tok = format!(
        "{}eyJzdWIiOiJ2a19hYmMifQ.c2ln",
        crate::governance::signing::TOKEN_PREFIX
    );
    assert_eq!(inspect_bearer(&tok, RESOURCE), Binding::Deferred);
}

#[test]
fn a_jwt_naming_this_resource_is_bound_in_both_aud_forms() {
    assert_eq!(
        inspect_bearer(&jwt(serde_json::json!({ "aud": RESOURCE })), RESOURCE),
        Binding::Bound,
        "the single-string aud form"
    );
    assert_eq!(
        inspect_bearer(
            &jwt(serde_json::json!({ "aud": ["https://other.example/api", RESOURCE] })),
            RESOURCE
        ),
        Binding::Bound,
        "the array aud form, with this resource in a non-first position"
    );
}

#[test]
fn a_token_minted_for_somebody_else_is_refused() {
    for (label, claims) in [
        (
            "a different resource entirely",
            serde_json::json!({ "aud": "https://wiki.example.com" }),
        ),
        (
            "an array that does not contain us",
            serde_json::json!({ "aud": ["https://wiki.example.com", "https://ci.example.com"] }),
        ),
        ("no aud claim at all", serde_json::json!({ "sub": "alice" })),
        (
            "an aud of the wrong JSON type",
            serde_json::json!({ "aud": 42 }),
        ),
        (
            "an empty aud array",
            serde_json::json!({ "aud": Vec::<String>::new() }),
        ),
    ] {
        assert_eq!(
            inspect_bearer(&jwt(claims), RESOURCE),
            Binding::Mismatch,
            "{label} must be refused"
        );
    }
}

#[test]
fn near_miss_audiences_are_not_treated_as_this_resource() {
    for near in [
        "https://gateway.example.com/plane-staging",
        "https://gateway.example.com/plane/",
        "https://gateway.example.com/plan",
        "https://gateway.example.com",
        "HTTPS://GATEWAY.EXAMPLE.COM/PLANE",
        "http://gateway.example.com/plane",
        "https://gateway.example.com.evil.test/plane",
    ] {
        assert_eq!(
            inspect_bearer(&jwt(serde_json::json!({ "aud": near })), RESOURCE),
            Binding::Mismatch,
            "`{near}` is not `{RESOURCE}` and must not be accepted as it"
        );
    }
}

#[test]
fn a_credential_with_no_readable_claims_is_opaque() {
    for tok in [
        "0f6d2a9c-3b1e-4f77-9a2e-8c5d1e0b7a44",
        "not.a.jwt.at.all.five.segments",
        "onlytwo.segments",
        "",
        "..",
        "aGVhZGVy.!!!!.c2ln",
        "aGVhZGVy.bm90LWpzb24.c",
    ] {
        assert_eq!(
            inspect_bearer(tok, RESOURCE),
            Binding::Opaque,
            "`{tok}` carries no readable audience and must be refused, not admitted"
        );
    }
}

#[test]
fn the_audience_refusal_descriptions_are_single_spaced_sentences() {
    assert_eq!(
        super::MISMATCH_DESCRIPTION,
        "The access token's audience does not identify this resource. Request a token whose \
         `resource` (RFC 8707) is this server's canonical URI."
    );
    assert_eq!(
        super::OPAQUE_DESCRIPTION,
        "This credential carries no readable audience, so it cannot be shown to have been issued \
         for this resource. A JWT access token is required here."
    );
    for description in [super::MISMATCH_DESCRIPTION, super::OPAQUE_DESCRIPTION] {
        assert!(
            !description.contains("  "),
            "a run of spaces: {description:?}"
        );
    }
}
