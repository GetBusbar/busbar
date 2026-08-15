// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 8707 audience binding for credentials busbar did not mint.
//!
//! The property under test is one-directional and that is the whole design: this filter may only
//! ever REFUSE. So every case below asks "does the wrong token get turned away", and the two cases
//! that answer `Bound` are there to prove the filter is not simply refusing everything — which is
//! the way a fail-closed check silently stops being a check.

use super::{inspect_bearer, Binding};
use base64::Engine as _;

const RESOURCE: &str = "https://gateway.example.com/mcp";

/// Build a JWT-shaped token whose payload is `claims`. The signature is garbage on purpose: this
/// module never verifies one, and a test that supplied a real signature would imply it did.
fn jwt(claims: serde_json::Value) -> String {
    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    format!(
        "{}.{}.{}",
        b64(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64(claims.to_string().as_bytes()),
        b64(b"not-a-real-signature")
    )
}

/// A busbar-minted token is DEFERRED, never judged here. It is not a JWT — it is
/// `bbk_<payload>.<sig>` — so reading it as one would find no `aud` and refuse every valid busbar
/// token presented on the MCP plane, which is a total outage dressed as a security control.
#[test]
fn a_busbar_token_is_deferred_to_the_verifier() {
    let tok = format!(
        "{}eyJzdWIiOiJ2a19hYmMifQ.c2ln",
        crate::governance::signing::TOKEN_PREFIX
    );
    assert_eq!(inspect_bearer(&tok, RESOURCE), Binding::Deferred);
}

/// The accept arms. Both `aud` forms RFC 7519 permits are read: a bare string, and an array in
/// which the expected value appears anywhere (not only first — an IdP is free to order them).
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

/// THE CONFUSED-DEPUTY CASE, and the reason this module exists. Every one of these is a token the
/// operator's IdP legitimately issued and correctly signed, and an auth plugin asked "did our IdP
/// sign this?" would say yes to all of them. None was minted for busbar.
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

/// A resource indicator is an OPAQUE IDENTIFIER, not a namespace. Every near-miss below shares a
/// prefix, a suffix or a case-folding with the real one, and every one of them is a different
/// resource. Matching any of them is how one deployment's tokens start being spent on another's.
#[test]
fn near_miss_audiences_are_not_treated_as_this_resource() {
    for near in [
        "https://gateway.example.com/mcp-staging",
        "https://gateway.example.com/mcp/",
        "https://gateway.example.com/mc",
        "https://gateway.example.com",
        "HTTPS://GATEWAY.EXAMPLE.COM/MCP",
        "http://gateway.example.com/mcp",
        "https://gateway.example.com.evil.test/mcp",
    ] {
        assert_eq!(
            inspect_bearer(&jwt(serde_json::json!({ "aud": near })), RESOURCE),
            Binding::Mismatch,
            "`{near}` is not `{RESOURCE}` and must not be accepted as it"
        );
    }
}

/// A credential with nothing to read. Refusal is the only honest answer to "was this minted for
/// me?" when the credential cannot say — see the module header on the opaque-token limitation.
#[test]
fn a_credential_with_no_readable_claims_is_opaque() {
    for tok in [
        "0f6d2a9c-3b1e-4f77-9a2e-8c5d1e0b7a44", // an opaque reference token
        "not.a.jwt.at.all.five.segments",
        "onlytwo.segments",
        "",
        "..",                     // three empty segments
        "aGVhZGVy.!!!!.c2ln",     // middle segment is not base64url
        "aGVhZGVy.bm90LWpzb24.c", // middle segment decodes to bytes that are not JSON
    ] {
        assert_eq!(
            inspect_bearer(tok, RESOURCE),
            Binding::Opaque,
            "`{tok}` carries no readable audience and must be refused, not admitted"
        );
    }
}
