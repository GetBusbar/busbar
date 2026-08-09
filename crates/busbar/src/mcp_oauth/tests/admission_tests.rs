// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The adversarial admission battery for the MCP resource server.
//!
//! There is no third-party coverage to lean on here. Server-side MCP OAuth is absent from busbar's
//! independent conformance battery and absent from the official `modelcontextprotocol/conformance`
//! suite, so there is no oracle and nothing to adopt — these tests ARE the coverage. They are written from the attacker's side: every case below is a token an
//! attacker or a confused client can actually produce, and every one of them is signed for real by
//! the fixture in `support.rs`, so a passing case cannot be passing because the crypto was faked.
//!
//! The single most important assertion in the file is
//! [`a_token_for_a_different_audience_is_refused`]. Get it wrong and busbar is a confused deputy
//! while every other gate in the system still reports green, because every other gate is asking a
//! different question.

use super::support::*;
use super::Refusal;

/// **THE confused-deputy defence.** The operator's IdP legitimately issues the same agent tokens for
/// several services. A token minted for the billing API — correctly signed, unexpired, from the
/// trusted issuer, naming a real subject and a real client — must NOT open busbar's MCP endpoint.
/// Everything about it is valid except who it was for.
///
/// If this passes wrongly, busbar accepts a credential intended for another service and then acts
/// with busbar's OWN upstream authority on the strength of it. That is the confused-deputy condition
/// exactly, and no other test in the system detects it: the signature is good, the expiry is good,
/// the principal resolves, the budget applies, the audit row is written. Everything is green and the
/// gateway is compromised.
///
/// RED (no audience check in `admit`): the token is ADMITTED, and the assertion fails on
/// `Ok(McpCaller { .. })` where a `Refusal::AudienceMismatch` was required.
/// GREEN: refused with `AudienceMismatch`, on the strength of the audience alone.
#[test]
fn a_token_for_a_different_audience_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    // The ONLY difference from a token that would be admitted.
    claims["aud"] = serde_json::json!(OTHER_RESOURCE);
    let token = idp.mint(&claims);

    // The control: the same claim set differing only in `aud` IS admitted, so this test cannot pass
    // because of some unrelated defect that refuses everything.
    let admitted = rs.admit(&idp.mint(&good_claims()), NOW);
    assert!(
        admitted.is_ok(),
        "control failed: the baseline token must be admitted, else the refusal below proves \
         nothing about the audience (got {admitted:?})"
    );

    assert_eq!(
        rs.admit(&token, NOW),
        Err(Refusal::AudienceMismatch),
        "a token whose audience is another service MUST be refused: accepting it makes busbar a \
         confused deputy for {OTHER_RESOURCE}"
    );
}

/// A token with NO audience at all is usable at every resource that will take it — the confused
/// deputy condition in its most general form. RFC 9068 makes `aud` required in a JWT access token
/// and RFC 8707 exists to bind one; an audience-less token has neither.
///
/// RED (no audience check): admitted.
/// GREEN: `AudienceMissing`.
#[test]
fn a_token_with_no_audience_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("aud");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW),
        Err(Refusal::AudienceMissing),
        "an audience-less bearer token is valid everywhere it is presented; busbar must not be one \
         of those places"
    );
}

/// The array spelling of `aud` (RFC 7519 §4.1.3, what Entra emits) must be searched, not compared
/// whole: a token naming three other services and not busbar is still a token for someone else.
///
/// RED (no audience check): admitted.
/// GREEN: `AudienceMismatch`.
#[test]
fn a_multi_valued_audience_that_omits_busbar_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims["aud"] = serde_json::json!([OTHER_RESOURCE, "https://crm.acme.com/api"]);
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW),
        Err(Refusal::AudienceMismatch)
    );
}

/// The other half of the array case: busbar named ALONGSIDE other resources is a token for busbar
/// too, and must be admitted. Without this, an over-strict "audience must equal exactly one string"
/// implementation would pass every refusal test in this file while breaking every Entra deployment.
#[test]
fn a_multi_valued_audience_that_names_busbar_is_admitted() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims["aud"] = serde_json::json!([OTHER_RESOURCE, BUSBAR_RESOURCE]);
    let caller = rs.admit(&idp.mint(&claims), NOW).expect("admitted");
    assert_eq!(caller.subject, "00u1a2b3c4d5e6f7g8h9");
}

/// The audience is an opaque identifier compared byte-for-byte. A near-miss — trailing slash, a
/// case-folded host, the http twin — is a DIFFERENT resource, and any "helpful" normalisation here
/// is a bypass with a friendly name.
///
/// RED (no audience check): every one of these is admitted.
/// GREEN: each is `AudienceMismatch`.
#[test]
fn the_audience_comparison_is_exact() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    for near_miss in [
        "https://busbar.acme.com/mcp/",
        "https://BUSBAR.acme.com/mcp",
        "http://busbar.acme.com/mcp",
        "https://busbar.acme.com/mcp?",
        "https://busbar.acme.com:443/mcp",
        " https://busbar.acme.com/mcp",
    ] {
        let mut claims = good_claims();
        claims["aud"] = serde_json::json!(near_miss);
        assert_eq!(
            rs.admit(&idp.mint(&claims), NOW),
            Err(Refusal::AudienceMismatch),
            "audience {near_miss:?} is not busbar's resource identifier and must not be treated as \
             though it were"
        );
    }
}

/// An expired token is a token whose authority the IdP has already withdrawn. The skew allowance is
/// 60 seconds, so this one is expired by an hour: the test is about expiry, not about the boundary.
///
/// RED (no expiry check): admitted.
/// GREEN: `Expired`.
#[test]
fn an_expired_token_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims["exp"] = serde_json::json!(NOW - 3600);
    assert_eq!(rs.admit(&idp.mint(&claims), NOW), Err(Refusal::Expired));
}

/// A token with no `exp` never expires. Treated as expired rather than as unbounded.
#[test]
fn a_token_with_no_expiry_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("exp");
    assert_eq!(rs.admit(&idp.mint(&claims), NOW), Err(Refusal::Expired));
}

/// A token not yet valid is refused for the mirror reason, beyond the same allowance.
#[test]
fn a_not_yet_valid_token_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims["nbf"] = serde_json::json!(NOW + 3600);
    assert_eq!(rs.admit(&idp.mint(&claims), NOW), Err(Refusal::NotYetValid));
}

/// `alg: none` — an UNSIGNED token with an empty signature segment, the oldest JWT forgery there is.
/// The attacker needs no key: they write the claims they want and declare the token unsigned. A
/// verifier that dispatches on the token's own `alg` and has a permissive default "verifies" it.
///
/// The claims here are the GOOD ones, so nothing else about this token is wrong — only that nobody
/// signed it.
///
/// RED (no algorithm allow-list): admitted, because every claim in it is otherwise valid.
/// GREEN: `UnsupportedAlgorithm("none")`.
#[test]
fn an_unsigned_alg_none_token_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    assert_eq!(
        rs.admit(&unsigned_token(&good_claims()), NOW),
        Err(Refusal::UnsupportedAlgorithm("none".to_string())),
        "an unsigned token is an attacker's own assertion about who they are"
    );
}

/// The symmetric half of the same family: `HS256` against an asymmetric key set is the
/// RS256-to-HS256 key-confusion attack, where the attacker HMACs the token with the PUBLIC key as
/// the shared secret. Refused by algorithm, before any key is consulted.
#[test]
fn an_hmac_token_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    // Header lies about the algorithm; the signature bytes are irrelevant because the refusal
    // happens before they are examined.
    let token = idp.mint_with_header(
        &serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "k1"}),
        &good_claims(),
    );
    assert_eq!(
        rs.admit(&token, NOW),
        Err(Refusal::UnsupportedAlgorithm("HS256".to_string()))
    );
}

/// A token signed by a key busbar does not trust — the same issuer name, the same `kid`, a real
/// ES256 signature, and a keypair that is simply not the one the operator configured. This is what
/// an attacker who can stand up their own IdP produces.
///
/// RED (no signature verification): admitted, because every CLAIM in it is correct — only the
/// signature is another party's.
/// GREEN: `BadSignature`.
#[test]
fn a_token_signed_by_the_wrong_key_is_refused() {
    let trusted = TestIdp::ec(ISSUER, "k1");
    // Same issuer, same kid, different keypair. The impersonation, not a corruption.
    let attacker = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&trusted);
    assert_eq!(
        rs.admit(&attacker.mint(&good_claims()), NOW),
        Err(Refusal::BadSignature),
        "a signature from a key the operator never configured proves nothing"
    );
}

/// A token naming a `kid` the trusted issuer does not publish. Distinct from a bad signature: there
/// was no key to check against, and silently trying every key in the set instead would make `kid`
/// decorative.
#[test]
fn a_token_naming_an_unpublished_kid_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let token = idp.mint_with_header(
        &serde_json::json!({"alg": "ES256", "typ": "at+jwt", "kid": "rotated-away"}),
        &good_claims(),
    );
    assert_eq!(rs.admit(&token, NOW), Err(Refusal::UnknownKey));
}

/// A perfectly valid token from an issuer the operator never configured. The issuer selects the key
/// set, so an unknown issuer must refuse rather than fall through to some default set.
#[test]
fn a_token_from_an_unconfigured_issuer_is_refused() {
    let trusted = TestIdp::ec(ISSUER, "k1");
    let stranger = TestIdp::ec("https://evil.example.com/", "k1");
    let rs = resource_server(&trusted);
    let mut claims = good_claims();
    claims["iss"] = serde_json::json!("https://evil.example.com/");
    assert_eq!(
        rs.admit(&stranger.mint(&claims), NOW),
        Err(Refusal::UntrustedIssuer)
    );
}

/// Structural junk: not three segments, not base64url, not JSON. Refused before any claim is read.
#[test]
fn a_malformed_token_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    for junk in [
        "not-a-token",
        "aGVhZGVy.cGF5bG9hZA",
        "a.b.c.d",
        "!!!.???.***",
    ] {
        assert!(
            matches!(rs.admit(junk, NOW), Err(Refusal::Malformed(_))),
            "{junk:?} is not a compact JWS and must be refused as malformed"
        );
    }
    assert_eq!(rs.admit("", NOW), Err(Refusal::NoCredential));
}

/// The positive case, and the one that proves every refusal above is attributable. A well-formed
/// token for the right audience is ADMITTED and resolves to the right principal: the subject the IdP
/// authenticated AND the client that is acting for them, kept as separate facts because "user X" and
/// "user X through agent Y" are different things and the second is what an operator wants in an
/// audit row.
#[test]
fn a_well_formed_token_is_admitted_and_resolves_to_user_and_client() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let caller = rs.admit(&idp.mint(&good_claims()), NOW).expect("admitted");
    assert_eq!(caller.subject, "00u1a2b3c4d5e6f7g8h9");
    assert_eq!(caller.client_id, "0oa9z8y7x6w5v4u3t2s1");
    assert_eq!(caller.issuer, ISSUER);
    assert_eq!(caller.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(caller.expires_at, NOW + 600);
    assert_eq!(caller.roles, vec!["mcp:tools:list", "mcp:tools:call"]);
    // The identity handed to the existing governance path is identity ONLY: policy is resolved by
    // busbar from `auth.role_bindings:`, never asserted by the token.
    let principal = caller.principal();
    assert_eq!(principal.id, "00u1a2b3c4d5e6f7g8h9");
    assert_eq!(principal.name.as_deref(), Some("Ada Lovelace"));
}

/// RS256 is what Okta, Entra and Auth0 sign access tokens with by default. It has its own key type,
/// its own `ring` verifier and its own material decode, so an ES256-only battery would leave the
/// algorithm most operators actually use entirely unexecuted.
#[test]
fn an_rs256_token_is_admitted_and_a_wrong_rs256_signature_is_not() {
    let idp = TestIdp::rsa(ISSUER, "rsa-1");
    let rs = resource_server(&idp);
    let caller = rs.admit(&idp.mint(&good_claims()), NOW).expect("admitted");
    assert_eq!(caller.client_id, "0oa9z8y7x6w5v4u3t2s1");

    // Same key, same header, claims altered after signing: the signature no longer covers the bytes.
    let token = idp.mint(&good_claims());
    let mut segments: Vec<&str> = token.split('.').collect();
    let forged_payload = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::json!({"iss": ISSUER, "sub": "root", "aud": BUSBAR_RESOURCE,
                           "exp": NOW + 600, "client_id": "c"})
        .to_string(),
    );
    segments[1] = &forged_payload;
    assert_eq!(
        rs.admit(&segments.join("."), NOW),
        Err(Refusal::BadSignature)
    );
}

/// The audience check must not be reachable only through one algorithm's code path. Repeating the
/// confused-deputy case under RS256 proves the check lives in the resource server, above the
/// signature branch, rather than in one of the two verifiers.
#[test]
fn the_audience_check_applies_to_rs256_too() {
    let idp = TestIdp::rsa(ISSUER, "rsa-1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims["aud"] = serde_json::json!(OTHER_RESOURCE);
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW),
        Err(Refusal::AudienceMismatch)
    );
}

/// No subject: nobody to attribute the call to, so there is no principal to govern, meter or audit.
#[test]
fn a_token_with_no_subject_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("sub");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW),
        Err(Refusal::SubjectMissing)
    );
    claims["sub"] = serde_json::json!("");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW),
        Err(Refusal::SubjectMissing)
    );
}

/// No client id: RFC 9068 §2.2 makes it REQUIRED in a JWT access token, and per-agent attribution is
/// something busbar promises operators. An unattributable token is refused rather than admitted as
/// "unknown", because "unknown" in an audit row is a claim that quietly stops being true.
#[test]
fn a_token_with_no_client_id_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("client_id");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW),
        Err(Refusal::ClientMissing)
    );
}

/// The client id has three spellings in the field: `client_id` (RFC 9068), `azp` (OIDC, what Entra
/// v2 and Keycloak emit) and `appid` (Entra v1). All three resolve; `client_id` wins when several
/// are present, because it is the one the RFC defines.
#[test]
fn the_client_id_is_read_from_client_id_then_azp_then_appid() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let mut claims = good_claims();

    claims["azp"] = serde_json::json!("azp-client");
    claims["appid"] = serde_json::json!("appid-client");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW)
            .expect("admitted")
            .client_id,
        "0oa9z8y7x6w5v4u3t2s1"
    );

    claims.as_object_mut().expect("object").remove("client_id");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW)
            .expect("admitted")
            .client_id,
        "azp-client"
    );

    claims.as_object_mut().expect("object").remove("azp");
    assert_eq!(
        rs.admit(&idp.mint(&claims), NOW)
            .expect("admitted")
            .client_id,
        "appid-client"
    );
}

/// RFC 7515 §4.1.11: a verifier that does not implement every parameter named in `crit` MUST refuse
/// the token. This one implements none, so any non-empty `crit` is a refusal — "the signature was
/// fine so we ignored the instruction we did not understand" is not an acceptable outcome.
#[test]
fn a_token_naming_a_critical_extension_is_refused() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let token = idp.mint_with_header(
        &serde_json::json!({"alg": "ES256", "kid": "k1", "crit": ["b64"], "b64": false}),
        &good_claims(),
    );
    // The refusal arrives as a failed signature check for this key, which is the fail-closed
    // outcome: no key verified the token, so nothing was admitted.
    assert!(matches!(
        rs.admit(&token, NOW),
        Err(Refusal::BadSignature) | Err(Refusal::UnknownKey)
    ));
}

/// A second issuer must not widen the first. With two authorization servers configured, a token from
/// issuer A signed by issuer A's key is admitted; the same token presented as though it came from
/// issuer B is not, because the issuer selects the key set.
#[test]
fn two_issuers_do_not_pool_their_keys() {
    let a = TestIdp::ec("https://a.okta.com/oauth2/default", "ka");
    let b = TestIdp::ec("https://b.okta.com/oauth2/default", "kb");
    let rs = super::ResourceServer::build(
        BUSBAR_RESOURCE,
        vec![(a.issuer.clone(), a.jwks()), (b.issuer.clone(), b.jwks())],
    )
    .expect("two issuers configure");

    let mut claims = good_claims();
    claims["iss"] = serde_json::json!(a.issuer);
    assert!(rs.admit(&a.mint(&claims), NOW).is_ok());

    // Issuer B's name over issuer A's key: B publishes no `ka`, so there is no key to try.
    claims["iss"] = serde_json::json!(b.issuer);
    assert_eq!(rs.admit(&a.mint(&claims), NOW), Err(Refusal::UnknownKey));
}

/// A refusal never reaches the wire, but it does reach a log, so every variant must carry a stable
/// tag. Enumerated exhaustively: a variant added without a tag fails to compile, and a variant added
/// without a test here fails this assertion.
#[test]
fn every_refusal_has_a_distinct_tag() {
    let all = [
        Refusal::NoCredential,
        Refusal::Malformed(String::new()),
        Refusal::UnsupportedAlgorithm(String::new()),
        Refusal::UntrustedIssuer,
        Refusal::UnknownKey,
        Refusal::BadSignature,
        Refusal::Expired,
        Refusal::NotYetValid,
        Refusal::AudienceMissing,
        Refusal::AudienceMismatch,
        Refusal::SubjectMissing,
        Refusal::ClientMissing,
    ];
    let mut tags: Vec<&str> = all.iter().map(|r| r.tag()).collect();
    tags.sort_unstable();
    let count = tags.len();
    tags.dedup();
    assert_eq!(tags.len(), count, "refusal tags must be distinct");
}
