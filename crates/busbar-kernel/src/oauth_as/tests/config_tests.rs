// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT REFUSALS, and the one path everybody gets backwards.

use super::{AsCfgError, AsIdentity, OauthAsCfg, StaticClientCfg};

fn cfg(issuer: &str) -> OauthAsCfg {
    OauthAsCfg {
        issuer: issuer.to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    }
}

/// RFC 8414 §3.1 PUTS THE WELL-KNOWN SEGMENT FIRST, and RFC 9728 §3.1 puts it last. The two
/// documents this deployment serves therefore have their paths built in OPPOSITE orders, a few lines
/// apart, and getting either backwards means every conforming client's discovery 404s while the
/// server looks healthy.
#[test]
fn the_authorization_server_metadata_path_inserts_the_issuer_path_after_the_well_known_segment() {
    let id = AsIdentity::from_cfg(&cfg("https://gw.example.com/tenant1")).expect("valid");
    assert_eq!(
        id.metadata_path(),
        "/.well-known/oauth-authorization-server/tenant1",
        "RFC 8414 section 3.1: the well-known segment comes BEFORE the issuer's path"
    );
    assert_eq!(id.authorize_path(), "/tenant1/authorize");
    assert_eq!(id.token_path(), "/tenant1/token");
    assert_eq!(id.jwks_uri(), "https://gw.example.com/tenant1/jwks");
}

/// An issuer at an origin root has no path to insert, and the well-known path is the bare one.
#[test]
fn an_issuer_with_no_path_serves_the_bare_well_known_document() {
    let id = AsIdentity::from_cfg(&cfg("https://gw.example.com")).expect("valid");
    assert_eq!(
        id.metadata_path(),
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(id.authorize_path(), "/authorize");
    assert_eq!(id.consent_url(), "https://gw.example.com/consent");
}

/// A TRAILING SLASH IS A DIFFERENT SERVER. Every endpoint is `{issuer}/name`, so `https://host/`
/// derives `https://host//token`; and RFC 9207's `iss` comparison is byte-for-byte, so a client that
/// discovered one spelling will refuse the other. Refused at boot rather than normalised away,
/// because normalising hands back a string that no longer equals what the operator wrote.
#[test]
fn an_issuer_with_a_trailing_slash_is_refused_at_boot() {
    assert!(matches!(
        AsIdentity::from_cfg(&cfg("https://gw.example.com/")),
        Err(AsCfgError::IssuerHasTrailingSlash(_))
    ));
}

#[test]
fn an_issuer_that_is_not_an_absolute_url_is_refused_at_boot() {
    assert!(matches!(
        AsIdentity::from_cfg(&cfg("gw.example.com")),
        Err(AsCfgError::IssuerNotAbsolute(_))
    ));
    assert!(matches!(
        AsIdentity::from_cfg(&cfg("")),
        Err(AsCfgError::MissingIssuer)
    ));
}

/// RFC 8414 §2 defines the issuer as a URL with no query and no fragment.
#[test]
fn an_issuer_with_a_query_or_fragment_is_refused_at_boot() {
    for bad in ["https://gw.example.com?x=1", "https://gw.example.com#f"] {
        assert!(
            matches!(
                AsIdentity::from_cfg(&cfg(bad)),
                Err(AsCfgError::IssuerHasQueryOrFragment(_))
            ),
            "`{bad}` was accepted as an issuer"
        );
    }
}

/// A `default_grant` entry that is not an RFC 6749 §3.3 scope token is refused AT BOOT, naming the
/// value. It has to be: `policy::default_grant_scopes` builds the registration ceiling from this
/// list and `expect`s it, so an unvalidated entry would be a panic on the first registration rather
/// than a message an operator can act on.
#[test]
fn a_default_grant_entry_that_is_not_a_scope_token_is_refused_at_boot() {
    let mut c = cfg("https://gw.example.com");
    c.default_grant = vec!["tools:read".into(), "not a token".into()];
    assert!(matches!(
        AsIdentity::from_cfg(&c),
        Err(AsCfgError::ScopeNotAToken(_))
    ));
}

/// THE REGISTRATION PATH IS ALWAYS DERIVED. Every validated identity carries a registration path,
/// under the issuer's own prefix, with nothing to switch. Mirrors the metadata document, which is
/// what `oauth-as` routes from; the two must agree or busbar mounts a path the service does not
/// answer.
#[test]
fn the_registration_path_is_always_derived() {
    assert_eq!(
        AsIdentity::from_cfg(&cfg("https://gw.example.com"))
            .expect("valid")
            .register_path(),
        "/register"
    );
    assert_eq!(
        AsIdentity::from_cfg(&cfg("https://gw.example.com/tenant1"))
            .expect("valid")
            .register_path(),
        "/tenant1/register",
        "a tenant-prefixed issuer keeps its registration endpoint under the prefix"
    );
}

/// THE FAPI 2.0 POSTURE IS OFF UNLESS THE OPERATOR WRITES IT. An `oauth_as:` block that does not
/// name `fapi2` is the plain OAuth 2.1 server: no PAR endpoint, no mandatory DPoP, no profile
/// narrowing. Proven from the operator's own spelling (the block as written), not from the struct
/// default, because `#[serde(default)]` is the line that makes it true.
#[test]
fn the_fapi2_posture_is_off_unless_the_block_names_it() {
    let written: OauthAsCfg =
        serde_json::from_value(serde_json::json!({ "issuer": "https://gw.example.com" }))
            .expect("a block naming only the issuer parses");
    assert!(!written.fapi2, "an unnamed `fapi2` must parse as off");
    let id = AsIdentity::from_cfg(&written).expect("valid");
    assert!(
        !id.fapi2(),
        "the plain block must validate to the plain posture"
    );
}

/// `fapi2: true` is the one line that turns the FAPI 2.0 Security Profile posture on.
#[test]
fn fapi2_true_turns_the_posture_on() {
    let written: OauthAsCfg = serde_json::from_value(serde_json::json!({
        "issuer": "https://gw.example.com",
        "fapi2": true,
    }))
    .expect("a block naming fapi2 parses");
    assert!(AsIdentity::from_cfg(&written).expect("valid").fapi2());
}

/// RFC 9126 s5: the pushed authorization request endpoint is derived under the issuer exactly as
/// every other endpoint is, so a tenant-prefixed issuer keeps it under the prefix, and the absolute
/// URL the metadata advertises is the path the router mounts.
#[test]
fn the_par_endpoint_is_derived_under_the_issuer() {
    let id = AsIdentity::from_cfg(&cfg("https://gw.example.com/tenant1")).expect("valid");
    assert_eq!(id.par_path(), "/tenant1/par");
    assert_eq!(id.par_endpoint(), "https://gw.example.com/tenant1/par");
    let root = AsIdentity::from_cfg(&cfg("https://gw.example.com")).expect("valid");
    assert_eq!(root.par_path(), "/par");
}

/// A public ES256 JWK as an operator pastes it: the RFC 7517 members, plus `use`/`alg` hints.
fn public_jwk() -> serde_json::Value {
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    })
}

fn with_client(client: serde_json::Value) -> Result<AsIdentity, AsCfgError> {
    let written: OauthAsCfg = serde_json::from_value(serde_json::json!({
        "issuer": "https://gw.example.com",
        "clients": [client],
    }))
    .expect("the block parses");
    AsIdentity::from_cfg(&written)
}

fn client(jwk: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "client_id": "fapi-client",
        "redirect_uris": ["https://client.example/cb"],
        "jwks": { "keys": [jwk] },
    })
}

/// STATIC CLIENTS ARE OFF UNLESS CONFIGURED: a block that names no `clients` declares none.
#[test]
fn no_static_client_is_declared_unless_the_block_lists_one() {
    let written: OauthAsCfg =
        serde_json::from_value(serde_json::json!({ "issuer": "https://gw.example.com" }))
            .expect("parses");
    assert!(written.clients.is_empty());
    assert!(AsIdentity::from_cfg(&written).expect("valid").clients.is_empty());
}

/// A confidential `private_key_jwt` client the operator provisions out of band: its id, its exact
/// redirect URIs, and the PUBLIC half of its ES256 key, as RFC 7591 s2 `jwks` spells it.
#[test]
fn a_static_private_key_jwt_client_with_a_public_jwk_validates() {
    let id = with_client(client(public_jwk())).expect("a well-formed static client validates");
    let clients: &[StaticClientCfg] = &id.clients;
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].client_id, "fapi-client");
    assert_eq!(clients[0].jwks.keys[0].x, public_jwk()["x"].as_str().unwrap());
}

/// THE REFUSALS, each at boot and each naming the client: a private key (`d`), a key that is not
/// EC P-256, an algorithm other than ES256, a coordinate that is not 32 bytes, no key at all, no
/// redirect URI, a relative or fragment-carrying redirect URI, an empty id, and a duplicate id.
#[test]
fn a_malformed_static_client_is_refused_at_boot() {
    let refused = |c: serde_json::Value, why: &str| match with_client(c) {
        Err(AsCfgError::StaticClient { .. }) => {}
        other => panic!("{why}: expected a StaticClient refusal, got {other:?}"),
    };
    let mut private = public_jwk();
    private["d"] = serde_json::json!("ESExQVFhcYGRobHB0eHxAhIiMkJSYnKCkqKywtLi8gM");
    refused(client(private), "a private key must never be configured");
    let mut other_curve = public_jwk();
    other_curve["crv"] = serde_json::json!("P-384");
    refused(client(other_curve), "P-256 only");
    let mut rsa_alg = public_jwk();
    rsa_alg["alg"] = serde_json::json!("RS256");
    refused(client(rsa_alg), "ES256 only");
    let mut short = public_jwk();
    short["x"] = serde_json::json!("AAAA");
    refused(client(short), "a P-256 coordinate is 32 bytes");
    let mut no_keys = client(public_jwk());
    no_keys["jwks"]["keys"] = serde_json::json!([]);
    refused(no_keys, "a key is required");
    let mut no_redirect = client(public_jwk());
    no_redirect["redirect_uris"] = serde_json::json!([]);
    refused(no_redirect, "a redirect URI is required");
    let mut relative = client(public_jwk());
    relative["redirect_uris"] = serde_json::json!(["/cb"]);
    refused(relative, "a redirect URI is absolute");
    let mut fragment = client(public_jwk());
    fragment["redirect_uris"] = serde_json::json!(["https://client.example/cb#f"]);
    refused(fragment, "a redirect URI carries no fragment");
    let mut empty_id = client(public_jwk());
    empty_id["client_id"] = serde_json::json!("");
    refused(empty_id, "a client id is required");

    let twice: OauthAsCfg = serde_json::from_value(serde_json::json!({
        "issuer": "https://gw.example.com",
        "clients": [client(public_jwk()), client(public_jwk())],
    }))
    .expect("parses");
    assert!(
        matches!(AsIdentity::from_cfg(&twice), Err(AsCfgError::StaticClient { .. })),
        "two clients with one id is refused"
    );
}
