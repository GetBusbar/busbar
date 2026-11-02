// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::{AsCfgError, AsIdentity, OauthAsCfg, StaticClientCfg};

fn cfg(issuer: &str) -> OauthAsCfg {
    OauthAsCfg {
        issuer: issuer.to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    }
}

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

#[test]
fn a_default_grant_entry_that_is_not_a_scope_token_is_refused_at_boot() {
    let mut c = cfg("https://gw.example.com");
    c.default_grant = vec!["tools:read".into(), "not a token".into()];
    assert!(matches!(
        AsIdentity::from_cfg(&c),
        Err(AsCfgError::ScopeNotAToken(_))
    ));
}

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

#[test]
fn fapi2_true_turns_the_posture_on() {
    let written: OauthAsCfg = serde_json::from_value(serde_json::json!({
        "issuer": "https://gw.example.com",
        "fapi2": true,
    }))
    .expect("a block naming fapi2 parses");
    assert!(AsIdentity::from_cfg(&written).expect("valid").fapi2());
}

#[test]
fn the_par_endpoint_is_derived_under_the_issuer() {
    let id = AsIdentity::from_cfg(&cfg("https://gw.example.com/tenant1")).expect("valid");
    assert_eq!(id.par_path(), "/tenant1/par");
    assert_eq!(id.par_endpoint(), "https://gw.example.com/tenant1/par");
    let root = AsIdentity::from_cfg(&cfg("https://gw.example.com")).expect("valid");
    assert_eq!(root.par_path(), "/par");
}

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

#[test]
fn no_static_client_is_declared_unless_the_block_lists_one() {
    let written: OauthAsCfg =
        serde_json::from_value(serde_json::json!({ "issuer": "https://gw.example.com" }))
            .expect("parses");
    assert!(written.clients.is_empty());
    assert!(AsIdentity::from_cfg(&written)
        .expect("valid")
        .clients
        .is_empty());
}

#[test]
fn a_static_private_key_jwt_client_with_a_public_jwk_validates() {
    let id = with_client(client(public_jwk())).expect("a well-formed static client validates");
    let clients: &[StaticClientCfg] = &id.clients;
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].client_id, "fapi-client");
    assert_eq!(
        clients[0].jwks.keys[0].x.as_deref(),
        public_jwk()["x"].as_str()
    );
}

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
        matches!(
            AsIdentity::from_cfg(&twice),
            Err(AsCfgError::StaticClient { .. })
        ),
        "two clients with one id is refused"
    );
}

fn modulus(bytes: usize) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        vec![0xC5u8; bytes],
    )
}

fn rsa_jwk() -> serde_json::Value {
    serde_json::json!({ "kty": "RSA", "kid": "r1", "use": "sig", "alg": "PS256", "n": modulus(256), "e": "AQAB" })
}

#[test]
fn a_static_ps256_client_with_an_rsa_public_jwk_validates() {
    let id = with_client(client(rsa_jwk())).expect("a 2048-bit RSA public JWK for PS256 validates");
    assert_eq!(id.clients[0].jwks.keys[0].kty, "RSA");
    let mut no_alg = rsa_jwk();
    no_alg.as_object_mut().unwrap().remove("alg");
    with_client(client(no_alg)).expect("an RSA key with no `alg` is PS256");
}

#[test]
fn a_malformed_rsa_static_client_is_refused_at_boot() {
    let refused = |c: serde_json::Value, why: &str| match with_client(c) {
        Err(AsCfgError::StaticClient { .. }) => {}
        other => panic!("{why}: expected a StaticClient refusal, got {other:?}"),
    };
    let mut private = rsa_jwk();
    private["d"] = serde_json::json!(modulus(256));
    refused(client(private), "a private key must never be configured");
    let mut weak = rsa_jwk();
    weak["n"] = serde_json::json!(modulus(128));
    refused(client(weak), "a modulus under 2048 bits");
    let mut rs256 = rsa_jwk();
    rs256["alg"] = serde_json::json!("RS256");
    refused(client(rs256), "PS256 only, never RS256");
    let mut no_e = rsa_jwk();
    no_e.as_object_mut().unwrap().remove("e");
    refused(client(no_e), "an RSA key carries `e`");
    let mut mixed = client(rsa_jwk());
    mixed["jwks"]["keys"] = serde_json::json!([rsa_jwk(), public_jwk()]);
    refused(mixed, "one client, one algorithm");
}

fn resolve_block(block: serde_json::Value) -> Result<busbar_kernel::config::RootCfg, Vec<String>> {
    crate::testkit::install_test_seam();
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "oauth_as": block,
    }))
    .expect("the document parses: the block is opaque to the kernel's own parse");
    busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
}

#[test]
fn an_invalid_block_is_refused_at_resolve_with_this_crates_text() {
    let refused = resolve_block(serde_json::json!({ "issuer": "https://gw.example.com/" }))
        .expect_err("a trailing slash must refuse the whole config");
    assert_eq!(
        refused,
        vec![AsCfgError::IssuerHasTrailingSlash("https://gw.example.com/".into()).to_string()]
    );
    let refused = resolve_block(serde_json::json!({ "issuer": "" })).expect_err("empty issuer");
    assert_eq!(refused, vec![AsCfgError::MissingIssuer.to_string()]);
}

#[test]
fn an_unknown_key_in_the_block_is_refused_at_resolve() {
    let refused = resolve_block(serde_json::json!({
        "issuer": "https://gw.example.com",
        "not_a_key": true,
    }))
    .expect_err("deny_unknown_fields must hold in the owner's parse");
    assert_eq!(refused.len(), 1);
    assert!(
        refused[0].starts_with("oauth_as: ") && refused[0].contains("not_a_key"),
        "{refused:?}"
    );
}

#[test]
fn the_signing_key_reference_is_listed_for_the_kernel_to_resolve() {
    let resolved = resolve_block(serde_json::json!({
        "issuer": "https://gw.example.com",
        "signing_key": { "env": "AS_SIGNING_KEY" },
    }))
    .expect("valid");
    let checked = resolved.oauth_as.expect("accepted");
    let paths: Vec<&str> = checked
        .secret_refs
        .iter()
        .map(|(p, _)| p.as_str())
        .collect();
    assert_eq!(paths, ["oauth_as.signing_key"]);

    let resolved =
        resolve_block(serde_json::json!({ "issuer": "https://gw.example.com" })).expect("valid");
    assert!(resolved.oauth_as.expect("accepted").secret_refs.is_empty());
}

#[test]
fn a_refresh_chain_has_a_bounded_lifetime() {
    let plain: crate::config::OauthAsCfg =
        serde_json::from_value(serde_json::json!({"issuer": "https://as.example.com"}))
            .expect("parses");
    let plane = crate::plane::AsPlane::build(
        crate::config::AsIdentity::from_cfg(&plain).expect("valid"),
        None,
        Vec::new(),
        crate::cimd::unconnected(),
    )
    .expect("builds");
    assert_eq!(
        plane.server().config().refresh_token_ttl,
        Some(std::time::Duration::from_secs(30 * 24 * 60 * 60)),
        "absent, a refresh chain lives thirty days"
    );

    let written: crate::config::OauthAsCfg = serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example.com",
        "refresh_token_ttl_secs": 3600,
    }))
    .expect("the refresh lifetime is a key of the block");
    let plane = crate::plane::AsPlane::build(
        crate::config::AsIdentity::from_cfg(&written).expect("valid"),
        None,
        Vec::new(),
        crate::cimd::unconnected(),
    )
    .expect("builds");
    assert_eq!(
        plane.server().config().refresh_token_ttl,
        Some(std::time::Duration::from_secs(3600))
    );
}

#[test]
fn a_token_lifetime_out_of_range_is_refused() {
    for (key, secs) in [
        ("access_token_ttl_secs", 0_u64),
        ("access_token_ttl_secs", 24 * 60 * 60 + 1),
        ("access_token_ttl_secs", u64::MAX),
        ("refresh_token_ttl_secs", 0),
        ("refresh_token_ttl_secs", 365 * 24 * 60 * 60 + 1),
    ] {
        let mut block = serde_json::Map::new();
        block.insert("issuer".into(), "https://as.example.com".into());
        block.insert(key.into(), secs.into());
        let cfg: Result<crate::config::OauthAsCfg, _> =
            serde_json::from_value(serde_json::Value::Object(block));
        let refused = cfg.map(|cfg| crate::config::AsIdentity::from_cfg(&cfg).is_err());
        assert!(
            matches!(refused, Ok(true)),
            "{key}: {secs} is refused at boot"
        );
    }
}

#[test]
fn an_absolute_url_split_differently_by_the_dialling_stack_is_refused_at_boot() {
    for bad in [
        "https://as.example\\@evil.example",
        "https://\\@evil.example/as",
    ] {
        assert!(
            matches!(
                AsIdentity::from_cfg(&cfg(bad)),
                Err(AsCfgError::IssuerNotAbsolute(_))
            ),
            "{bad}"
        );
    }
    for bad in [
        "https://client.example\\@evil.example/cb",
        "https://\\@evil.example/cb",
    ] {
        let mut c = client(public_jwk());
        c["redirect_uris"] = serde_json::json!([bad]);
        assert!(
            matches!(with_client(c), Err(AsCfgError::StaticClient { .. })),
            "{bad}"
        );
    }
}
