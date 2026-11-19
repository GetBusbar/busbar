// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the authorization server answers a protected resource of this same deployment about an
//! access token: live only while its own store holds it, for the resource it was granted for.

use std::sync::Arc;

use base64::Engine as _;
use busbar_kernel::oauth_as::seam::AccessStanding;
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;
use oauth_as::store::Storage as _;

use crate::config::OauthAsCfg;

const ISSUER: &str = "https://as.example.com";
const RESOURCE: &str = "https://gw.example.com/mcp";
const OTHER_RESOURCE: &str = "https://gw.example.com/mcp-staging";
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ID: &str = "standing-test-client";

async fn plane() -> Arc<crate::plane::AsPlane> {
    let config = OauthAsCfg {
        issuer: ISSUER.into(),
        default_grant: vec!["read".into()],
        ..Default::default()
    };
    let block = busbar_contract::yaml::to_value(
        config.authoring(&busbar_kernel::test_hooks::tokens::seal()),
    )
    .expect("owner config serializes");
    let plane = crate::plane::seam_build::<crate::NoConnections>(
        block,
        Vec::new(),
        vec![RESOURCE.to_string(), OTHER_RESOURCE.to_string()],
        None,
        crate::testkit::memory_store().await,
        crate::testkit::ADMIN_ORIGIN.to_string(),
    )
    .await
    .expect("the owner seam builds over the store")
    .downcast::<crate::plane::AsPlane>()
    .unwrap_or_else(|_| panic!("the owner seam returns its plane"));
    let scope = ScopeSet::parse("read").expect("scope");
    plane
        .server()
        .register_client(Client {
            client_id: ClientId::new(CLIENT_ID),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.into()],
            allowed_scopes: scope.clone(),
            default_scopes: scope,
            name: None,
            registration: None,
        })
        .await
        .expect("the store registers the client");
    plane
}

/// An access token granted for `resource` (RFC 8707), or for none.
async fn token(plane: &crate::plane::AsPlane, resource: Option<&str>) -> String {
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    if let Some(resource) = resource {
        pairs.push(("resource", resource));
    }
    let request = oauth_as::authorization::AuthorizationRequest::from_pairs(pairs);
    let validated = plane
        .server()
        .validate_authorization_request(&request)
        .await
        .expect("request validates");
    let code = plane
        .server()
        .issue_authorization_code(oauth_as::server::UserApproval::granted(
            &validated,
            "busbar-operator",
        ))
        .await
        .expect("the approved request mints a code");
    plane
        .server()
        .token(oauth_as::server::TokenRequest::AuthorizationCode {
            client_id: ClientId::new(CLIENT_ID),
            client_secret: None,
            code: code.code,
            redirect_uri: Some(REDIRECT_URI.into()),
            code_verifier: Some(VERIFIER.into()),
        })
        .await
        .expect("the approved code exchanges")
        .access_token
}

#[tokio::test]
async fn a_token_is_live_only_on_the_resource_it_was_granted_for() {
    let plane = plane().await;
    let access = token(&plane, Some(RESOURCE)).await;
    assert_eq!(
        plane.access_standing(&access, RESOURCE).await,
        AccessStanding::Live
    );
    assert_eq!(
        plane.access_standing(&access, OTHER_RESOURCE).await,
        AccessStanding::Dead,
        "a token for one protected resource is dead on another of the same deployment"
    );
    assert_eq!(
        plane
            .access_standing(&access, "https://gw.example.com/mcp/")
            .await,
        AccessStanding::Dead,
        "a resource indicator is compared for equality"
    );
}

#[tokio::test]
async fn a_revoked_token_is_dead_at_once() {
    let plane = plane().await;
    let access = token(&plane, Some(RESOURCE)).await;
    assert_eq!(
        plane.access_standing(&access, RESOURCE).await,
        AccessStanding::Live
    );
    plane
        .server()
        .store()
        .delete_token(&access)
        .await
        .expect("revocation removes the record");
    assert_eq!(
        plane.access_standing(&access, RESOURCE).await,
        AccessStanding::Dead,
        "its signature and expiry are unchanged; its issuer no longer holds it"
    );
}

#[tokio::test]
async fn a_token_that_names_this_issuer_and_was_never_issued_is_dead() {
    let plane = plane().await;
    let access = token(&plane, Some(RESOURCE)).await;
    // The issued token with one byte of its signature changed: it still names this issuer.
    let mut forged = access.clone();
    let last = forged.pop().expect("a token is not empty");
    forged.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(
        plane.access_standing(&forged, RESOURCE).await,
        AccessStanding::Dead
    );
}

#[tokio::test]
async fn a_token_of_another_issuer_is_not_this_servers_to_judge() {
    let plane = plane().await;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let foreign = format!(
        "{}.{}.{}",
        b64.encode(br#"{"alg":"ES256","typ":"at+jwt"}"#),
        b64.encode(
            format!(r#"{{"iss":"https://idp.example.com","aud":"{RESOURCE}","sub":"u"}}"#)
                .as_bytes()
        ),
        b64.encode(b"signature"),
    );
    assert_eq!(
        plane.access_standing(&foreign, RESOURCE).await,
        AccessStanding::NotMine
    );
    assert_eq!(
        plane
            .access_standing("opaque-reference-token", RESOURCE)
            .await,
        AccessStanding::NotMine,
        "not a JWT: this server mints only JWTs, and the audience check refuses it elsewhere"
    );
}

#[tokio::test]
async fn a_grant_that_named_no_resource_stands_on_the_signed_audience_alone() {
    let plane = plane().await;
    let access = token(&plane, None).await;
    // Its signed `aud` is the deployment's standing audience, judged for equality by the
    // resource before this is asked; the record narrows nothing.
    assert_eq!(
        plane.access_standing(&access, RESOURCE).await,
        AccessStanding::Live
    );
}
