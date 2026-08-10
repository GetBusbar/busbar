// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! REGISTRATION IS NOT A GRANT. Adversarially, against a real server.
//!
//! Every test here drives `oauth_as::server::AuthorizationServer` built by the SAME code the boot
//! path builds it with — `super::super::plane::AsPlane::build` — rather than a hand-assembled
//! `ServerConfig` that could be configured more strictly than production is. A test that builds its
//! own subject proves something about the test.
//!
//! THREE OF THE FIVE were watched to FAIL against a permissive build before they were watched to
//! pass: `..._cannot_ask_for_more_than_the_default_grant`,
//! `with_no_default_grant_configured_...` and `..._names_itself_after_the_deployment_...`, driven
//! red by widening `RegistrationConfig::allowed_scopes` past the operator's ceiling and by removing
//! the impersonation refusal. The fourth, `..._cannot_ask_for_the_client_credentials_grant`, could
//! NOT be driven red; the limit that puts on what it proves is written at the test itself rather
//! than glossed over here.

use oauth_as::registration::{ClientMetadata, RegistrationFailure};

use crate::oauth_as::config::{AsIdentity, OauthAsCfg};
use crate::oauth_as::plane::AsPlane;

/// A plane with dynamic registration ON and the operator's ceiling set to `grant`.
fn plane(grant: &[&str]) -> AsPlane {
    let cfg = OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        dynamic_registration: true,
        default_grant: grant.iter().map(|s| (*s).to_string()).collect(),
        access_token_ttl_secs: None,
    };
    let identity = AsIdentity::from_cfg(&cfg).expect("a valid oauth_as block");
    AsPlane::build(
        identity,
        None,
        vec!["https://gw.example.com/mcp".to_string()],
    )
    .expect("the plane builds")
}

/// One registration request, with whatever `scope` and `grant_types` the attacker chose.
fn attempt(scope: Option<&str>, grant_types: Option<Vec<&str>>) -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["http://127.0.0.1:3000/callback".to_string()],
        token_endpoint_auth_method: Some("none".to_string()),
        grant_types: grant_types.map(|g| g.into_iter().map(str::to_string).collect::<Vec<_>>()),
        response_types: Some(vec!["code".to_string()]),
        client_name: Some("an agent".to_string()),
        scope: scope.map(str::to_string),
        software_statement: None,
    }
}

/// THE ESCALATION, ATTEMPTED. A client that registers itself and asks for more than the operator's
/// `default_grant` must be REFUSED — not quietly narrowed, and not issued a client it then believes
/// carries the scope it asked for.
#[tokio::test]
async fn a_self_registered_client_cannot_ask_for_more_than_the_default_grant() {
    let plane = plane(&["mcp:read"]);
    let refusal = plane
        .server()
        .register_dynamic_client(&attempt(Some("mcp:read mcp:write admin"), None), None)
        .await
        .expect_err(
            "registering with `admin` succeeded. A client that can name its own scope at \
             registration has converted \"I exist\" into \"I am authorised\", which is the whole \
             defect this plane was built not to have.",
        );
    assert!(
        matches!(refusal, RegistrationFailure::Invalid(_)),
        "expected `invalid_client_metadata`, got {refusal:?}"
    );
}

/// THE DEFAULT CEILING IS EMPTY, so an operator who turned registration on without deciding what a
/// registrant may reach has granted nothing. Any scope at all is refused.
#[tokio::test]
async fn with_no_default_grant_configured_every_requested_scope_is_refused() {
    let plane = plane(&[]);
    let refusal = plane
        .server()
        .register_dynamic_client(&attempt(Some("mcp:read"), None), None)
        .await
        .expect_err("an unconfigured ceiling admitted a scope");
    assert!(matches!(refusal, RegistrationFailure::Invalid(_)));
}

/// A REGISTRATION INSIDE THE CEILING SUCCEEDS. Without this, every test above would pass against a
/// server that refuses everything, which proves nothing about the ceiling and everything about the
/// endpoint being broken.
#[tokio::test]
async fn a_registration_within_the_default_grant_is_accepted() {
    let plane = plane(&["mcp:read"]);
    let info = plane
        .server()
        .register_dynamic_client(&attempt(Some("mcp:read"), None), None)
        .await
        .expect("a registration inside the operator's ceiling must succeed");
    assert!(!info.client_id.is_empty());
}

/// THE OTHER ESCALATION: not a wider scope, a different GRANT. `client_credentials` mints a token
/// with no resource owner in the loop at all, so a client that could register itself into it would
/// never need the consent screen. Refused.
///
/// **HONEST LIMIT ON WHAT THIS TEST PROVES.** It was NOT possible to drive it red. Against a build
/// whose `allowed_grant_types` included `ClientCredentials` — as a public client and again as a
/// confidential one — the registration was still refused, so `oauth-as` refuses this shape for at
/// least one further reason that this test does not isolate. What the test therefore establishes is
/// that the refusal HAPPENS, which is the property that matters at the boundary; it does NOT
/// establish that `allowed_grant_types` is what causes it, and it would keep passing if that list
/// were widened by mistake. Recorded here rather than left implied, because a test nobody has
/// watched fail is exactly what this project's standing rules call not-evidence.
#[tokio::test]
async fn a_self_registered_client_cannot_ask_for_the_client_credentials_grant() {
    let plane = plane(&["mcp:read"]);
    // A CONFIDENTIAL client, deliberately. `client_credentials` is a confidential-client grant, so
    // a registration presenting `token_endpoint_auth_method: none` is refused for being public
    // rather than for the grant it asked for — and a test refused for the wrong reason passes
    // against a server that has no ceiling at all. Watched: with `token_endpoint_auth_method: none`
    // this test PASSED against a build whose `allowed_grant_types` included `client_credentials`,
    // which is the "green about something it never tested" defect, caught by running it red.
    let mut metadata = attempt(Some("mcp:read"), Some(vec!["client_credentials"]));
    metadata.token_endpoint_auth_method = Some("client_secret_basic".to_string());
    let refusal = plane
        .server()
        .register_dynamic_client(&metadata, None)
        .await
        .expect_err(
            "registering for `client_credentials` succeeded, so a self-registered client can mint \
             a token with nobody's consent",
        );
    assert!(matches!(refusal, RegistrationFailure::Invalid(_)));
}

/// THE CONSENT SCREEN CANNOT BE MADE TO LIE. A registrant naming itself after the deployment is
/// refused by the policy, because the screen shows the client's identity and a user asked to approve
/// "busbar" cannot tell the gateway from a stranger who typed the word.
#[tokio::test]
async fn a_client_that_names_itself_after_the_deployment_is_refused() {
    let plane = plane(&["mcp:read"]);
    let mut metadata = attempt(Some("mcp:read"), None);
    metadata.client_name = Some("Busbar Gateway".to_string());
    let refusal = plane
        .server()
        .register_dynamic_client(&metadata, None)
        .await
        .expect_err("a client impersonating the deployment registered");
    assert!(matches!(refusal, RegistrationFailure::Unauthorized));
}

/// REGISTRATION IS ABSENT, NOT MERELY REFUSING, WHEN THE OPERATOR DID NOT TURN IT ON.
///
/// `oauth-as` derives its route table from the metadata document, so an unadvertised
/// `registration_endpoint` is an unrouted path — which is the difference between "this deployment
/// does not do dynamic registration" and "this deployment has an endpoint that says no".
#[tokio::test]
async fn registration_is_off_by_default() {
    let cfg = OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        dynamic_registration: false,
        default_grant: vec!["mcp:read".to_string()],
        access_token_ttl_secs: None,
    };
    let identity = AsIdentity::from_cfg(&cfg).expect("valid");
    assert!(
        identity.register_path().is_none(),
        "an unconfigured deployment derived a registration path"
    );
    let plane =
        AsPlane::build(identity, None, vec!["https://gw.example.com/mcp".into()]).expect("builds");
    assert!(
        plane.server().metadata().registration_endpoint.is_none(),
        "the metadata document advertises a registration endpoint nobody asked for"
    );
    let refusal = plane
        .server()
        .register_dynamic_client(&attempt(None, None), None)
        .await
        .expect_err("registration answered while disabled");
    assert!(matches!(refusal, RegistrationFailure::Disabled));
}
