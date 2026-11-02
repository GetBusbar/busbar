// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use oauth_as::registration::{ClientMetadata, RegistrationFailure};

use crate::config::{AsIdentity, OauthAsCfg};

use crate::plane::AsPlane;

fn plane(grant: &[&str]) -> AsPlane {
    let cfg = OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: grant.iter().map(|s| (*s).to_string()).collect(),
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    };
    let identity = AsIdentity::from_cfg(&cfg).expect("a valid oauth_as block");
    AsPlane::build(
        identity,
        None,
        vec!["https://gw.example.com/rpc".to_string()],
        crate::cimd::unconnected(),
    )
    .expect("the plane builds")
}

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

#[tokio::test]
async fn a_self_registered_client_cannot_ask_for_more_than_the_default_grant() {
    let plane = plane(&["tools:read"]);
    let refusal = plane
        .server()
        .register_dynamic_client(&attempt(Some("tools:read tools:write admin"), None), None)
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

#[tokio::test]
async fn with_no_default_grant_configured_every_requested_scope_is_refused() {
    let plane = plane(&[]);
    let refusal = plane
        .server()
        .register_dynamic_client(&attempt(Some("tools:read"), None), None)
        .await
        .expect_err("an unconfigured ceiling admitted a scope");
    assert!(matches!(refusal, RegistrationFailure::Invalid(_)));
}

#[tokio::test]
async fn a_registration_within_the_default_grant_is_accepted() {
    let plane = plane(&["tools:read"]);
    let info = plane
        .server()
        .register_dynamic_client(&attempt(Some("tools:read"), None), None)
        .await
        .expect("a registration inside the operator's ceiling must succeed");
    assert!(!info.client_id.is_empty());
}

#[tokio::test]
async fn a_self_registered_client_cannot_ask_for_the_client_credentials_grant() {
    let plane = plane(&["tools:read"]);

    let mut metadata = attempt(Some("tools:read"), Some(vec!["client_credentials"]));
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

#[tokio::test]
async fn a_client_that_names_itself_after_the_deployment_is_refused() {
    let plane = plane(&["tools:read"]);
    let mut metadata = attempt(Some("tools:read"), None);
    metadata.client_name = Some("Busbar Gateway".to_string());
    let refusal = plane
        .server()
        .register_dynamic_client(&metadata, None)
        .await
        .expect_err("a client impersonating the deployment registered");
    assert!(matches!(refusal, RegistrationFailure::Unauthorized));
}

#[tokio::test]
async fn registration_is_on_whenever_the_plane_is() {
    let cfg = OauthAsCfg {
        issuer: "https://gw.example.com".to_string(),
        signing_key: None,
        key_id: None,
        default_grant: vec!["tools:read".to_string()],
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    };
    let identity = AsIdentity::from_cfg(&cfg).expect("valid");
    assert_eq!(
        identity.register_path(),
        "/register",
        "every validated identity derives the registration path; there is nothing to switch"
    );
    let plane = AsPlane::build(
        identity,
        None,
        vec!["https://gw.example.com/rpc".into()],
        crate::cimd::unconnected(),
    )
    .expect("builds");
    assert_eq!(
        plane.server().metadata().registration_endpoint.as_deref(),
        Some("https://gw.example.com/register"),
        "the metadata document must advertise the endpoint, or `oauth-as` will not route it"
    );
    plane
        .server()
        .register_dynamic_client(&attempt(None, None), None)
        .await
        .expect("registration is one of the three always-on mechanisms and must admit a client");
}

#[tokio::test]
async fn open_registration_is_throttled() {
    let plane = plane(&[]);
    for n in 0..oauth_as::rate_limit::DEFAULT_CLIENT_REGISTRATION_CAPACITY {
        plane
            .server()
            .register_dynamic_client(&attempt(None, None), None)
            .await
            .unwrap_or_else(|e| panic!("registration {n} inside the budget was refused: {e:?}"));
    }
    let refused = plane
        .server()
        .register_dynamic_client(&attempt(None, None), None)
        .await
        .expect_err("a registration past the budget was admitted");
    assert!(
        matches!(refused, RegistrationFailure::Unauthorized),
        "expected the throttle's refusal, got {refused:?}"
    );
}

#[tokio::test]
async fn an_idle_self_registered_client_is_reclaimed_and_a_busy_one_kept() {
    use oauth_as::client::ClientId;
    use oauth_as::store::Storage as _;
    async fn register(plane: &AsPlane) -> ClientId {
        ClientId::new(
            plane
                .server()
                .register_dynamic_client(&attempt(None, None), None)
                .await
                .expect("registers")
                .client_id,
        )
    }
    let plane = plane(&[]);
    let store = plane.server().store();
    let idle = register(&plane).await;
    let busy = register(&plane).await;
    let now = std::time::SystemTime::now();
    let past_idle =
        now + crate::policy::REGISTERED_CLIENT_IDLE + std::time::Duration::from_secs(60);
    let mut refresh = oauth_as::token::RefreshTokenRecord::new(
        "rt-busy",
        busy.clone(),
        Some("busbar-operator".to_string()),
        oauth_as::scope::ScopeSet::default(),
        "fam-busy",
    );
    refresh.expires_at = Some(past_idle + crate::policy::REGISTERED_CLIENT_IDLE);
    let _ = store
        .put_refresh_token(refresh)
        .await
        .expect("issues a refresh token");
    let provisioned = oauth_as::client::Client {
        client_id: ClientId::new("operator-made"),
        auth: oauth_as::client::ClientAuth::Public,
        grant_types: vec![oauth_as::grant::GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example.com/cb".to_string()],
        allowed_scopes: oauth_as::scope::ScopeSet::default(),
        default_scopes: oauth_as::scope::ScopeSet::default(),
        name: None,
        registration: None,
    };
    store.put_client(provisioned).await.expect("stores");

    store.sweep_expired(past_idle).await.expect("sweeps");
    assert!(
        store.get_client(&idle).await.expect("reads").is_none(),
        "an idle self-registered client was kept"
    );
    assert!(
        store.get_client(&busy).await.expect("reads").is_some(),
        "a self-registered client holding a live refresh token was reclaimed"
    );
    assert!(
        store
            .get_client(&ClientId::new("operator-made"))
            .await
            .expect("reads")
            .is_some(),
        "a client nobody registered was reclaimed"
    );
}
