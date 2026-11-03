// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId, SecretHash};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;
use oauth_as::store::Storage as _;

const CLIENT: &str = "operator-device-client";
const SECRET: &str = "device-client-secret-for-test";

#[tokio::test]
async fn device_csrf_is_shared_and_spent_once_across_fresh_nodes() {
    let store = crate::testkit::store_calls();
    let build = || {
        let identity = crate::config::AsIdentity::from_cfg(&crate::config::OauthAsCfg {
            issuer: "https://as.example".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::plane::AsPlane::build_carrying(
            identity,
            None,
            Vec::new(),
            crate::cimd::unconnected(),
            Arc::new(crate::plane::Carried::over(Some(Arc::clone(&store)))),
        )
        .unwrap()
    };
    let first = build();
    first
        .issue_device_form("session-a", "csrf-a", "operator")
        .await
        .unwrap();
    let second = build();
    assert!(!second
        .consume_device_form("session-b", "csrf-a", "operator")
        .await
        .unwrap());
    assert!(!second
        .consume_device_form("session-a", "forged", "operator")
        .await
        .unwrap());
    assert!(!second
        .consume_device_form("session-a", "csrf-a", "someone-else")
        .await
        .unwrap());
    assert!(second
        .consume_device_form("session-a", "csrf-a", "operator")
        .await
        .unwrap());
    assert!(!first
        .consume_device_form("session-a", "csrf-a", "operator")
        .await
        .unwrap());
}

#[tokio::test]
async fn only_explicit_operator_device_clients_can_omit_redirects_and_use_device_grants() {
    let mut cfg: crate::config::OauthAsCfg = serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example/tenant",
        "clients": [{
            "client_id": "configured-device",
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }] }
        }]
    }))
    .unwrap();
    assert!(
        !cfg.clients[0].device_authorization,
        "no implicit permission upgrade"
    );
    assert!(crate::config::AsIdentity::from_cfg(&cfg).is_err());
    cfg.clients[0].device_authorization = true;
    let identity = crate::config::AsIdentity::from_cfg(&cfg).unwrap();
    assert_eq!(
        identity.device_authorization_path(),
        "/tenant/device_authorization"
    );
    assert_eq!(identity.verification_path(), "/tenant/device");
    assert_eq!(identity.revocation_path(), "/tenant/revoke");
    let plane = build_owner(identity).unwrap();
    let client = plane
        .server()
        .store()
        .get_client(&ClientId::new("configured-device"))
        .await
        .unwrap()
        .unwrap();
    assert!(client.grant_types.contains(&GrantType::DeviceCode));
    assert!(client.grant_types.contains(&GrantType::RefreshToken));
    assert!(!client.grant_types.contains(&GrantType::AuthorizationCode));

    cfg.clients[0].device_authorization = false;
    cfg.clients[0].redirect_uris = vec!["https://client.example/cb".to_string()];
    let plane = build_owner(crate::config::AsIdentity::from_cfg(&cfg).unwrap()).unwrap();
    let client = plane
        .server()
        .store()
        .get_client(&ClientId::new("configured-device"))
        .await
        .unwrap()
        .unwrap();
    assert!(client.grant_types.contains(&GrantType::AuthorizationCode));
    assert!(!client.grant_types.contains(&GrantType::DeviceCode));
}

fn build_owner(
    identity: crate::config::AsIdentity,
) -> Result<crate::plane::AsPlane, crate::plane::AsBuildError> {
    crate::plane::AsPlane::build_carrying(
        identity,
        None,
        Vec::new(),
        crate::cimd::unconnected(),
        Arc::new(crate::plane::Carried::over(Some(
            crate::testkit::store_calls(),
        ))),
    )
}

#[tokio::test]
async fn confidential_secret_device_tokens_retain_their_records_and_revoke_the_whole_grant() {
    use oauth_as::server::TokenRequest;
    let identity = crate::config::AsIdentity::from_cfg(&crate::config::OauthAsCfg {
        issuer: "https://as.example".into(),
        default_grant: vec!["read".into()],
        ..Default::default()
    })
    .unwrap();
    let plane = build_owner(identity).unwrap();
    let server = plane.server();
    let scope = ScopeSet::from_tokens(["read"]).unwrap();
    server
        .register_client(Client {
            client_id: ClientId::new(CLIENT),
            auth: ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::sha256(SECRET),
            },
            grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
            redirect_uris: Vec::new(),
            allowed_scopes: scope.clone(),
            default_scopes: scope.clone(),
            name: Some("Operator provisioned device".into()),
            registration: None,
        })
        .await
        .unwrap();
    let grant = server
        .device_authorization(&ClientId::new(CLIENT), Some(SECRET), Some(&scope))
        .await
        .unwrap();
    server
        .approve_device(&grant.user_code, "busbar-operator")
        .await
        .unwrap();
    let tokens = server
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new(CLIENT),
            client_secret: Some(SECRET.into()),
            device_code: grant.device_code,
        })
        .await
        .unwrap();
    let access = tokens.access_token;
    let refresh = tokens.refresh_token.unwrap();
    assert!(server.store().get_token(&access).await.unwrap().is_some());
    assert!(server
        .store()
        .get_refresh_token(&refresh)
        .await
        .unwrap()
        .is_some());
    assert!(server
        .revoke(&ClientId::new(CLIENT), Some("wrong"), &refresh, None)
        .await
        .is_err());
    assert!(server
        .store()
        .get_refresh_token(&refresh)
        .await
        .unwrap()
        .is_some());
    server
        .revoke(&ClientId::new(CLIENT), Some(SECRET), &refresh, None)
        .await
        .unwrap();
    assert!(server
        .store()
        .get_refresh_token(&refresh)
        .await
        .unwrap()
        .is_none());
    assert!(
        server.store().get_token(&access).await.unwrap().is_none(),
        "refresh revocation cascades to the grant's access token"
    );
    let retry = server
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new(CLIENT),
            client_secret: Some(SECRET.into()),
            refresh_token: refresh,
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(retry.error, oauth_as::ErrorCode::InvalidGrant);
    server
        .revoke(&ClientId::new(CLIENT), Some(SECRET), "unknown-token", None)
        .await
        .unwrap();
}
