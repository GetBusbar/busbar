// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId, SecretHash};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;
use oauth_as::store::Storage as _;
use serde_json::Value;

use crate::flow_tests::{send, serve_with_admin_chain, Jar};
use crate::testkit::oauth_as_plane;

const CLIENT: &str = "operator-device-client";
const SECRET: &str = "device-client-secret-for-test";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

async fn setup() -> (String, Arc<busbar_kernel::state::App>, reqwest::Client) {
    let (origin, app) = serve_with_admin_chain(Vec::new()).await;
    let scope = ScopeSet::from_tokens(["read"]).unwrap();
    oauth_as_plane(&app)
        .unwrap()
        .server()
        .register_client(Client {
            client_id: ClientId::new(CLIENT),
            auth: ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::sha256(SECRET),
            },
            grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
            redirect_uris: Vec::new(),
            allowed_scopes: scope.clone(),
            default_scopes: scope,
            name: Some("Operator provisioned device".to_string()),
            registration: None,
        })
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (origin, app, client)
}

async fn start(client: &reqwest::Client, origin: &str) -> Value {
    let response = client
        .post(format!("{origin}/device_authorization"))
        .form(&[
            ("client_id", CLIENT),
            ("client_secret", SECRET),
            ("scope", "read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let grant: Value = response.json().await.unwrap();
    assert_eq!(grant["verification_uri"], format!("{origin}/device"));
    assert!(grant["device_code"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(grant["user_code"].as_str().is_some_and(|s| !s.is_empty()));
    grant
}

fn csrf(page: &str) -> String {
    let after = page
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .expect("the authenticated form carries a CSRF token");
    after.split('"').next().unwrap().to_string()
}

async fn screen(client: &reqwest::Client, jar: &mut Jar, origin: &str, grant: &Value) -> String {
    let target = format!(
        "{origin}/device?user_code={}",
        grant["user_code"].as_str().unwrap()
    );
    let (status, _, page) = send(client, jar, reqwest::Method::GET, &target, None).await;
    assert_eq!(status, 200, "{page}");
    assert!(
        page.contains(CLIENT) && page.contains("read"),
        "the operator must see the client and scope: {page}"
    );
    csrf(&page)
}

async fn submit(
    client: &reqwest::Client,
    jar: &mut Jar,
    origin: &str,
    grant: &Value,
    token: &str,
    action: &str,
    request_origin: &str,
) -> (reqwest::StatusCode, String) {
    let mut request = client
        .post(format!("{origin}/device"))
        .header(reqwest::header::ORIGIN, request_origin)
        .form(&[
            ("user_code", grant["user_code"].as_str().unwrap()),
            ("csrf_token", token),
            ("action", action),
        ]);
    if let Some(cookie) = jar.header_for("/device") {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let response = request.send().await.unwrap();
    for cookie in response.headers().get_all(reqwest::header::SET_COOKIE) {
        jar.store(cookie.to_str().unwrap(), "/device");
    }
    let status = response.status();
    (status, response.text().await.unwrap())
}

async fn poll(
    client: &reqwest::Client,
    origin: &str,
    grant: &Value,
) -> (reqwest::StatusCode, Value) {
    let response = client
        .post(format!("{origin}/token"))
        .form(&[
            ("grant_type", DEVICE_GRANT),
            ("device_code", grant["device_code"].as_str().unwrap()),
            ("client_id", CLIENT),
            ("client_secret", SECRET),
        ])
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

#[tokio::test]
async fn advertised_device_flow_requires_confirmation_mints_and_revokes() {
    let (origin, app, client) = setup().await;
    let meta: Value = client
        .get(format!("{origin}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        meta["device_authorization_endpoint"],
        format!("{origin}/device_authorization")
    );
    assert_eq!(meta["revocation_endpoint"], format!("{origin}/revoke"));

    let undecided = start(&client, &origin).await;
    assert_eq!(
        poll(&client, &origin, &undecided).await.1["error"],
        "authorization_pending"
    );

    let grant = start(&client, &origin).await;
    let mut jar = Jar::new(false);
    let token = screen(&client, &mut jar, &origin, &grant).await;
    assert!(jar.header_for("/token").is_none());
    assert!(jar.header_for("/revoke").is_none());
    let (status, page) = submit(
        &client, &mut jar, &origin, &grant, &token, "approve", &origin,
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Approved."), "{page}");
    let (status, tokens) = poll(&client, &origin, &grant).await;
    assert_eq!(status, 200, "{tokens}");
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let server = oauth_as_plane(&app).unwrap();
    assert!(server
        .server()
        .store()
        .get_token(access)
        .await
        .unwrap()
        .is_some());
    assert!(server
        .server()
        .store()
        .get_refresh_token(refresh)
        .await
        .unwrap()
        .is_some());

    let wrong = client
        .post(format!("{origin}/revoke"))
        .form(&[
            ("client_id", CLIENT),
            ("client_secret", "wrong"),
            ("token", refresh),
        ])
        .send()
        .await
        .unwrap();
    assert!(wrong.status().is_client_error());
    assert!(server
        .server()
        .store()
        .get_refresh_token(refresh)
        .await
        .unwrap()
        .is_some());
    let revoked = client
        .post(format!("{origin}/revoke"))
        .form(&[
            ("client_id", CLIENT),
            ("client_secret", SECRET),
            ("token", refresh),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);
    assert!(revoked.bytes().await.unwrap().is_empty());
    assert!(server
        .server()
        .store()
        .get_refresh_token(refresh)
        .await
        .unwrap()
        .is_none());
    assert!(
        server
            .server()
            .store()
            .get_token(access)
            .await
            .unwrap()
            .is_none(),
        "refresh revocation cascades to the grant's access token"
    );
    let retry = client
        .post(format!("{origin}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            ("client_secret", SECRET),
            ("refresh_token", refresh),
        ])
        .send()
        .await
        .unwrap();
    assert!(retry.status().is_client_error());
    let retry: Value = retry.json().await.unwrap();
    assert_eq!(retry["error"], "invalid_grant");
    let unknown = client
        .post(format!("{origin}/revoke"))
        .form(&[
            ("client_id", CLIENT),
            ("client_secret", SECRET),
            ("token", "unknown-token"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown.status(),
        200,
        "RFC 7009 does not disclose token existence"
    );
    assert!(unknown.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn device_forms_refuse_missing_forged_replayed_and_cross_origin_csrf_and_allow_deny() {
    let (origin, _app, client) = setup().await;
    for attack in ["missing", "forged", "cross-origin", "replay"] {
        let grant = start(&client, &origin).await;
        let mut jar = Jar::new(false);
        let token = screen(&client, &mut jar, &origin, &grant).await;
        let submitted = match attack {
            "missing" => "",
            "forged" => "not-issued",
            _ => &token,
        };
        let request_origin = if attack == "cross-origin" {
            "https://attacker.example"
        } else {
            &origin
        };
        if attack == "replay" {
            assert_eq!(
                submit(&client, &mut jar, &origin, &grant, &token, "", &origin)
                    .await
                    .0,
                200
            );
        }
        let (status, page) = submit(
            &client,
            &mut jar,
            &origin,
            &grant,
            submitted,
            "approve",
            request_origin,
        )
        .await;
        assert_eq!(status, 403, "{attack}: {page}");
        assert_eq!(
            poll(&client, &origin, &grant).await.1["error"],
            "authorization_pending"
        );
    }
    let grant = start(&client, &origin).await;
    let mut jar = Jar::new(false);
    let token = screen(&client, &mut jar, &origin, &grant).await;
    let (status, page) = submit(&client, &mut jar, &origin, &grant, &token, "deny", &origin).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("denied"), "{page}");
    assert_eq!(
        poll(&client, &origin, &grant).await.1["error"],
        "access_denied"
    );
}

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

fn build_owner(identity: crate::config::AsIdentity) -> Result<crate::plane::AsPlane, String> {
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
