// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    application_with_resource_auth_at,
    browser::{send, Jar},
};
use base64::Engine as _;
use busbar_contract::crypto::ecdsa_p256;
use busbar_contract::json::{self, JsonValueTrait as _, Value};
use busbar_core_oauth2::config::{OauthAsCfg, StaticClientCfg, StaticClientJwk, StaticClientJwks};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const CLIENT: &str = "operator-device-client";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

struct Key(ecdsa_p256::KeyPair);
impl Key {
    fn new() -> Self {
        let pkcs8 = ecdsa_p256::generate_pkcs8().unwrap();
        Self(ecdsa_p256::from_pkcs8(&pkcs8).unwrap())
    }
    fn jwk(&self) -> StaticClientJwk {
        let point = &self.0.public_key();
        StaticClientJwk {
            kty: "EC".into(),
            crv: Some("P-256".into()),
            x: Some(B64.encode(&point[1..33])),
            y: Some(B64.encode(&point[33..65])),
            n: None,
            e: None,
            kid: Some("device-key".into()),
            alg: Some("ES256".into()),
            d: None,
        }
    }
    fn assertion(&self, issuer: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = B64.encode(json::json!({"alg":"ES256","kid":"device-key"}).to_string());
        let claims = B64.encode(
            json::json!({"iss":CLIENT,"sub":CLIENT,"aud":issuer,"iat":now,"exp":now+60,
            "jti":format!("device-{now}-{}",NEXT.fetch_add(1,Ordering::Relaxed))})
            .to_string(),
        );
        let input = format!("{header}.{claims}");
        let signature = self.0.sign_fixed(input.as_bytes()).unwrap();
        format!("{input}.{}", B64.encode(signature))
    }
}

struct Subject {
    origin: String,
    /// The admin listener's origin, where the operator's approval page lives.
    admin: String,
    app: Arc<busbar_kernel::state::App>,
    client: super::Client,
    key: Key,
}

async fn setup() -> Subject {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (admin_listener, admin_listen) = super::bind_admin().await;
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let key = Key::new();
    let config = OauthAsCfg {
        issuer: origin.clone(),
        default_grant: vec!["read".into()],
        clients: vec![StaticClientCfg {
            device_authorization: true,
            client_id: CLIENT.into(),
            redirect_uris: Vec::new(),
            jwks: StaticClientJwks {
                keys: vec![key.jwk()],
            },
        }],
        ..Default::default()
    };
    let app = application_with_resource_auth_at(Some(&config), true, &admin_listen).await;
    super::serve_split(Arc::clone(&app), listener, admin_listener, true);
    Subject {
        origin,
        admin: format!("http://{admin_listen}"),
        app,
        client: super::client(),
        key,
    }
}

fn credentials(subject: &Subject, key: &Key) -> Vec<(&'static str, String)> {
    vec![
        ("client_id", CLIENT.into()),
        ("client_assertion_type", ASSERTION_TYPE.into()),
        ("client_assertion", key.assertion(&subject.origin)),
    ]
}

async fn start(subject: &Subject) -> Value {
    let mut form = credentials(subject, &subject.key);
    form.push(("scope", "read".into()));
    let response = subject
        .client
        .post(format!("{}/device_authorization", subject.origin))
        .form(&form)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let grant: Value = super::read_json(response).await;
    assert_eq!(status, 200, "{grant}");
    assert_eq!(
        grant["verification_uri"],
        format!("{}/oauth/device", subject.admin)
    );
    assert!(grant["device_code"]
        .as_str()
        .is_some_and(|code| !code.is_empty()));
    assert!(grant["user_code"]
        .as_str()
        .is_some_and(|code| !code.is_empty()));
    grant
}

async fn poll(subject: &Subject, grant: &Value) -> (reqwest::StatusCode, Value) {
    let mut form = credentials(subject, &subject.key);
    form.extend([
        ("grant_type", DEVICE_GRANT.into()),
        ("device_code", grant["device_code"].as_str().unwrap().into()),
    ]);
    let response = subject
        .client
        .post(format!("{}/token", subject.origin))
        .form(&form)
        .send()
        .await
        .unwrap();
    (response.status(), super::read_json(response).await)
}

fn csrf(page: &str) -> String {
    let after = page
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .expect("the authenticated form carries a CSRF token");
    after.split('"').next().unwrap().to_string()
}

async fn screen(client: &super::Client, jar: &mut Jar, origin: &str, grant: &Value) -> String {
    let target = format!(
        "{origin}/oauth/device?user_code={}",
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
    client: &super::Client,
    jar: &mut Jar,
    origin: &str,
    grant: &Value,
    token: &str,
    action: &str,
    request_origin: &str,
) -> (reqwest::StatusCode, String) {
    let mut request = client
        .post(format!("{origin}/oauth/device"))
        .header(reqwest::header::ORIGIN, request_origin)
        .form(&[
            ("user_code", grant["user_code"].as_str().unwrap()),
            ("csrf_token", token),
            ("action", action),
        ]);
    if let Some(cookie) = jar.header_for("/oauth/device") {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let response = request.send().await.unwrap();
    for cookie in response.headers().get_all(reqwest::header::SET_COOKIE) {
        jar.store(cookie.to_str().unwrap(), "/oauth/device");
    }
    let status = response.status();
    (status, response.text().await.unwrap())
}

#[tokio::test]
async fn advertised_device_flow_requires_confirmation_mints_and_revokes() {
    let subject = setup().await;
    let (origin, client) = (subject.origin.clone(), subject.client.clone());
    let meta: Value = super::read_json(
        client
            .get(format!("{origin}/.well-known/oauth-authorization-server"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        meta["device_authorization_endpoint"],
        format!("{origin}/device_authorization")
    );
    assert_eq!(meta["revocation_endpoint"], format!("{origin}/revoke"));
    let undecided = start(&subject).await;
    assert_eq!(
        poll(&subject, &undecided).await.1["error"],
        "authorization_pending"
    );
    let grant = start(&subject).await;
    let mut jar = Jar::new(true);
    let token = screen(&client, &mut jar, &subject.admin, &grant).await;
    assert!(jar.header_for("/token").is_none());
    assert!(jar.header_for("/revoke").is_none());
    let (status, page) = submit(
        &client,
        &mut jar,
        &subject.admin,
        &grant,
        &token,
        "approve",
        &subject.admin,
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("Approved."), "{page}");
    let (status, tokens) = poll(&subject, &grant).await;
    assert_eq!(status, 200, "{tokens}");
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    super::code_flow_tests::verified_claims(&subject.app, access).await;
    assert!(!refresh.is_empty());
    let wrong_key = Key::new();
    let mut wrong = credentials(&subject, &wrong_key);
    wrong.push(("token", refresh.into()));
    let response = client
        .post(format!("{origin}/revoke"))
        .form(&wrong)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error());

    let mut kept = credentials(&subject, &subject.key);
    kept.extend([
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh.into()),
    ]);
    let kept = client
        .post(format!("{origin}/token"))
        .form(&kept)
        .send()
        .await
        .unwrap();
    let status = kept.status();
    let kept: Value = super::read_json(kept).await;
    assert_eq!(
        status, 200,
        "the wrongly authenticated revocation left the grant live: {kept}"
    );
    let refresh = kept["refresh_token"].as_str().unwrap();
    let mut revoke = credentials(&subject, &subject.key);
    revoke.push(("token", refresh.into()));
    let revoked = client
        .post(format!("{origin}/revoke"))
        .form(&revoke)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);
    assert!(revoked.bytes().await.unwrap().is_empty());
    let mut retry = credentials(&subject, &subject.key);
    retry.extend([
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh.into()),
    ]);
    let retry = client
        .post(format!("{origin}/token"))
        .form(&retry)
        .send()
        .await
        .unwrap();
    assert!(retry.status().is_client_error());
    let retry: Value = super::read_json(retry).await;
    assert_eq!(retry["error"], "invalid_grant");
    let mut unknown = credentials(&subject, &subject.key);
    unknown.push(("token", "unknown-token".into()));
    let unknown = client
        .post(format!("{origin}/revoke"))
        .form(&unknown)
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown.status(),
        200,
        "RFC7009 does not disclose token existence"
    );
    assert!(unknown.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn device_forms_refuse_missing_forged_replayed_and_cross_origin_csrf_and_allow_deny() {
    let subject = setup().await;
    let (origin, client) = (subject.origin.clone(), subject.client.clone());
    for attack in ["missing", "forged", "cross-origin", "replay"] {
        let grant = start(&subject).await;
        let mut jar = Jar::new(true);
        let token = screen(&client, &mut jar, &subject.admin, &grant).await;
        let submitted = match attack {
            "missing" => "",
            "forged" => "not-issued",
            _ => &token,
        };
        let request_origin = if attack == "cross-origin" {
            "https://attacker.example"
        } else {
            &subject.admin
        };
        if attack == "replay" {
            assert_eq!(
                submit(
                    &client,
                    &mut jar,
                    &subject.admin,
                    &grant,
                    &token,
                    "",
                    &subject.admin
                )
                .await
                .0,
                200
            );
        }
        let (status, page) = submit(
            &client,
            &mut jar,
            &subject.admin,
            &grant,
            submitted,
            "approve",
            request_origin,
        )
        .await;
        assert_eq!(status, 403, "{attack}: {page}");
        assert_eq!(
            poll(&subject, &grant).await.1["error"],
            "authorization_pending"
        );
    }
    let grant = start(&subject).await;
    let mut jar = Jar::new(true);
    let token = screen(&client, &mut jar, &subject.admin, &grant).await;
    let (status, page) = submit(
        &client,
        &mut jar,
        &subject.admin,
        &grant,
        &token,
        "deny",
        &subject.admin,
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("denied"), "{page}");
    assert_eq!(poll(&subject, &grant).await.1["error"], "access_denied");
}

#[tokio::test]
async fn the_browser_device_routes_require_admin_and_public_registration_keeps_its_grant_policy() {
    let (origin, admin, _app) = super::consent_tests::serve_at(&["read"], true).await;
    let client = super::client();
    for method in [reqwest::Method::GET, reqwest::Method::POST] {
        let response = client
            .request(method, format!("{admin}/oauth/device"))
            .form(&[("user_code", "ABCD-EFGH"), ("action", "approve")])
            .send()
            .await
            .unwrap();
        assert!(matches!(response.status().as_u16(), 401 | 403));
        let page = response.text().await.unwrap();
        assert!(!page.contains("csrf_token") && !page.contains("ABCD-EFGH"));
    }
    let response = client
        .post(format!("{origin}/register"))
        .json(&json::json!({
            "redirect_uris": ["https://client.example/cb"],
            "grant_types": [DEVICE_GRANT],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_client_error(),
        "public registration cannot enable device grants"
    );
    let registration = client
        .post(format!("{origin}/register"))
        .json(&json::json!({
            "redirect_uris":["https://client.example/cb"],"grant_types":["authorization_code"],
            "token_endpoint_auth_method":"none","scope":"read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(registration.status(), 201);
    let registration: Value = super::read_json(registration).await;
    let code_client = registration["client_id"].as_str().unwrap();
    let response = client
        .post(format!("{origin}/device_authorization"))
        .form(&[("client_id", code_client), ("scope", "read")])
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    let error: Value = super::read_json(response).await;
    assert_eq!(
        error["error"], "unauthorized_client",
        "a pre-existing code-only registration does not gain device permission"
    );
}

fn assert_framing_refused(headers: &reqwest::header::HeaderMap, what: &str) {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(header("cache-control"), "no-store", "{what}");
    assert_eq!(header("x-frame-options"), "DENY", "{what}");
    assert!(
        header("content-security-policy").contains("frame-ancestors 'none'"),
        "{what}"
    );
    assert_eq!(header("referrer-policy"), "no-referrer", "{what}");
}

/// #140: the device approval page is an operator page, so it lives on the admin listener and the
/// grant names that listener; and the operator sees WHAT they approve before any approve control
/// exists (RFC 8628 s5.4).
#[tokio::test]
async fn the_verification_uri_names_the_admin_listener_and_the_page_confirms_before_approving() {
    let subject = setup().await;
    let (origin, admin, client) = (
        subject.origin.clone(),
        subject.admin.clone(),
        subject.client.clone(),
    );
    let mut form = credentials(&subject, &subject.key);
    form.push(("scope", "read".into()));
    let response = client
        .post(format!("{origin}/device_authorization"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let grant: Value = super::read_json(response).await;
    assert_eq!(
        grant["verification_uri"],
        format!("{admin}/oauth/device"),
        "the published verification page is the admin listener's: {grant}"
    );
    let user_code = grant["user_code"].as_str().unwrap().to_string();

    for path in [
        format!("/device?user_code={user_code}"),
        format!("/oauth/device?user_code={user_code}"),
    ] {
        let response = client.get(format!("{origin}{path}")).send().await.unwrap();
        let status = response.status();
        let page = response.text().await.unwrap();
        assert_ne!(status, 200, "the public listener serves {path}: {page}");
        assert!(
            !page.contains(CLIENT) && !page.contains("csrf_token"),
            "the public listener renders the operator page at {path}: {page}"
        );
    }

    let mut jar = Jar::new(false);
    let (status, headers, entry) = send(
        &client,
        &mut jar,
        reqwest::Method::GET,
        &format!("{admin}/oauth/device"),
        None,
    )
    .await;
    assert_eq!(status, 200, "the code-entry form renders: {entry}");
    assert!(entry.contains("name=\"user_code\""), "{entry}");
    assert!(
        !entry.contains("value=\"approve\""),
        "no approve control before the operator has seen the request: {entry}"
    );
    assert_framing_refused(&headers, "the entry form");

    let (status, headers, page) = send(
        &client,
        &mut jar,
        reqwest::Method::GET,
        &format!("{admin}/oauth/device?user_code={user_code}"),
        None,
    )
    .await;
    assert_eq!(status, 200, "the confirm page renders: {page}");
    assert_framing_refused(&headers, "the confirm page");
    let approve_at = page
        .find("value=\"approve\"")
        .expect("the confirm page carries the approve control");
    assert!(
        page[..approve_at].contains(CLIENT) && page[..approve_at].contains("read"),
        "the client and the scope are named before the approve control: {page}"
    );
    assert!(
        jar.header_for("/oauth/device").is_some(),
        "the confirm page binds its form to this browser"
    );

    let (status, _, refused) = send(
        &client,
        &mut jar,
        reqwest::Method::GET,
        &format!("{admin}/oauth/device?user_code=NOPE-NOPE"),
        None,
    )
    .await;
    assert!(status.is_client_error(), "{status}: {refused}");
    assert!(
        !refused.contains("csrf_token") && !refused.contains("value=\"approve\""),
        "an unknown code gets a refusal and no form: {refused}"
    );
    assert_eq!(
        poll(&subject, &grant).await.1["error"],
        "authorization_pending",
        "looking at the request decided nothing"
    );
}
