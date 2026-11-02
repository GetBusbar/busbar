// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    application_with_resource_auth,
    browser::{encode_component, location, path_of, percent_decode, query_param, send, Jar},
};
use base64::Engine as _;
use busbar_core_oauth2::config::OauthAsCfg;
use std::sync::Arc;

const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SCOPE: &str = "read";

async fn serve() -> (String, Arc<busbar_kernel::state::App>) {
    serve_with_scopes(&[SCOPE]).await
}

async fn serve_with_scopes(scopes: &[&str]) -> (String, Arc<busbar_kernel::state::App>) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let config = OauthAsCfg {
        issuer: origin.clone(),
        default_grant: scopes.iter().map(|scope| (*scope).into()).collect(),
        ..Default::default()
    };
    let app = application_with_resource_auth(Some(&config), None, true);
    let router = busbar_kernel::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (origin, app)
}

async fn register_client(origin: &str) -> String {
    register_client_with_scope(origin, SCOPE).await
}

async fn register_client_with_scope(origin: &str, scope: &str) -> String {
    let response = reqwest::Client::new().post(format!("{origin}/register")).json(&serde_json::json!({
        "redirect_uris":[REDIRECT_URI],"token_endpoint_auth_method":"none",
        "response_types":["code"],"grant_types":["authorization_code","refresh_token"],"scope":scope,"client_name":"Flow Test",
    })).send().await.expect("register actual public client");
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 201, "the public client registers: {body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub(super) async fn verified_claims(
    app: &busbar_kernel::state::App,
    access: &str,
) -> serde_json::Value {
    let calls = app
        .auth
        .position_calls("oauth-resource")
        .expect("the actual OIDC product is configured");
    let mut request = busbar_contract::auth_calls::VerifyRequest::default();
    request.credential = Some(busbar_contract::redacted::Secret::new(
        access.as_bytes().to_vec(),
    ));
    request.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let answer = calls.verify(request).await;
    assert!(
        matches!(
            answer.verified,
            busbar_contract::auth_calls::Verified::Identity(_)
        ),
        "the actual verifier admits the freshly minted token: {answer:?}"
    );
    let encoded = access.split('.').nth(1).expect("actual JWT claims");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .unwrap();
    serde_json::from_slice(&bytes).expect("verified claims JSON")
}

#[tokio::test]
async fn the_authorization_code_flow_mints_and_exchanges_a_code() {
    let (origin, app) = serve().await;
    let client_id = register_client(&origin).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={client_id}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, &origin);
    assert!(
        consent.starts_with(&format!("{origin}/consent?return=")),
        "the redirect must name this deployment's consent screen: {consent}"
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {body}");
    let set_cookie = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("ASCII").to_string())
        .collect::<Vec<_>>();
    assert!(
        !set_cookie.is_empty(),
        "the consent screen must open a session"
    );

    assert!(
        jar.header_for("/consent").is_some(),
        "the consent POST reads the session cookie; Set-Cookie was {set_cookie:?}"
    );
    assert!(
        jar.header_for("/authorize").is_some(),
        "`/authorize` is where the approval resolver reads the session cookie, and it is a SIBLING \
         of `/consent`, not a child: a cookie the browser will not send here cannot mint a code. \
         Set-Cookie was {set_cookie:?}"
    );

    let return_to =
        query_param(&consent, "return").expect("the screen carries the pending request");
    let return_to = percent_decode(&return_to);
    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/consent"),
        Some(&[("return", return_to.as_str())]),
    )
    .await;
    assert_eq!(status, 302, "an approval must redirect back: {body}");
    let back = location(&headers, &origin);
    assert!(
        path_of(&back) == "/authorize",
        "the approval hands the browser back to the authorization endpoint: {back}"
    );

    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "the approved request must redirect: {body}");
    let redirect = location(&headers, &origin);
    assert!(
        redirect.starts_with(REDIRECT_URI),
        "an approved request goes to the CLIENT's redirect URI, not back to the consent screen. \
         Got: {redirect}"
    );
    let code = query_param(&redirect, "code").unwrap_or_else(|| {
        panic!("the approved authorization request must carry a code: {redirect}")
    });
    assert!(!code.is_empty(), "an empty code is not a code");
    assert_eq!(
        query_param(&redirect, "state").as_deref(),
        Some("s1"),
        "RFC 6749 §4.1.2: the client's `state` is returned verbatim"
    );

    let (status, _headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/token"),
        Some(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await;
    assert_eq!(status, 200, "the code must be exchangeable: {body}");
    let token: serde_json::Value = serde_json::from_str(&body).expect("a token response is JSON");
    let access = token["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token: {body}"))
        .to_string();

    let record = verified_claims(&app, &access).await;
    assert_eq!(record["client_id"].as_str(), Some(client_id.as_str()));
    assert_eq!(
        record["sub"].as_str(),
        Some("busbar-operator"),
        "the code was minted for the operator, who is this plane's only resource owner"
    );
    assert_eq!(record["scope"].as_str(), Some(SCOPE));

    assert_eq!(
        busbar_kernel::auth::audience::inspect_bearer(&access, &origin),
        busbar_kernel::auth::audience::Binding::Bound,
        "the access token must carry this deployment's audience"
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(
        path_of(&location(&headers, &origin)),
        "/consent",
        "a spent approval must not authorise a second request"
    );
}

async fn mint_access_token(origin: &str, client_id: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256",
        encode_component(client_id)
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, origin);

    let (status, _headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {body}");

    let return_to =
        query_param(&consent, "return").expect("the screen carries the pending request");
    let return_to = percent_decode(&return_to);
    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/consent"),
        Some(&[("return", return_to.as_str())]),
    )
    .await;
    assert_eq!(status, 302, "an approval must redirect back: {body}");
    let back = location(&headers, origin);

    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "the approved request must redirect: {body}");
    let redirect = location(&headers, origin);
    assert!(
        redirect.starts_with(REDIRECT_URI),
        "an approved request goes to the client's redirect URI: {redirect}"
    );
    let code = query_param(&redirect, "code")
        .unwrap_or_else(|| panic!("the approved request must carry a code: {redirect}"));

    let (status, _headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/token"),
        Some(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await;
    assert_eq!(status, 200, "the code must be exchangeable: {body}");
    let token: serde_json::Value = serde_json::from_str(&body).expect("a token response is JSON");
    token["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token: {body}"))
        .to_string()
}

#[tokio::test]
async fn dynamic_client_registration_admits_a_client_end_to_end() {
    let (origin, app) = serve().await;

    let resp = reqwest::Client::new()
        .post(format!("{origin}/register"))
        .json(&serde_json::json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "client_name": "an agent",
            "scope": SCOPE,
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(
        resp.status(),
        201,
        "RFC 7591 §3.2.1: a registration is 201 Created; the endpoint mounts with the plane, \
         unconditionally"
    );
    let registration: serde_json::Value = resp.json().await.expect("a registration response");
    let client_id = registration["client_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no client_id in {registration}"))
        .to_string();

    let access = mint_access_token(&origin, &client_id).await;
    let record = verified_claims(&app, &access).await;
    assert_eq!(record["client_id"].as_str(), Some(client_id.as_str()));
    assert_eq!(record["scope"].as_str(), Some(SCOPE));
}

fn requesting(page: &str) -> String {
    page.split_once("<p>Requesting: <code>")
        .and_then(|(_, rest)| rest.split_once("</code>"))
        .map(|(scope, _)| scope.to_string())
        .unwrap_or_else(|| panic!("the screen names what it is asking for: {page}"))
}

async fn shown_and_granted(
    origin: &str,
    app: &busbar_kernel::state::App,
    client_id: &str,
    scope_param: &str,
) -> (String, String) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);
    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1{scope_param}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256",
        encode_component(client_id)
    );
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, origin);
    let (status, _headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {page}");
    let shown = requesting(&page);

    let return_to = percent_decode(
        &query_param(&consent, "return").expect("the screen carries the pending request"),
    );
    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/consent"),
        Some(&[("return", return_to.as_str())]),
    )
    .await;
    assert_eq!(status, 302, "an approval must redirect back: {body}");
    let back = location(&headers, origin);
    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "the approved request must redirect: {body}");
    let redirect = location(&headers, origin);
    let code = query_param(&redirect, "code")
        .unwrap_or_else(|| panic!("the approved request must carry a code: {redirect}"));
    let (status, _headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/token"),
        Some(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await;
    assert_eq!(status, 200, "the code must be exchangeable: {body}");
    let token: serde_json::Value = serde_json::from_str(&body).expect("a token response is JSON");
    let access = token["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token: {body}"));
    let record = verified_claims(app, access).await;
    (shown, record["scope"].as_str().unwrap_or("").to_owned())
}

#[tokio::test]
async fn a_request_naming_no_scope_is_shown_the_default_it_is_granted() {
    let (origin, app) = serve_with_scopes(&["read", "write"]).await;
    let defaulted = register_client_with_scope(&origin, "read write").await;
    let (shown, granted) = shown_and_granted(&origin, &app, &defaulted, "").await;
    assert_eq!(granted, "read write", "the registered default is granted");
    assert_eq!(
        shown, granted,
        "the consent screen must name the scope the approval grants"
    );
}

#[tokio::test]
async fn the_consent_screen_names_a_requested_scope_and_an_empty_grant() {
    let (origin, app) = serve().await;
    let client_id = register_client(&origin).await;
    let (shown, granted) = shown_and_granted(&origin, &app, &client_id, "&scope=read").await;
    assert_eq!((shown.as_str(), granted.as_str()), (SCOPE, SCOPE));

    let empty = register_client_with_scope(&origin, "").await;
    let (shown, granted) = shown_and_granted(&origin, &app, &empty, "").await;
    assert_eq!(granted, "", "an empty default grants nothing");
    assert_eq!(shown, "no scopes", "and the screen says so");
}
