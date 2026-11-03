// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    application_with_document,
    browser::{location, percent_decode, query_param, send, Jar},
};
use busbar_core_oauth2::config::OauthAsCfg;
use std::sync::Arc;

const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const OFFSITE_REDIRECT_URI: &str = "https://client.example/cb";
const SCOPE: &str = "read";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

pub(super) async fn serve(
    scopes: &[&str],
    guarded: bool,
) -> (String, Arc<busbar_kernel::state::App>) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let oauth = OauthAsCfg {
        issuer: origin.clone(),
        default_grant: scopes.iter().map(|scope| (*scope).into()).collect(),
        ..Default::default()
    };
    let mut document = serde_json::json!({
        "providers": {}, "models": {},
        "oauth_as": oauth,
        "auth": {"chain":[],"admin_auth":[]},
        "advanced": {"allow_destinations":["127.0.0.1"]},
    });
    if guarded {
        let directory = super::plugins::scratch(&format!(
            "oauth-consent-operator-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let credential = directory.join("operator-token");
        std::fs::write(&credential, "oauth-consent-route-operator")
            .expect("write test operator input");
        let operator = busbar_kernel::config::operator_provider();
        document["auth"]["admin_auth"] = serde_json::json!([operator]);
        document["identity-providers"] = serde_json::json!({});
        document["identity-providers"][operator] = serde_json::json!({
            "module":operator,"token":{"file":credential},
        });
    }
    let app = application_with_document(document);
    let router = busbar_kernel::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (origin, app)
}

async fn register_client(origin: &str, redirect: &str, scopes: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{origin}/register"))
        .json(&serde_json::json!({
            "redirect_uris":[redirect], "token_endpoint_auth_method":"none",
            "response_types":["code"], "grant_types":["authorization_code","refresh_token"],
            "scope":scopes,
        }))
        .send()
        .await
        .expect("register real public client");
    let status = response.status();
    let body = response.text().await.expect("registration body");
    assert_eq!(status, 201, "the real registration succeeds: {body}");
    serde_json::from_str::<serde_json::Value>(&body).expect("registration JSON")["client_id"]
        .as_str()
        .expect("registered client id")
        .to_owned()
}

#[tokio::test]
async fn a_multi_scope_or_default_scope_request_is_approved_on_its_first_consent() {
    let (origin, _app) = serve(&["read", "write"], false).await;
    let multi = register_client(&origin, REDIRECT_URI, "read write").await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    for scope in ["&scope=write%20read", "&scope=read%20read%20write", ""] {
        let mut jar = Jar::new(false);
        let authorize = format!(
            "{origin}/authorize?response_type=code&client_id={multi}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1{scope}\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let (status, headers, body) =
            send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
        assert_eq!(
            status, 302,
            "{scope:?}: authorize must redirect to consent: {body}"
        );
        let consent = location(&headers, &origin);
        let (status, _headers, body) =
            send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
        assert_eq!(
            status, 200,
            "{scope:?}: the consent screen must render: {body}"
        );
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
        assert_eq!(
            status, 302,
            "{scope:?}: an approval must redirect back: {body}"
        );
        let back = location(&headers, &origin);
        let (status, headers, body) =
            send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
        assert_eq!(status, 302, "{scope:?}: {body}");
        let redirect = location(&headers, &origin);
        assert!(
            redirect.starts_with(REDIRECT_URI),
            "{scope:?}: an approved request goes to the client's redirect URI on its FIRST \
             approval, not back to the consent screen. Got: {redirect}"
        );
        assert!(
            query_param(&redirect, "code").is_some_and(|c| !c.is_empty()),
            "{scope:?}: the approved request carries a code: {redirect}"
        );
    }
}

#[tokio::test]
async fn the_consent_screen_names_the_client_and_the_redirect_host() {
    let (origin, _app) = serve(&[SCOPE], false).await;
    let offsite_client_id = register_client(&origin, OFFSITE_REDIRECT_URI, SCOPE).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={offsite_client_id}\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, &origin);
    let (status, _headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {page}");

    assert!(
        page.contains(offsite_client_id.as_str()),
        "the screen must NAME the client asking for authorization: {page}"
    );
    assert!(
        page.contains(SCOPE),
        "the screen must name the scopes being requested: {page}"
    );

    let visible = strip_hidden_return(&page);
    assert!(
        visible.contains("client.example"),
        "the consent screen must name the HOST the approval sends the credential to \
         (client.example, from redirect_uri {OFFSITE_REDIRECT_URI}) somewhere the operator can READ \
         it. Without it, an operator approving \"{offsite_client_id} for scope {SCOPE}\" cannot tell \
         a legitimate registration from one pointing at an attacker's callback. Visible page, with \
         the hidden `return` field removed:\n{visible}"
    );
}

fn strip_hidden_return(page: &str) -> String {
    let marker = "name=return value=\"";
    let Some(start) = page.find(marker) else {
        return page.to_string();
    };
    let after = start + marker.len();
    let Some(end) = page[after..].find('"') else {
        return page.to_string();
    };
    format!("{}{}", &page[..after], &page[after + end..])
}

#[tokio::test]
async fn an_unauthenticated_visitor_is_never_shown_the_consent_screen() {
    let (origin, _app) = serve(&[SCOPE], true).await;
    let client_id = register_client(&origin, REDIRECT_URI, SCOPE).await;
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
    assert_eq!(
        status, 302,
        "the authorization endpoint must answer with a redirect, not with a page describing the \
         request: {body}"
    );
    assert!(
        !body.contains(client_id.as_str()),
        "the redirect away from /authorize must not itself carry a body naming the client: {body}"
    );

    let consent = location(&headers, &origin);
    let (status, _headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert!(
        status == 401 || status == 403,
        "the consent screen is `RouteAuth::Admin`: an anonymous visitor must be refused, got \
         {status}: {page}"
    );
    assert!(
        !page.contains(client_id.as_str()),
        "an anonymous visitor must NOT be told which client is asking — that page is the phishing \
         surface: {page}"
    );
}

#[tokio::test]
async fn a_return_target_a_browser_reads_as_off_site_is_refused_on_approve_and_deny() {
    let (origin, _app) = serve(&[SCOPE], false).await;
    let client_id = register_client(&origin, REDIRECT_URI, SCOPE).await;
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
    let (_, headers, _) = send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    let consent = location(&headers, &origin);
    let (status, _, body) = send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(
        status, 200,
        "the consent screen renders and opens a session: {body}"
    );
    assert!(
        jar.header_for("/consent").is_some(),
        "the session cookie is live"
    );

    for answer in ["approve", "deny"] {
        for bypass in ["/\t/evil.example", "/\n/evil.example", "/\\evil.example"] {
            let (status, headers, _) = send(
                &client,
                &mut jar,
                reqwest::Method::POST,
                &format!("{origin}/consent"),
                Some(&[("return", bypass), ("answer", answer)]),
            )
            .await;
            assert_eq!(
                status, 400,
                "{answer} with return {bypass:?} must be refused"
            );
            assert!(
                headers.get(reqwest::header::LOCATION).is_none(),
                "{answer} with return {bypass:?} redirected the browser"
            );
        }
    }

    let (status, _, _) = send(
        &client,
        &mut jar,
        reqwest::Method::GET,
        &format!("{origin}/consent?return=%2F%09%2Fevil.example"),
        None,
    )
    .await;
    assert_eq!(
        status, 400,
        "the consent screen renders for an off-site return target"
    );
}
