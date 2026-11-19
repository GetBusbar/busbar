// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #140: the operator approval pages live on the ADMIN listener, never on the public one.
//!
//! The contract says a `RouteAuth::Admin` route is physically absent from the data listener, and
//! the admin listener is loopback by default precisely so an open admin posture is not public. The
//! authorization server's consent and device pages were mounted on the data listener, which undid
//! both. These tests drive the deployment on its two real listeners.

use super::browser::{
    cookie_path, location, path_of, percent_decode, query_param, send, sent_to, Jar,
};
use super::consent_tests::{register_client, serve_at};
use busbar_contract::route::RouteAuth;

const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SCOPE: &str = "read";

fn no_redirects() -> super::Client {
    super::Client::plain()
}

fn is_handle(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn csrf(page: &str) -> Option<String> {
    let after = page.split("name=\"csrf_token\" value=\"").nth(1)?;
    after.split('"').next().map(str::to_string)
}

fn header(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn the_data_listener_declares_no_operator_route() {
    let (_origin, _admin, app) = serve_at(&[SCOPE], false).await;
    assert!(app.oauth_as_any().is_some(), "the AS is configured");
    let admin_lines: Vec<_> = busbar_kernel::base_data_core_lines(&app)
        .into_iter()
        .filter(|(_, _, auth)| *auth == RouteAuth::Admin)
        .collect();
    assert!(
        admin_lines.is_empty(),
        "an Admin route is physically absent from the data listener, so the authorization \
         server declares none there: {admin_lines:?}"
    );
}

#[tokio::test]
async fn the_approval_pages_answer_only_on_the_admin_listener() {
    let (origin, admin, _app) = serve_at(&[SCOPE], false).await;
    let client = no_redirects();
    for path in ["/device", "/consent", "/oauth/device", "/oauth/consent"] {
        for method in [reqwest::Method::GET, reqwest::Method::POST] {
            let response = client
                .request(method.clone(), format!("{origin}{path}"))
                .header(reqwest::header::ORIGIN, &origin)
                .form(&[("return", "/authorize"), ("answer", "approve")])
                .send()
                .await
                .expect("request");
            let status = response.status();
            let body = response.text().await.expect("body");
            assert_eq!(
                status, 404,
                "the public listener must answer {method} {path} with its normal 404: {body}"
            );
        }
    }

    let (status, body) = {
        let response = client
            .get(format!("{admin}/oauth/device"))
            .send()
            .await
            .expect("request");
        (response.status(), response.text().await.expect("body"))
    };
    assert_eq!(
        status, 200,
        "the admin listener serves the device page: {body}"
    );
    let (status, body) = {
        let response = client
            .get(format!("{admin}/oauth/consent"))
            .send()
            .await
            .expect("request");
        (response.status(), response.text().await.expect("body"))
    };
    assert_eq!(
        status, 400,
        "the admin listener serves the consent page, refusing a visit with no request: {body}"
    );
}

#[tokio::test]
async fn the_consent_hop_names_the_admin_origin_and_binds_the_answer_to_the_starting_browser() {
    let (origin, admin, _app) = serve_at(&[SCOPE], false).await;
    let client_id = register_client(&origin, REDIRECT_URI, SCOPE).await;
    let client = no_redirects();
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
        "authorize sends the browser to consent: {body}"
    );
    let start = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("busbar_as_start="))
        .map(str::to_string)
        .expect("the authorization endpoint gives the starting browser its start cookie");
    let start_path = cookie_path(&start).expect("the start cookie names its path");
    assert_eq!(start_path, "/authorize", "{start}");
    for admin_path in ["/oauth/consent", "/oauth/device"] {
        assert!(
            !sent_to(admin_path, &start_path),
            "loopback origins share host-only cookies across ports, so the start cookie's path \
             must never reach {admin_path}: {start}"
        );
    }
    assert!(
        start.contains("HttpOnly") && start.contains("SameSite=Lax"),
        "{start}"
    );

    let consent = location(&headers, &origin);
    assert!(
        consent.starts_with(&format!("{admin}/oauth/consent?")),
        "the consent page is the admin listener's: {consent}"
    );
    let reference = query_param(&consent, "ref").expect("the hop names the starting browser");
    assert!(is_handle(&reference), "{reference}");
    let return_to = percent_decode(&query_param(&consent, "return").expect("return"));

    let (status, headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen renders: {page}");
    assert_eq!(header(&headers, "cache-control"), "no-store");
    assert_eq!(header(&headers, "x-frame-options"), "DENY");
    assert!(header(&headers, "content-security-policy").contains("frame-ancestors 'none'"));
    assert_eq!(header(&headers, "referrer-policy"), "no-referrer");
    assert!(page.contains(client_id.as_str()), "{page}");
    let token = csrf(&page).expect("the consent form carries a CSRF token");
    let consent_page = format!("{admin}/oauth/consent");

    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &consent_page,
        Some(&[
            ("return", return_to.as_str()),
            ("ref", reference.as_str()),
            ("answer", "approve"),
        ]),
    )
    .await;
    assert_eq!(
        status, 403,
        "an answer without the form token is refused: {body}"
    );
    assert!(headers.get(reqwest::header::LOCATION).is_none());

    let mut forced = no_redirects()
        .post(&consent_page)
        .header(reqwest::header::ORIGIN, "https://attacker.example")
        .form(&[
            ("return", return_to.as_str()),
            ("ref", reference.as_str()),
            ("csrf_token", token.as_str()),
            ("answer", "approve"),
        ]);
    if let Some(cookie) = jar.header_for("/oauth/consent") {
        forced = forced.header(reqwest::header::COOKIE, cookie);
    }
    let forced = forced.send().await.expect("request");
    assert_eq!(
        forced.status(),
        403,
        "a cross-site submission is refused even with the token"
    );

    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &consent_page,
        Some(&[
            ("return", return_to.as_str()),
            ("ref", reference.as_str()),
            ("csrf_token", token.as_str()),
            ("answer", "approve"),
        ]),
    )
    .await;
    assert_eq!(
        status, 302,
        "the operator's approval redirects back: {body}"
    );
    let back = location(&headers, &origin);
    let handle = query_param(&back, "busbar_consent").expect("the way back carries one-time T");
    assert!(is_handle(&handle), "{back}");
    assert_eq!(
        back,
        format!("{origin}{return_to}&busbar_consent={handle}"),
        "the way back is the T-free request with T appended"
    );
    assert!(
        jar.header_for("/authorize")
            .is_some_and(|c| !c.contains("busbar_as_consent")),
        "the admin form cookie never reaches the authorization endpoint"
    );

    let (status, _, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &consent_page,
        Some(&[
            ("return", return_to.as_str()),
            ("ref", reference.as_str()),
            ("csrf_token", token.as_str()),
            ("answer", "approve"),
        ]),
    )
    .await;
    assert_eq!(status, 403, "the form token is single use: {body}");

    let wrong = if handle.starts_with('0') {
        "1".repeat(64)
    } else {
        "0".repeat(64)
    };
    let forged = back.replace(&handle, &wrong);
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &forged, None).await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(
        path_of(&location(&headers, &origin)),
        "/oauth/consent",
        "the starting browser with a wrong T mints nothing"
    );

    let mut stranger = Jar::new(false);
    let (status, headers, body) =
        send(&client, &mut stranger, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(
        path_of(&location(&headers, &origin)),
        "/oauth/consent",
        "T in another browser (no start cookie) mints nothing"
    );

    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "{body}");
    let redirect = location(&headers, &origin);
    assert!(
        redirect.starts_with(REDIRECT_URI) && query_param(&redirect, "code").is_some(),
        "the starting browser with its T gets the code: {redirect}"
    );

    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(
        path_of(&location(&headers, &origin)),
        "/oauth/consent",
        "T is spent once"
    );
}
