// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{application_with_auth_plugin, issuer, plugins};
use base64::Engine as _;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn cookie(raw: &str) -> serde_json::Value {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .expect("cookie base64url");
    serde_json::from_slice(&bytes).expect("the browser cookie carries JSON")
}

async fn hosted(methods: &[(&str, bool)]) -> (String, tokio::task::JoinHandle<()>) {
    hosted_with_settings(methods, issuer::settings("oauth-hosted")).await
}

async fn hosted_with_settings(
    methods: &[(&str, bool)],
    settings: serde_json::Map<String, serde_json::Value>,
) -> (String, tokio::task::JoinHandle<()>) {
    hosted_with_secret(methods, settings, "oauth-hosted-test-client-secret").await
}

async fn hosted_with_secret(
    methods: &[(&str, bool)],
    settings: serde_json::Map<String, serde_json::Value>,
    client_secret: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let library =
        plugins::token_verifier_cdylib_path().expect("build the actual pinned OIDC plugin");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .expect("read OIDC Statement")
        .expect("OIDC states itself");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("valid Statement")
        .name;
    let secrets = plugins::scratch(&format!(
        "oauth-hosted-provider-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let secret = secrets.join("client-secret");
    std::fs::write(&secret, client_secret).expect("write confidential-client input");
    let mut definitions = serde_json::Map::new();
    for (name, button) in methods {
        let mut provider = serde_json::json!({"module":module,"settings":settings});
        if *button {
            provider["browser_login"] =
                serde_json::json!({"client_id":"oauth-hosted","client_secret":{"file":secret}});
        }
        definitions.insert((*name).into(), provider);
    }
    let app = application_with_auth_plugin(
        serde_json::json!({
            "providers":{},"models":{},"public_url":"https://busbar.example.com",
            "identity-providers":definitions,"auth":{"chain":[],"admin_auth":[]},
            "advanced":{"allow_destinations":["127.0.0.1"]},
        }),
        &library,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = busbar_kernel::build_router(app);
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{address}"), handle)
}

async fn page(base: &str) -> String {
    let response = client()
        .get(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.text().await.unwrap()
}

async fn refresh_flag_for(base: &str, site: Option<&str>) -> bool {
    let mut request = client().get(format!("{base}/auth/token?method=microsoft&refresh=1"));
    if let Some(site) = site {
        request = request.header("sec-fetch-site", site);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), 302, "begin redirects to the real IdP");
    let header = response.headers()["set-cookie"].to_str().unwrap();
    let raw = header
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("busbar_login=")
        .unwrap();
    cookie(raw)["refresh"].as_bool().expect("refresh flag")
}

#[tokio::test]
async fn chooser_renders_0_1_n_buttons() {
    let (base0, h0) = hosted(&[]).await;
    let body0 = page(&base0).await;
    assert_eq!(body0.matches("class=\"provider\"").count(), 0);
    assert!(body0.contains("No browser login"));

    let (base1, h1) = hosted(&[("microsoft", true)]).await;
    let body1 = page(&base1).await;
    assert_eq!(body1.matches("class=\"provider\"").count(), 1);
    assert!(body1.contains("/auth/token?method=microsoft"));

    let (basen, hn) = hosted(&[
        ("microsoft", true),
        ("second-sso", true),
        ("headless-only", false),
    ])
    .await;
    let bodyn = page(&basen).await;
    assert_eq!(
        bodyn.matches("class=\"provider\"").count(),
        2,
        "only the two browser_login methods render buttons; the gui-off method is excluded"
    );
    assert!(
        !bodyn.contains("method=headless-only"),
        "gui-off method not shown"
    );

    assert!(bodyn.contains("https://busbar.example.com"));
    assert!(!bodyn.contains("https://busbar.example.com/v1"));
    h0.abort();
    h1.abort();
    hn.abort();
}

#[tokio::test]
async fn gui_off_method_still_works_via_post() {
    let (base, handle) = hosted(&[("headless-only", false)]).await;
    let client = reqwest::Client::new();

    let r = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(r.status().as_u16(), 404, "POST /auth/token must exist");
    assert_ne!(r.status().as_u16(), 405, "POST /auth/token must be allowed");
    handle.abort();
}

#[tokio::test]
async fn begin_sets_httponly_secure_cookie_and_redirects() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let resp = client()
        .get(format!("{base}/auth/token?method=microsoft"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with(
        issuer::settings("oauth-hosted")["authorization_endpoint"]
            .as_str()
            .unwrap()
    ));
    let sc = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(sc.contains("HttpOnly"), "cookie must be HttpOnly: {sc}");
    assert!(sc.contains("Secure"), "cookie must be Secure: {sc}");
    assert!(
        sc.contains("SameSite=Lax"),
        "cookie must be SameSite=Lax: {sc}"
    );

    let raw = sc
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("busbar_login=")
        .unwrap();
    let cookie = cookie(raw);
    assert_eq!(cookie["method"], "microsoft");
    assert!(
        !cookie["code_verifier"].as_str().unwrap().is_empty()
            && !cookie["state"].as_str().unwrap().is_empty()
            && !cookie["nonce"].as_str().unwrap().is_empty()
    );
    handle.abort();
}

#[tokio::test]
async fn a_refresh_link_rotates_only_from_busbars_own_page() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    for site in [Some("cross-site"), None, Some("none"), Some("same-site")] {
        assert!(
            !refresh_flag_for(&base, site).await,
            "Sec-Fetch-Site {site:?} does not rotate the key"
        );
    }
    assert!(
        refresh_flag_for(&base, Some("same-origin")).await,
        "busbar's own Refresh link rotates the key"
    );
    handle.abort();
}

async fn start_cookie(base: &str) -> (String, serde_json::Value) {
    let response = client()
        .get(format!("{base}/auth/token?method=microsoft"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let raw = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("busbar_login=")
        .unwrap()
        .to_owned();
    let decoded = cookie(&raw);
    let location = response.headers()["location"].to_str().unwrap();
    let nonce =
        super::browser::query_param(location, "nonce").expect("actual OIDC authorize nonce");
    assert_eq!(
        super::browser::percent_decode(&nonce),
        decoded["nonce"].as_str().unwrap(),
        "the real plugin uses the cookie's nonce"
    );
    (raw, decoded)
}

#[tokio::test]
async fn callback_state_mismatch_400() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let (raw, decoded) = start_cookie(&base).await;
    let code = format!("refused-state-{}", busbar_kernel::door::op_id().counter());
    let response = client()
        .get(format!("{base}/auth/token"))
        .query(&[("code", code.as_str()), ("state", "WRONG-STATE")])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400, "state mismatch must be a clean 400");
    let response = client()
        .get(format!("{base}/auth/token"))
        .query(&[
            ("code", code.as_str()),
            ("state", decoded["state"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400, "no cookie ⇒ 400");
    assert_eq!(
        issuer::exchanges_for(&code),
        0,
        "no complete_login exchange is handed to the actual plugin on a refused callback"
    );
    handle.abort();
}

#[tokio::test]
async fn callback_nonce_mismatch_rejected() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let (raw, decoded) = start_cookie(&base).await;
    let code = format!("WRONG-NONCE-{}", busbar_kernel::door::op_id().counter());
    assert_ne!(code, decoded["nonce"].as_str().unwrap());
    let response = client()
        .get(format!("{base}/auth/token"))
        .query(&[
            ("code", code.as_str()),
            ("state", decoded["state"].as_str().unwrap()),
        ])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "an id_token whose nonce ≠ the cookie nonce must be rejected (no key issued)"
    );
    let body = response.text().await.unwrap();
    assert!(!body.contains("bbk_"), "no key issued");
    assert_eq!(issuer::exchanges_for(&code),1,"the real plugin exchanges the callback once; start_cookie proved it received the core's nonce");
    handle.abort();
}

pub(super) fn assert_branded_error_page(body: &str, heading: &str) {
    assert!(
        body.starts_with("<!doctype html>"),
        "a browser-flow failure must be a full styled HTML document, not plain text: {body}"
    );
    assert!(
        body.contains("class=\"wordmark\">Busbar"),
        "the error card carries the Busbar brand lockup: {body}"
    );
    assert!(
        body.contains("class=\"erricon\""),
        "the error card shows the alert glyph: {body}"
    );

    let heading_esc = heading.replace('\'', "&#39;");
    assert!(
        body.contains(&heading_esc),
        "the error card heading is human-readable ({heading}): {body}"
    );
    assert!(
        body.contains("class=\"backlink\"") && body.contains("href=\"/auth/token\""),
        "the error card links back to sign in: {body}"
    );
    assert!(
        body.contains("Back to sign in"),
        "the back link is labeled: {body}"
    );
}

#[tokio::test]
async fn browser_callback_failure_renders_branded_html() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let (raw, _decoded) = start_cookie(&base).await;
    let response = client()
        .get(format!("{base}/auth/token"))
        .query(&[
            ("code", "refused-branded-callback"),
            ("state", "WRONG-STATE"),
        ])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().unwrap_or("").contains("Max-Age=0")));
    let body = response.text().await.unwrap();
    assert_branded_error_page(&body, "Sign-in couldn't be verified");
    assert!(
        !body.contains("state mismatch"),
        "the internal reason is not leaked to the user: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn no_self_serve_grant_renders_branded_html() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let (raw, decoded) = start_cookie(&base).await;
    let response = client()
        .get(format!("{base}/auth/token"))
        .query(&[
            ("code", decoded["nonce"].as_str().unwrap()),
            ("state", decoded["state"].as_str().unwrap()),
        ])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403, "no grant ⇒ 403");
    let body = response.text().await.unwrap();
    assert_branded_error_page(&body, "No access yet");
    assert!(
        body.contains("admin"),
        "the copy tells the user to ask their admin: {body}"
    );
    handle.abort();
}
#[tokio::test]
async fn api_json_path_stays_json_not_html() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let client = reqwest::Client::new();
    let r = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "unauthenticated API exchange ⇒ 401"
    );
    let ctype = r
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ctype.contains("application/json"),
        "the API path returns JSON, not text/html: {ctype}"
    );
    let body = r.text().await.unwrap();
    assert!(
        !body.contains("<!doctype") && !body.contains("class=\"backlink\""),
        "the API path must NOT return the styled HTML error card: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("API error is JSON");
    assert!(
        json.get("error").and_then(|e| e.as_str()).is_some(),
        "the API keeps the {{\"error\":…}} shape: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn redirect_begin_still_redirects() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let resp = client()
        .get(format!("{base}/auth/token?method=microsoft"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    handle.abort();
}

#[tokio::test]
async fn logout_renders_signed_out_and_clears_cookie() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let resp = client()
        .get(format!("{base}/auth/token?logout=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    assert!(
        resp.headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("Max-Age=0")),
        "logout must clear the busbar login cookie"
    );
    let body = resp.text().await.unwrap();
    assert!(body.starts_with("<!doctype html>"), "branded HTML card");
    assert!(body.contains("Signed out"), "the heading confirms sign-out");
    assert!(
        body.contains("href=\"/auth/token\"") && body.contains("Sign in again"),
        "offers a clean re-entry: {body}"
    );

    assert!(
        body.contains("doesn't revoke your key"),
        "copy is honest about scope: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn callback_security_check_failed_renders_the_state_mismatch_bytes() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let (raw, decoded) = start_cookie(&base).await;
    let code = format!(
        "security-mismatch-{}",
        busbar_kernel::door::op_id().counter()
    );
    let failed = client()
        .get(format!("{base}/auth/token"))
        .query(&[
            ("code", code.as_str()),
            ("state", decoded["state"].as_str().unwrap()),
        ])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    let mismatch = client()
        .get(format!("{base}/auth/token"))
        .query(&[("code", code.as_str()), ("state", "WRONG")])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status().as_u16(), 400);
    assert_eq!(failed.status(), mismatch.status());
    for h in [reqwest::header::CACHE_CONTROL, reqwest::header::SET_COOKIE] {
        assert_eq!(
            failed.headers().get(&h),
            mismatch.headers().get(&h),
            "{h} matches the state mismatch's"
        );
    }
    assert!(failed
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_some_and(|v| v.to_str().is_ok_and(|v| v.contains("Max-Age=0"))));
    let (a, b) = (failed.text().await.unwrap(), mismatch.text().await.unwrap());
    assert!(
        a.contains("Sign-in couldn&#39;t be verified")
            || a.contains("Sign-in couldn't be verified")
    );
    assert_eq!(
        a, b,
        "one page for a state mismatch and a failed security check"
    );
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_anonymous_begin_does_not_starve_the_runtime() {
    let (base, handle) =
        hosted_with_settings(&[("microsoft", true)], issuer::pending_settings()).await;
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let base = base.clone();
            tokio::spawn(async move {
                client()
                    .get(format!("{base}/auth/token?method=microsoft"))
                    .send()
                    .await
                    .unwrap()
                    .status()
            })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    tokio::time::timeout(std::time::Duration::from_millis(750),tokio::spawn(async {})).await
        .expect("the runtime stopped polling while four ANONYMOUS begins sat inside the actual OIDC plugin's discovery")
        .expect("runtime canary completes");
    for task in tasks {
        assert_eq!(
            task.await.unwrap(),
            302,
            "the real OIDC discovery eventually redirects"
        );
    }
    handle.abort();
}

#[tokio::test]
async fn a_door_callback_with_a_foreign_state_asks_the_plugin_nothing() {
    let (base, handle) = hosted(&[("microsoft", true)]).await;
    let (raw, _cookie) = start_cookie(&base).await;
    let code = format!("foreign-state-{}", busbar_kernel::door::op_id().counter());
    let response = client()
        .get(format!("{base}/auth/token"))
        .query(&[("code", code.as_str()), ("state", "FOREIGN")])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        issuer::exchanges_for(&code),
        0,
        "the actual plugin makes no token exchange on a foreign state"
    );
    handle.abort();
}

#[tokio::test]
async fn the_client_secret_rides_nothing_the_flow_makes() {
    const SECRET: &str = "REAL-SECRET-XYZ";
    let (base, handle) = hosted_with_secret(
        &[("microsoft", true)],
        issuer::settings("oauth-hosted"),
        SECRET,
    )
    .await;
    let begun = client()
        .get(format!("{base}/auth/token?method=microsoft"))
        .send()
        .await
        .unwrap();
    assert_eq!(begun.status(), 302);
    let location = begun.headers()[reqwest::header::LOCATION].to_str().unwrap();
    assert!(!location.contains(SECRET), "not on the authorize redirect");
    let set = begun.headers()[reqwest::header::SET_COOKIE]
        .to_str()
        .unwrap();
    let raw = set
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("busbar_login=")
        .unwrap();
    let decoded = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .unwrap(),
    )
    .unwrap();
    assert!(
        !decoded.contains(SECRET) && !set.contains(SECRET),
        "not in the login cookie: {decoded}"
    );
    let cookie = cookie(raw);
    let called = client()
        .get(format!("{base}/auth/token"))
        .query(&[
            ("code", cookie["nonce"].as_str().unwrap()),
            ("state", cookie["state"].as_str().unwrap()),
        ])
        .header("cookie", format!("busbar_login={raw}"))
        .send()
        .await
        .unwrap();
    assert!(
        !called.text().await.unwrap().contains(SECRET),
        "not on the page rendered"
    );
    handle.abort();
}
