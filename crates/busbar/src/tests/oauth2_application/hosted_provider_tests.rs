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
    std::fs::write(&secret, "oauth-hosted-test-client-secret")
        .expect("write confidential-client input");
    let mut definitions = serde_json::Map::new();
    for (name, button) in methods {
        let mut provider =
            serde_json::json!({"module":module,"settings":issuer::settings("oauth-hosted")});
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
