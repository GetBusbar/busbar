// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::{application, application_with_document};

fn keys_application() -> Arc<busbar_kernel::state::App> {
    let directory = super::plugins::scratch(&format!(
        "oauth-hosted-secrets-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([0x71_u8; 32])).expect("write test signing input");
    std::fs::write(&operator_token, "oauth-hosted-route-operator")
        .expect("write test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {}, "models": {},
        "public_url": "https://busbar.example.com",
        "auth": {
            "chain": ["keys"],
            "admin_auth": [operator],
            "signing_key": {"file": signing_key},
        },
    });
    document["identity-providers"] = serde_json::json!({});
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": {"file": operator_token},
    });
    application_with_document(document)
}

async fn serve(app: Arc<busbar_kernel::state::App>) -> (String, tokio::task::JoinHandle<()>) {
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn auth_token_bypasses_middleware_exact_match() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let app = keys_application();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let g = client
        .get(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        g.status().as_u16(),
        401,
        "GET /auth/token must bypass the chain"
    );
    assert!(g.status().is_success(), "chooser renders 200");

    let p = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(p.status().as_u16(), 404);
    assert_ne!(p.status().as_u16(), 405);

    let h = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert!(h.status().is_success() || h.status().as_u16() == 503);

    let m = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(m.status().as_u16(), 401, "/metrics must still be gated");

    let x = client
        .get(format!("{base}/auth/tokenx"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        x.status().as_u16(),
        200,
        "no /auth prefix over-match onto the login page"
    );
    handle.abort();
}

#[tokio::test]
async fn auth_token_absent_from_admin_router() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = application(None, None);
    let (data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let ah = tokio::spawn(async move { axum::serve(admin_listener, admin).await.unwrap() });
    let data_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_addr = data_listener.local_addr().unwrap();
    let dh = tokio::spawn(async move { axum::serve(data_listener, data).await.unwrap() });
    let client = reqwest::Client::new();

    let admin_hit = client
        .get(format!("http://{admin_addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        admin_hit.status().as_u16(),
        404,
        "/auth/token is data-plane only; it must be absent from the admin router"
    );
    let data_hit = client
        .get(format!("http://{data_addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert!(
        data_hit.status().is_success(),
        "the data router DOES serve /auth/token (control)"
    );
    ah.abort();
    dh.abort();
}

#[tokio::test]
async fn auth_token_bypass_does_not_apply_on_the_admin_router() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = keys_application();
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let ah = tokio::spawn(async move { axum::serve(admin_listener, admin).await.unwrap() });
    let client = reqwest::Client::new();

    let hit = client
        .get(format!("http://{admin_addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        hit.status().as_u16(),
        401,
        "the /auth/token bypass belongs to the DATA router that mounts it; on the admin router the \
         path is unmounted and unauthenticated, so the auth chain must answer it"
    );

    let health = client
        .get(format!("http://{admin_addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        health.status().as_u16(),
        401,
        "/healthz is declared open on the admin router and must stay open (this app has no lanes, \
         so the probe itself answers 503 — what matters is that auth did not answer it)"
    );
    ah.abort();
}

#[tokio::test]
async fn core_route_bypass_is_exact_in_path_and_method() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = keys_application();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    for (method, path) in [
        (reqwest::Method::GET, "/healthz"),
        (reqwest::Method::HEAD, "/healthz"),
        (reqwest::Method::GET, "/auth/token"),
    ] {
        let r = client
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .await
            .unwrap();
        assert_ne!(
            r.status().as_u16(),
            401,
            "{method} {path} is declared open and must bypass the chain"
        );
    }

    let p = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert!(
        p.status().as_u16() != 404 && p.status().as_u16() != 405,
        "POST /auth/token is declared open and must reach its handler, which runs the chain itself"
    );

    for (method, path) in [
        (reqwest::Method::PUT, "/auth/token"),
        (reqwest::Method::DELETE, "/auth/token"),
        (reqwest::Method::PUT, "/healthz"),
        (reqwest::Method::GET, "/auth"),
        (reqwest::Method::GET, "/auth/"),
        (reqwest::Method::GET, "/auth/token/"),
        (reqwest::Method::GET, "/auth/tokenx"),
        (reqwest::Method::GET, "/healthz/"),
        (reqwest::Method::GET, "/healthzx"),
        (reqwest::Method::GET, "/HEALTHZ"),
        (reqwest::Method::GET, "/AUTH/TOKEN"),
        (reqwest::Method::GET, "/.well-known"),
        (
            reqwest::Method::GET,
            "/.well-known/oauth-authorization-server",
        ),
        (reqwest::Method::GET, "/oauth"),
        (reqwest::Method::GET, "/oauth/authorize"),
        (reqwest::Method::POST, "/oauth/token"),
    ] {
        let r = client
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            401,
            "{method} {path} is a near miss on a declared-open route and must take the normal bar"
        );
    }
    handle.abort();
}

fn golden_cell(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
        .join(name);
    let text = std::fs::read_to_string(&path).expect("the 1.5.5 golden cell");
    serde_json::from_str(&text).expect("golden json")
}

#[tokio::test]
async fn the_hosted_login_page_moved_with_its_1_5_5_bytes() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let golden = golden_cell("http.crosscut__auth-token__GET-none.json");
    let app = application(None, None);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let got = client
        .get(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        u64::from(got.status().as_u16()),
        golden["status"].as_u64().unwrap()
    );
    for name in ["cache-control", "content-type", "content-length"] {
        assert_eq!(
            got.headers().get(name).and_then(|v| v.to_str().ok()),
            golden["headers"][name].as_str(),
            "the {name} header is 1.5.5's"
        );
    }
    let page = got.text().await.unwrap();
    assert_eq!(
        page,
        golden["body"]["text"].as_str().unwrap(),
        "the page is 1.5.5's"
    );

    let signed_out = client
        .get(format!("{base}/auth/token?logout=1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_ne!(signed_out, golden["body"]["text"].as_str().unwrap());
    handle.abort();
}
