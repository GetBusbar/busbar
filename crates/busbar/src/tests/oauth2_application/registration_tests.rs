// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::application;
use busbar_core_oauth2::config::OauthAsCfg;
use std::sync::Arc;

const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const SCOPE: &str = "read";

async fn serve() -> (String, Arc<busbar_kernel::state::App>) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let config = OauthAsCfg {
        issuer: origin.clone(),
        default_grant: vec![SCOPE.into()],
        ..Default::default()
    };
    let app = application(Some(&config), None);
    let router = busbar_kernel::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (origin, app)
}

async fn register(origin: &str, body: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("{origin}/register"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("register")
        .status()
        .as_u16()
}

fn registration(name: &str) -> String {
    serde_json::json!({
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": "none",
        "response_types": ["code"],
        "grant_types": ["authorization_code", "refresh_token"],
        "client_name": name,
        "scope": SCOPE,
    })
    .to_string()
}

#[tokio::test]
async fn refused_registrations_do_not_close_registration_for_everyone() {
    let (origin, _app) = serve().await;
    for i in 0..10 {
        let status = register(&origin, &registration(&format!("busbar {i}"))).await;
        assert_ne!(
            status, 201,
            "a name impersonating the deployment is refused"
        );
    }
    for _ in 0..10 {
        let status = register(&origin, "{ not a registration").await;
        assert_ne!(status, 201, "a body that does not parse is refused");
    }
    assert_eq!(
        register(&origin, &registration("an agent")).await,
        201,
        "a legitimate registration is admitted after another caller's refusals"
    );
}

#[tokio::test]
async fn admitted_registrations_keep_the_ceiling() {
    let (origin, _app) = serve().await;
    for i in 0..60 {
        assert_eq!(
            register(&origin, &registration(&format!("agent {i}"))).await,
            201,
            "registration {i} is inside the ceiling"
        );
    }
    assert_ne!(
        register(&origin, &registration("one too many")).await,
        201,
        "the sixty-first registration in a minute is refused"
    );
}
