// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    application_with_auth_plugin, directory, hosted_provider_tests::assert_branded_error_page,
    plugins,
};
use base64::Engine as _;
use std::sync::Arc;

async fn application() -> (
    Arc<busbar_kernel::state::App>,
    String,
    tokio::task::JoinHandle<()>,
) {
    application_with_directory(directory::settings()).await
}

async fn application_with_directory(
    settings: serde_json::Value,
) -> (
    Arc<busbar_kernel::state::App>,
    String,
    tokio::task::JoinHandle<()>,
) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let library =
        std::path::PathBuf::from(std::env::var_os("BUSBAR_TEST_LDAP_PLUGIN").expect(
            "BUSBAR_TEST_LDAP_PLUGIN names the actual source-receipted LDAP product cdylib",
        ));
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .expect("LDAP statement reads")
        .expect("the actual LDAP product states itself");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("valid LDAP statement")
        .name;
    let secrets = plugins::scratch(&format!(
        "oauth-directory-signing-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let signing_key = secrets.join("signing-key");
    std::fs::write(&signing_key, hex::encode([7_u8; 32])).expect("write actual signing input");
    let app = application_with_auth_plugin(
        serde_json::json!({
            "providers":{},"models":{},"public_url":"https://busbar.example.com",
            "identity-providers":{"directory":{"module":module,"settings":settings,"browser_login":{}}},
            "auth":{"chain":[],"admin_auth":[],"signing_key":{"file":signing_key},
                "role_bindings":{"directory":{"members":{"group":"team"}}}},
            "groups":{"team":{"child_default":{"limits":[{"budget":500,"per":"month"}]}}},
            "advanced":{"allow_destinations":["127.0.0.1"]},
        }),
        &library,
    );
    let router = busbar_kernel::build_router(Arc::clone(&app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (app, format!("http://{address}"), handle)
}

async fn form(base: &str, refresh: bool) -> (String, serde_json::Value, String) {
    let response = reqwest::Client::new()
        .get(format!(
            "{base}/auth/token?method=directory&refresh={}",
            if refresh { "1" } else { "0" }
        ))
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "credential begin renders a form, not a 302"
    );
    let raw = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("busbar_login=")
        .unwrap()
        .to_owned();
    let decoded = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&raw)
            .unwrap(),
    )
    .unwrap();
    (raw, decoded, response.text().await.unwrap())
}

async fn submit(base: &str, raw: &str, state: &str, password: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/auth/token"))
        .header("cookie", format!("busbar_login={raw}"))
        .form(&[
            ("__state", state),
            ("username", "alice"),
            ("password", password),
        ])
        .send()
        .await
        .unwrap()
}

fn extract_key(body: &str) -> String {
    let start = body.find("bbk_").expect("a bbk_ key in the issued page");
    body[start..]
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect()
}

#[tokio::test]
async fn credential_begin_renders_the_form() {
    let (_app, base, handle) = application().await;
    let (_raw, _cookie, body) = form(&base, false).await;
    assert!(body.contains("method=\"post\"") && body.contains("action=\"/auth/token\""));
    assert!(body.contains("name=\"username\"") && body.contains("type=\"text\""));
    assert!(
        body.contains("name=\"password\"") && body.contains("type=\"password\""),
        "the password field must be masked"
    );
    assert!(
        body.contains("name=\"__state\""),
        "a CSRF field must be present"
    );
    handle.abort();
}

#[tokio::test]
async fn credential_submit_issues_via_shared_seam() {
    let (app, base, handle) = application().await;
    let (raw, cookie, _body) = form(&base, false).await;
    let response = submit(&base, &raw, cookie["state"].as_str().unwrap(), "pw").await;
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("ldap:uid=alice,dc=example"),
        "the issued page shows the actual LDAP product identity: {body}"
    );
    let key = extract_key(&body);
    assert!(app
        .governance
        .as_ref()
        .unwrap()
        .verify_token(&key, busbar_kernel::store::now(), None)
        .is_some());
    handle.abort();
}

#[tokio::test]
async fn credential_submit_wrong_password_401() {
    let (_app, base, handle) = application().await;
    let (raw, cookie, _body) = form(&base, false).await;
    let response = submit(&base, &raw, cookie["state"].as_str().unwrap(), "WRONG").await;
    assert_eq!(response.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn credential_reject_renders_branded_html() {
    let (_app, base, handle) = application().await;
    let (raw, cookie, _body) = form(&base, false).await;
    let response = submit(&base, &raw, cookie["state"].as_str().unwrap(), "WRONG").await;
    assert_eq!(response.status(), 401);
    assert_branded_error_page(&response.text().await.unwrap(), "Sign-in was declined");
    handle.abort();
}

#[tokio::test]
async fn credential_submit_state_mismatch_400() {
    let (_app, base, handle) = application().await;
    let (raw, _cookie, _body) = form(&base, false).await;
    let response = submit(&base, &raw, "WRONG", "pw").await;
    assert_eq!(response.status(), 400);
    handle.abort();
}

#[tokio::test]
async fn refresh_rotates_key_and_revokes_the_old_one() {
    let (app, base, handle) = application().await;
    let (raw, cookie, _body) = form(&base, false).await;
    let first = submit(&base, &raw, cookie["state"].as_str().unwrap(), "pw").await;
    let key1 = extract_key(&first.text().await.unwrap());
    let (raw, cookie, _body) = form(&base, true).await;
    let second = submit(&base, &raw, cookie["state"].as_str().unwrap(), "pw").await;
    let key2 = extract_key(&second.text().await.unwrap());
    assert_ne!(key1, key2, "Refresh must mint a DIFFERENT token");
    let gov = app.governance.as_ref().unwrap();
    let now = busbar_kernel::store::now();
    assert!(
        gov.verify_token(&key1, now, None).is_none(),
        "the prior token must stop verifying after Refresh (rotation)"
    );
    assert!(
        gov.verify_token(&key2, now, None).is_some(),
        "the new token verifies"
    );
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_credential_submit_does_not_starve_the_runtime() {
    let (_app, base, handle) = application_with_directory(directory::pending_settings()).await;
    let (raw, cookie, _body) = form(&base, false).await;
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let (base, raw, state) = (
                base.clone(),
                raw.clone(),
                cookie["state"].as_str().unwrap().to_owned(),
            );
            tokio::spawn(async move { submit(&base, &raw, &state, "hunter2").await.status() })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    tokio::time::timeout(std::time::Duration::from_millis(750),tokio::spawn(async {})).await
        .expect("the runtime stopped polling while four ANONYMOUS credential POSTs sat inside the actual LDAP plugin's complete_login")
        .expect("runtime canary completes");
    for task in tasks {
        assert_eq!(
            task.await.unwrap(),
            401,
            "the delayed real directory refuses the password"
        );
    }
    handle.abort();
}
