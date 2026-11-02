// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::Router;

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[tokio::test]
async fn test_1_5_2_admin_path_bypasses_governance_and_mints() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (gov, _secret) = dp_gov_with_key();
    let app = crate::new_test_app().governance(gov).build();
    let (addr, handle) = dp_serve(app).await;

    let r = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(X_ADMIN_TOKEN, "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "minted-via-admin"}).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "admin token must authenticate the admin API and mint (got {})",
        r.status()
    );

    let bad = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(X_ADMIN_TOKEN, "nope")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "x"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong admin token must be rejected"
    );
    handle.abort();
}

#[tokio::test]
async fn split_admin_listener_no_double_exposure() {
    use busbar_kernel::governance::GovState;
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;
    use busbar_kernel_testkit::test_support::LaneSpec;
    use std::sync::Arc;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = crate::new_test_app()
        .lane(LaneSpec::new(
            "test-model",
            crate::linked_protocol(),
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (data_router, admin_router, _handle) = crate::build_split_routers_with_limits(
        app,
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        busbar_kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );

    async fn get(router: Router, path: &str, token: Option<&str>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut req = reqwest::Client::new().get(format!("http://{addr}{path}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let code = req.send().await.unwrap().status().as_u16();
        server.abort();
        code
    }

    let admin_path = format!("{}/keys", crate::v1::contract::ADMIN_PREFIX);

    assert_eq!(
        get(admin_router.clone(), &admin_path, Some("admintok")).await,
        200,
        "admin router must serve the admin surface"
    );

    assert_eq!(
        get(data_router.clone(), &admin_path, Some("admintok")).await,
        404,
        "data router must NOT serve the admin surface even for an authenticated admin request"
    );

    assert_eq!(get(admin_router, "/healthz", None).await, 200);
    assert_eq!(get(data_router, "/healthz", None).await, 200);
}

#[tokio::test]
async fn test_governance_admin_api() {
    use busbar_kernel::governance::GovState;
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;
    use std::sync::Arc;

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());

    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[9u8; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );

    let app = crate::new_test_app().keys_chain().governance(gov).build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let r = client
        .post(format!("{base}/api/v1/admin/keys"))
        .json(&serde_json::json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "no admin token → unauthorized");

    let r = client
        .post(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .json(&serde_json::json!({"name": "team-a", "allowed_pools": ["allowedpool"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201, "admin create → 201");
    let created: serde_json::Value = r.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let secret = created["token"].as_str().unwrap().to_string();
    assert!(secret.starts_with("bbk_"), "signed token returned once");
    assert!(
        created.get("generation_hash").is_none(),
        "hash never returned"
    );
    assert!(created.get("secret").is_none(), "no legacy secret in 1.5.0");

    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let listed: serde_json::Value = r.json().await.unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    assert!(listed["items"][0].get("generation_hash").is_none());

    let r = client
        .get(format!("{base}/api/v1/admin/keys/{id}/usage"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    let r = client
        .post(format!("{base}/allowedpool/v1/messages"))
        .bearer_auth(&secret)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        404,
        "minted key authenticates + ACL passes"
    );

    let r = client
        .delete(format!("{base}/api/v1/admin/keys/{id}"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let listed: serde_json::Value = r.json().await.unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 0, "deleted");

    handle.abort();
}

async fn dp_serve(
    app: std::sync::Arc<busbar_kernel::state::App>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

fn dp_gov_with_key() -> (std::sync::Arc<busbar_kernel::governance::GovState>, String) {
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;
    let store = std::sync::Arc::new(MemoryStore::new());
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = std::sync::Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (_k, secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "vk".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    (
        gov,
        secret
            .expose(&busbar_kernel::seal::lend())
            .as_str()
            .to_string(),
    )
}
