// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::{self, JsonValueTrait as _};

#[tokio::test]
async fn test_admin_v1_info_reports_version_features_and_topology() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_ECF98D34EBFD";
    const WITNESS: &str =
        "actual root case test_admin_v1_info_reports_version_features_and_topology completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_info_reports_version_features_and_topology-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let unauth = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "v1/info must be admin-guarded"
    );

    let resp = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "info must report the build version"
    );

    assert_eq!(body["build"]["weighted_floor"], json::json!(true));
    let auth_modules = body["build"]["auth_modules"].as_array().unwrap();
    assert!(
        auth_modules.iter().any(|m| m == "keys"),
        "auth_modules must contain the built-in `keys` verifier: {auth_modules:?}"
    );
    assert_eq!(
        auth_modules
            .iter()
            .any(|m| m == busbar_kernel::config::operator_provider()),
        busbar_kernel::preflight::linked_auth_names()
            .contains(&busbar_kernel::config::operator_provider()),
        "auth_modules must contain the operator credential iff its row is linked: {auth_modules:?}"
    );

    assert_eq!(
        body["build"]["hook_plugins"],
        json::json!(busbar_kernel::preflight::root_rows().hook_names),
        "hook_plugins must be exactly the linked hook rows the root's install record carries"
    );

    assert!(body["topology"]["pools"].is_number());
    assert!(body["topology"]["models"].is_number());
    assert!(body["topology"]["providers"].is_number());

    assert_eq!(body["config_persistence"], true);
    assert!(body.get("overlay_ignored").is_none());

    let deployment_id = body["deployment_id"].as_str().expect("deployment_id");
    assert!(
        deployment_id
            .strip_prefix("dep_")
            .is_some_and(|h| h.len() == 32
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "deployment_id is dep_ + 32 lowercase hex: {deployment_id}"
    );
    let node_id = body["node_id"].as_str().expect("node_id");
    assert!(
        node_id.strip_prefix("node_").is_some_and(|h| h.len() == 16
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "node_id is node_ + 16 lowercase hex: {node_id}"
    );
    let nodes = body["nodes"].as_array().expect("nodes");
    let own = nodes
        .iter()
        .find(|n| n["node_id"] == node_id)
        .expect("nodes lists this process's own lease row");
    assert_eq!(own["state"], "live");
    assert_eq!(own["role"], "writer");
    assert!(own["started_at"].as_u64().unwrap() <= own["last_seen_at"].as_u64().unwrap());

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_auth_read() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_024DA465EEE4";
    const WITNESS: &str = "actual root case test_admin_v1_auth_read completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_admin_v1_auth_read-actual-store");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let body = client
        .get(format!("http://{addr}/api/v1/admin/auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let body = json::parse_value(&body).unwrap();
    assert_eq!(body["chain"], json::json!([]));
    assert_eq!(body["open"], true, "no explicit chain → open front door");
    assert_eq!(body["upstream_credentials"], "own");

    assert!(body.get("client_tokens").is_none());

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_malformed_body_returns_generic_400_no_input_fragment() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_B4C1C47A3742";
    const WITNESS: &str = "actual root case test_admin_malformed_body_returns_generic_400_no_input_fragment completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_malformed_body_returns_generic_400_no_input_fragment-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let secret_fragment = "SUPER_SECRET_AWS_KEY_abc123";
    let malformed = format!(r#"{{"name": "k", "secret_access_key": "{secret_fragment}" "#);

    for path in ["/api/v1/admin/keys", "/api/v1/admin/keys/some-id"] {
        let req = if path == "/api/v1/admin/keys" {
            client.post(format!("http://{addr}{path}"))
        } else {
            client.patch(format!("http://{addr}{path}"))
        };
        let resp = req
            .header("x-admin-token", "admintok")
            .header("content-type", busbar_contract::protocol::APPLICATION_JSON)
            .body(malformed.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "malformed body on {path} must be 400"
        );
        let text = resp.text().await.unwrap();
        assert!(
            !text.contains(secret_fragment),
            "the 400 body on {path} must NOT echo any input fragment; got {text}"
        );

        assert!(
            !text.contains("expected")
                && !text.contains("column")
                && !text.contains("EOF")
                && !text.contains("line"),
            "the 400 body on {path} must NOT contain serde error text; got {text}"
        );
        let body = json::parse_value(text.as_bytes()).unwrap();
        assert_eq!(
            body["error"]["message"], "invalid JSON",
            "the 400 body on {path} must be the generic envelope; got {text}"
        );
        assert_eq!(
            body["error"]["code"],
            "invalid_request", // frozen v1 envelope: keys speak the SAME code enum
            "the 400 error code must be invalid_request; got {text}"
        );
    }

    handle.abort();
    println!("{WITNESS}");
}
