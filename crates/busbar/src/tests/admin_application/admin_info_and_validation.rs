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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
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

    assert!(
        body.get("config_persistence").is_none(),
        "config_persistence moved to the core/durability state store.persistence (section 10.1): {body:?}"
    );
    let durability = client
        .get(format!(
            "http://{addr}/api/v1/admin/kinds/core/instances/durability"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(durability.status().as_u16(), 200);
    let durability = json::parse_value(&durability.bytes().await.unwrap()).unwrap();
    assert_eq!(
        durability["state"],
        json::json!({"store": {"persistence": true}}),
        "whether API config changes survive restart is the core/durability state: {durability:?}"
    );
    assert_eq!(
        durability["state_schema"]["properties"]["store"]["properties"]["persistence"]["type"],
        "boolean",
        "core/durability states its own state schema: {durability:?}"
    );
    assert_eq!(
        body["warnings"],
        json::json!([]),
        "a boot without --ignore-overlay carries no overlay_ignored warning"
    );

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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
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

/// One authenticated admin GET: the status and the parsed body.
async fn admin_read(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    path: &str,
) -> (u16, json::Value) {
    let resp = client
        .get(format!("http://{addr}/api/v1/admin{path}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    (status, body)
}

/// ADMIN-API-1.6-ONE-MODEL r2 §10.1 (#317, review B N1): `/info` is node identity and nothing
/// else (no topology, no compiled-in plugin names, no process-local counters), and the Store's
/// node lease rows are the `core/process` view `nodes`, read with `kinds:read`.
#[tokio::test]
async fn info_is_node_identity_and_nodes_are_a_process_view() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_3F17A0C2D9B4";
    const WITNESS: &str =
        "actual root case info_is_node_identity_and_nodes_are_a_process_view completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "info_is_node_identity_and_nodes_are_a_process_view-actual-store",
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
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();

    let (status, info) = admin_read(&client, addr, "/info").await;
    assert_eq!(status, 200, "{info:?}");
    let mut members: Vec<String> = info
        .as_object()
        .expect("/info is an object")
        .iter()
        .map(|(name, _)| name.to_owned())
        .collect();
    members.sort();
    assert_eq!(
        members,
        [
            "config_generation",
            "deployment_id",
            "incarnation",
            "node_id",
            "started_at_ms",
            "version",
            "warnings",
        ],
        "/info is node identity only: {info:?}"
    );
    assert_eq!(
        info["warnings"],
        json::json!([]),
        "a normal boot carries no warning"
    );
    let incarnation = info["incarnation"].as_str().expect("incarnation");
    assert!(
        incarnation.len() == 32
            && incarnation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "incarnation is the 128-bit process generation, 32 lowercase hex: {incarnation}"
    );
    let started_at_ms = info["started_at_ms"].as_u64().expect("started_at_ms");
    assert!(
        started_at_ms >= 1_600_000_000_000,
        "started_at_ms is epoch milliseconds: {started_at_ms}"
    );
    let node_id = info["node_id"].as_str().expect("node_id").to_owned();

    let (status, process) = admin_read(&client, addr, "/kinds/core/instances/process").await;
    assert_eq!(status, 200, "{process:?}");
    assert!(
        process["views"]
            .as_array()
            .is_some_and(|views| views.iter().any(|v| v["view"] == "nodes")),
        "core/process offers the view `nodes`: {process:?}"
    );
    let (status, view) =
        admin_read(&client, addr, "/kinds/core/instances/process/views/nodes").await;
    assert_eq!(status, 200, "{view:?}");
    let fields: Vec<String> = view["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|f| f["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        fields,
        [
            "node_id",
            "role",
            "state",
            "started_at_ms",
            "last_seen_at_ms"
        ],
        "{view:?}"
    );
    let rows = view["rows"].as_array().expect("rows").to_vec();
    let own = rows
        .iter()
        .find(|row| row[0] == node_id.as_str())
        .expect("the view lists this process's own lease row");
    assert_eq!(own[1], "writer");
    assert_eq!(own[2], "live");
    let started = own[3].as_u64().expect("started_at_ms");
    let seen = own[4].as_u64().expect("last_seen_at_ms");
    assert!(
        started >= 1_600_000_000_000 && started <= seen,
        "lease times are epoch milliseconds, start before last seen: {own:?}"
    );

    handle.abort();
    println!("{WITNESS}");
}
