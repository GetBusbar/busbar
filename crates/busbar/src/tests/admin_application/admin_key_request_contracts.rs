// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonContainerTrait as _;
use busbar_contract::json::{self, JsonValueTrait as _};

#[tokio::test]
async fn test_create_list_usage_roundtrip_through_spawn_blocking() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_4BB2BCB58411";
    const WITNESS: &str =
        "actual root case test_create_list_usage_roundtrip_through_spawn_blocking completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_list_usage_roundtrip_through_spawn_blocking-actual-store",
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

    let created = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let body = json::parse_value(&created.bytes().await.unwrap()).unwrap();
    let id = body["id"].as_str().unwrap().to_string();
    assert!(
        body["token"]
            .as_str()
            .is_some_and(|t| t.starts_with("bbk_")),
        "signed token returned once on create"
    );
    assert!(
        body["generation_hash"].is_null(),
        "generation_hash must never be exposed"
    );

    let listed = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status().as_u16(), 200);
    let lb = json::parse_value(&listed.bytes().await.unwrap()).unwrap();
    assert_eq!(lb["items"].as_array().unwrap().len(), 1);
    assert!(
        lb["items"][0]["secret"].is_null(),
        "list must not leak secrets"
    );

    let usage = client
        .get(format!("http://{addr}/api/v1/admin/keys/{id}/usage"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(usage.status().as_u16(), 200);
    let ub = json::parse_value(&usage.bytes().await.unwrap()).unwrap();
    assert_eq!(ub["id"], id);
    assert!(
        ub["rate_headroom"].is_null(),
        "an inline-cap-free key has no headroom signal: {ub}"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_create_key_rejects_removed_budget_period_field() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_F97AC2AA9B1A";
    const WITNESS: &str =
        "actual root case test_create_key_rejects_removed_budget_period_field completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_key_rejects_removed_budget_period_field-actual-store",
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
    let url = format!("http://{addr}/api/v1/admin/keys");

    for removed in ["total", "daily", "weekly", ""] {
        let resp = client
            .post(&url)
            .header("authorization", "Bearer admintok")
            .json(&json::json!({"name": "k", "budget_period": removed}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "the removed budget_period field must 400 via deny_unknown_fields (value '{removed}')"
        );
        let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
        assert_eq!(
            body["error"]["code"],
            "invalid_request", // frozen v1 envelope: keys speak the SAME code enum
            "400 error code must be invalid_request: {body}"
        );
    }

    let resp = client
        .post(&url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "a pure-auth body still mints");
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert!(
        body.get("budget_period").is_none() || body["budget_period"].is_null(),
        "the key surface no longer carries budget_period: {body}"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_create_key_rejects_unsafe_labels() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_D58E8368BEE2";
    const WITNESS: &str = "actual root case test_create_key_rejects_unsafe_labels completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_key_rejects_unsafe_labels-actual-store",
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
    let url = format!("http://{addr}/api/v1/admin/keys");

    let post = |labels: json::Value| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("authorization", "Bearer admintok")
                .json(&json::json!({"name": "k", "labels": labels}))
                .send()
                .await
                .unwrap()
        }
    };

    let resp = post(json::json!({"key": "oops"})).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a reserved 'key' label must be rejected"
    );
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("reserved"),
        "400 body must name the reserved-label reason: {body}"
    );

    for reserved in ["bucket", "model", "tier"] {
        let resp = post(json::json!({ reserved: "x" })).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "reserved label '{reserved}' must be rejected"
        );
    }

    let mut many = json::Map::new();
    for i in 0..100 {
        many.insert(&format!("l{i}"), json::json!("v"));
    }
    let resp = post(json::Value::from(many)).await;
    assert_eq!(resp.status().as_u16(), 400, "100 labels must be rejected");
    assert!(
        json::parse_value(&resp.bytes().await.unwrap()).unwrap()["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("too many labels"),
    );

    let resp = post(json::json!({"team-name": "growth"})).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an invalid label name (hyphen) must be rejected"
    );

    let resp = post(json::json!({"1team": "growth"})).await;
    assert_eq!(resp.status().as_u16(), 400, "leading-digit name rejected");

    let resp = post(json::json!({"team": "x".repeat(257)})).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an over-long label value must be rejected"
    );

    let resp = post(json::json!({"team": "growth", "env": "prod"})).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "a valid label set must still mint"
    );
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["labels"]["team"], "growth");
    assert_eq!(body["labels"]["env"], "prod");

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_create_key_name_length_boundary_is_exact() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_64FE1E7E1257";
    const WITNESS: &str =
        "actual root case test_create_key_name_length_boundary_is_exact completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_key_name_length_boundary_is_exact-actual-store",
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
    let url = format!("http://{addr}/api/v1/admin/keys");

    let post = |name: String| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("authorization", "Bearer admintok")
                .json(&json::json!({"name": name}))
                .send()
                .await
                .unwrap()
        }
    };

    let at_max = "n".repeat(256);
    let resp = post(at_max).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "a name of exactly 256 chars must mint"
    );

    let over_max = "n".repeat(257);
    let resp = post(over_max).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a name of 257 chars must be rejected"
    );
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("256 characters"),
        "the 400 body must name the length reason: {body}"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_create_key_rejects_removed_max_budget_cents_field() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_B106E70A9CB7";
    const WITNESS: &str =
        "actual root case test_create_key_rejects_removed_max_budget_cents_field completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_key_rejects_removed_max_budget_cents_field-actual-store",
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
    let url = format!("http://{addr}/api/v1/admin/keys");

    for value in [-1_i64, 0, 100_000] {
        let resp = client
            .post(&url)
            .header("authorization", "Bearer admintok")
            .json(&json::json!({"name": "k", "max_budget_cents": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "the removed max_budget_cents field must 400 via deny_unknown_fields (value {value})"
        );
        let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
        assert_eq!(
            body["error"]["code"], "invalid_request",
            "400 error code must be invalid_request: {body}"
        );
    }

    let resp = client
        .post(&url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "a pure-auth body still mints");
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert!(
        body.get("max_budget_cents").is_none() || body["max_budget_cents"].is_null(),
        "the key surface no longer carries max_budget_cents: {body}"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_patch_key_enables_disables_and_validates_at_create_parity() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_DD384470DE1D";
    const WITNESS: &str =
        "actual root case test_patch_key_enables_disables_and_validates_at_create_parity completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_patch_key_enables_disables_and_validates_at_create_parity-actual-store",
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
    let base = format!("http://{addr}/api/v1/admin/keys");

    let created = json::parse_value(
        &client
            .post(&base)
            .header("authorization", "Bearer admintok")
            .json(&json::json!({"name": "k"}))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let key_url = format!("{base}/{id}");

    let no_tok = client
        .patch(&key_url)
        .json(&json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_ne!(no_tok.status().as_u16(), 200, "PATCH must be admin-gated");

    let disabled = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status().as_u16(), 200);
    let body = json::parse_value(&disabled.bytes().await.unwrap()).unwrap();
    assert_eq!(body["enabled"], false, "key is disabled: {body}");

    for bad in [
        json::json!({"max_budget_cents": -1}),
        json::json!({"rpm_limit": 0}),
        json::json!({"tpm_limit": 0}),
    ] {
        let r = client
            .patch(&key_url)
            .header("authorization", "Bearer admintok")
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "PATCH must reject {bad} with 400");
    }

    let missing = client
        .patch(format!("{base}/vk_nope"))
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    // Revoked is terminal: a PATCH {enabled:true} on a revoked key is refused with a coded 409,
    // audited as a rejected key.patch, and the key stays revoked.
    let revoked = client
        .post(format!("{key_url}/revoke"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status().as_u16(), 200);
    let reenable = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reenable.status().as_u16(),
        409,
        "a revoked key is never re-enabled"
    );
    let body = json::parse_value(&reenable.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body,
        json::json!({"error": {"code": "conflict", "message": format!(
            "BUSBAR-4044: key '{id}' is revoked, and a revoked key is never re-enabled; delete it \
             instead, and a self-serve subject's next sign-in issues a new key. See \
             https://getbusbar.com/docs/1.6/errors/BUSBAR-4044"
        )}}),
    );
    let after = json::parse_value(
        &client
            .get(&key_url)
            .header("authorization", "Bearer admintok")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(after["enabled"], false, "the key stays revoked: {after}");
    assert_eq!(after["state"], "revoked", "the key stays revoked: {after}");

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_create_key_rejects_removed_rate_limit_fields() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_C38524ADD09A";
    const WITNESS: &str =
        "actual root case test_create_key_rejects_removed_rate_limit_fields completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_key_rejects_removed_rate_limit_fields-actual-store",
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
    let url = format!("http://{addr}/api/v1/admin/keys");

    for field in ["rpm_limit", "tpm_limit"] {
        for value in [0, 5] {
            let resp = client
                .post(&url)
                .header("authorization", "Bearer admintok")
                .json(&json::json!({"name": "k", field: value}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                400,
                "the removed {field} field must 400 via deny_unknown_fields (value {value})"
            );
            let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
            assert_eq!(
                body["error"]["code"], "invalid_request",
                "400 error code must be invalid_request: {body}"
            );
        }
    }

    let resp = client
        .post(&url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "a pure-auth body still mints");
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert!(
        body.get("rpm_limit").is_none() || body["rpm_limit"].is_null(),
        "the key surface no longer carries rpm_limit: {body}"
    );
    assert!(
        body.get("tpm_limit").is_none() || body["tpm_limit"].is_null(),
        "the key surface no longer carries tpm_limit: {body}"
    );

    handle.abort();
    println!("{WITNESS}");
}
