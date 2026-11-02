// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn test_audience_bound_token_is_rejected_on_the_data_plane() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("test_audience_bound_token_is_rejected_on_the_data_plane");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            (operator): { "module": operator, "token": { "file": operator_secret } }
        },
        "auth": {
            "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": {}
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
    )
    .expect("the actual product builds the session deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("normal root opened governance");
    let now = busbar_kernel::store::now();
    let (key, secret) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "auth-data-gate".into(),
                allowed_pools: Some(vec!["pa".into()]),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .expect("mint through actual root governance and Store");
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let verifier = busbar_kernel::governance::signing::TokenVerifier::single(
        signer.kid(),
        signer.verifying_key(),
    );
    let generation = verifier
        .verify(secret.expose(&busbar_kernel::seal::lend()), now, None)
        .expect("plain sibling claims")
        .generation;
    let bound = signer.mint_for_audience(
        &key.id,
        now + 3600,
        generation.as_deref(),
        "https://busbar.example.com/rpc",
        Some("client-1"),
    );
    let bound_header = format!("Bearer {bound}");
    let plain_header = format!("Bearer {}", secret.expose(&busbar_kernel::seal::lend()));
    let router = busbar_kernel::build_router(app);
    let mut statuses = Vec::new();
    for (method, uri, carrier) in [
        (
            "POST",
            "/pa/v1/messages",
            Some(("authorization", bound_header.as_str())),
        ),
        (
            "GET",
            "/stats",
            Some(("authorization", bound_header.as_str())),
        ),
        (
            "GET",
            "/stats",
            Some(("authorization", plain_header.as_str())),
        ),
    ] {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        if let Some((name, value)) = carrier {
            request = request.header(name, value);
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(router.clone(), request.body(axum::body::Body::from(
                r#"{"model":"pa","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#)).unwrap()))
            .await.expect("the actual root data gate request is bounded").unwrap();
        statuses.push(response.status().as_u16());
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), 64 * 1024),
        )
        .await
        .expect("the actual data gate response body is bounded")
        .unwrap();
    }
    assert_eq!(
        statuses[0], 401,
        "audience-bound token refused on data-plane ingress"
    );
    assert_eq!(
        statuses[1], 401,
        "audience-bound token refused on chain-only /stats"
    );
    assert_ne!(statuses[2], 401, "plain data-plane sibling still admitted");
}

#[tokio::test]
async fn test_governance_rejects_empty_token_even_if_empty_secret_key_exists() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory =
        plugins::scratch("test_governance_rejects_empty_token_even_if_empty_secret_key_exists");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            (operator): { "module": operator, "token": { "file": operator_secret } }
        },
        "auth": {
            "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": {}
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    anchor
        .records
        .put_key(&busbar_kernel::governance::VirtualKey {
            id: "empty".into(),
            generation_hash: busbar_contract::redacted::sha256_hex(b""),
            name: "empty".into(),
            allowed_scopes: Some(vec![busbar_contract::records::ScopeRef::pool("pa")]),
            enabled: true,
            created_at: 0,
            revision: 1,
            ..Default::default()
        })
        .expect("the actual Store contains the empty-secret-hash row before root cache load");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
    )
    .expect("the actual product builds the session deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let router = busbar_kernel::build_router(app);
    let mut statuses = Vec::new();
    for (method, uri, carrier) in [
        ("POST", "/pa/v1/messages", None),
        ("POST", "/pa/v1/messages", Some(("x-api-key", ""))),
    ] {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        if let Some((name, value)) = carrier {
            request = request.header(name, value);
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(router.clone(), request.body(axum::body::Body::from(
                r#"{"model":"pa","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#)).unwrap()))
            .await.expect("the actual root data gate request is bounded").unwrap();
        statuses.push(response.status().as_u16());
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), 64 * 1024),
        )
        .await
        .expect("the actual data gate response body is bounded")
        .unwrap();
    }
    assert_eq!(
        statuses[0], 401,
        "absent credential refused despite empty-secret-hash row"
    );
    assert_eq!(statuses[1], 401, "present-but-empty credential refused");
}

#[tokio::test]
async fn test_governance_active_with_admin_token_rejects_missing_vkey() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory =
        plugins::scratch("test_governance_active_with_admin_token_rejects_missing_vkey");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            (operator): { "module": operator, "token": { "file": operator_secret } }
        },
        "auth": {
            "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": {}
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
    )
    .expect("the actual product builds the session deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let router = busbar_kernel::build_router(app);
    let mut statuses = Vec::new();
    for (method, uri, carrier) in [("POST", "/pa/v1/messages", None::<(&str, &str)>)] {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        if let Some((name, value)) = carrier {
            request = request.header(name, value);
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(router.clone(), request.body(axum::body::Body::from(
                r#"{"model":"pa","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#)).unwrap()))
            .await.expect("the actual root data gate request is bounded").unwrap();
        statuses.push(response.status().as_u16());
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), 64 * 1024),
        )
        .await
        .expect("the actual data gate response body is bounded")
        .unwrap();
    }
    assert_eq!(
        statuses[0], 401,
        "active governance with keys chain requires a virtual key"
    );
}

#[tokio::test]
async fn test_1_5_2_keys_chain_disabled_vkey_rejected() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("test_1_5_2_keys_chain_disabled_vkey_rejected");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            (operator): { "module": operator, "token": { "file": operator_secret } }
        },
        "auth": {
            "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": {}
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
    )
    .expect("the actual product builds the session deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("normal root opened governance");
    let now = busbar_kernel::store::now();
    let (key, secret) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "auth-data-gate".into(),
                allowed_pools: Some(vec!["pa".into()]),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .expect("mint through actual root governance and Store");
    gov.update_key(&key.id, Some(false), None)
        .expect("disable actual persisted key");
    let bearer = format!("Bearer {}", secret.expose(&busbar_kernel::seal::lend()));
    let router = busbar_kernel::build_router(app);
    let mut statuses = Vec::new();
    for (method, uri, carrier) in [(
        "POST",
        "/pa/v1/messages",
        Some(("authorization", bearer.as_str())),
    )] {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        if let Some((name, value)) = carrier {
            request = request.header(name, value);
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(router.clone(), request.body(axum::body::Body::from(
                r#"{"model":"pa","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#)).unwrap()))
            .await.expect("the actual root data gate request is bounded").unwrap();
        statuses.push(response.status().as_u16());
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), 64 * 1024),
        )
        .await
        .expect("the actual data gate response body is bounded")
        .unwrap();
    }
    assert_eq!(
        statuses[0], 401,
        "a disabled vkey is never re-admitted via synth"
    );
}
