// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn admin_plugin_full_binding_allows_mutation() {
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
    let directory = plugins::scratch("auth-admin-full");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "test-scope-module": { "module": oidc_module, "max_admin_scope": "full", "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": [], "admin_auth": ["test-scope-module"], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "test-scope-module": { "minters": { "admin_scope": "full" } } }
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
    let token = common::credentials::token_for("alice", &["minters"], "api://auth-self-groups");
    assert!(
        busbar_core_admin::verb::row_of(busbar_core_admin::verb::KernelVerb::PostHooks)
            .is_some_and(|row| row.bound),
        "the actual product binds the mutation verb"
    );
    let router = busbar_kernel::build_router(app);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/admin/hooks")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        ),
    )
    .await
    .expect("the actual delegated mutation request is bounded")
    .unwrap();
    assert_ne!(
        response.status().as_u16(),
        401,
        "full binding must authenticate"
    );
    assert_ne!(
        response.status().as_u16(),
        403,
        "full binding satisfies the actual mutation scope"
    );
}

#[tokio::test]
async fn admin_max_admin_scope_caps_binding() {
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
    let directory = plugins::scratch("auth-admin-capped");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "test-scope-module": { "module": oidc_module, "max_admin_scope": "read-only", "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": [], "admin_auth": ["test-scope-module"], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "test-scope-module": { "ops": { "admin_scope": "full" } } }
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
    let token = common::credentials::token_for("alice", &["ops"], "api://auth-self-groups");
    assert!(
        busbar_core_admin::verb::row_of(busbar_core_admin::verb::KernelVerb::PostHooks)
            .is_some_and(|row| row.bound),
        "the actual product binds the mutation verb"
    );
    let router = busbar_kernel::build_router(app);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/admin/hooks")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        ),
    )
    .await
    .expect("the actual delegated mutation request is bounded")
    .unwrap();
    assert_eq!(
        response.status().as_u16(),
        403,
        "a read-only ceiling caps a full binding below the actual Full mutation scope"
    );
}

#[tokio::test]
async fn admin_plugin_readonly_binding_get_ok_post_403() {
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
    let directory = plugins::scratch("auth-admin-readonly");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "test-scope-module": { "module": oidc_module, "max_admin_scope": "read-only", "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": [], "admin_auth": ["test-scope-module"], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "test-scope-module": { "viewers": { "admin_scope": "read-only" } } }
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
    let token = common::credentials::token_for("alice", &["viewers"], "api://auth-self-groups");
    let router = busbar_kernel::build_router(app);
    let get = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router.clone(),
            axum::http::Request::builder()
                .uri("/api/v1/admin/keys")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the actual delegated read is bounded")
    .unwrap();
    assert_ne!(
        get.status().as_u16(),
        403,
        "read-only binding satisfies the actual ReadOnly scope"
    );
    assert_ne!(
        get.status().as_u16(),
        401,
        "the real OIDC credential authenticates"
    );
    assert_eq!(
        get.status().as_u16(),
        200,
        "the actual key-list handler answers"
    );
    let post = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/admin/hooks")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        ),
    )
    .await
    .expect("the actual delegated mutation refusal is bounded")
    .unwrap();
    assert_eq!(
        post.status().as_u16(),
        403,
        "read-only binding cannot mutate"
    );
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(post.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual forbidden envelope is bounded")
    .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body.contains("\"forbidden\""),
        "the frozen forbidden envelope remains: {body}"
    );
}

#[tokio::test]
async fn roleless_external_admin_principal_denied() {
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
    let directory = plugins::scratch("auth-admin-roleless");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "ext-admin", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "ext-admin": { "module": oidc_module, "max_admin_scope": "full", "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": [], "admin_auth": ["ext-admin"], "signing_key": { "file": signing },
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
    // The actual OIDC product namespaces the subject. The raw operator-id collision policy
    // is separately pinned as Principal DATA by auth::tests::admin_scope_resolution.
    let token = common::credentials::token_for("admin", &[], "api://auth-self-groups");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            busbar_kernel::build_router(app),
            axum::http::Request::builder()
                .uri("/api/v1/admin/keys")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the actual roleless principal refusal is bounded")
    .unwrap();
    assert_eq!(
        response.status().as_u16(),
        403,
        "a genuinely identified roleless external principal earns no admin grant"
    );
}

#[tokio::test]
async fn forbidden_admin_requests_audit_once_per_window() {
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
    let directory = plugins::scratch("auth-admin-audit-window");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "test-scope-module": { "module": oidc_module, "max_admin_scope": "full", "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": [], "admin_auth": ["test-scope-module"], "signing_key": { "file": signing },
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
    let unique = format!(
        "unbound-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let principal_id = format!("oidc:{unique}");
    let token =
        common::credentials::token_for(&unique, &[unique.as_str()], "api://auth-self-groups");
    let router = busbar_kernel::build_router(app);
    for _ in 0..50 {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(
                router.clone(),
                axum::http::Request::builder()
                    .uri("/api/v1/admin/keys")
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("each real forbidden request is bounded")
        .unwrap();
        assert_eq!(
            response.status().as_u16(),
            403,
            "an authenticated unbound role is forbidden even on an actual ReadOnly GET"
        );
    }
    let n = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, busbar_kernel::audit_ring::MAX_AUDIT_ENTRIES, None, None)
        .iter()
        .filter(|entry| entry.action == "admin.forbidden" && entry.principal == principal_id)
        .count();
    assert!((1..=2).contains(&n),
        "50 forbidden requests from one actual principal produce1..=2 window-bounded audit rows, got {n}");
}
