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

#[tokio::test]
async fn the_admin_gate_admits_only_the_listed_verbs() {
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
    let directory = plugins::scratch("auth-admin-named");
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
            "role_bindings": { "test-scope-module": { "ops": { "verbs": ["post_config_apply"] } } }
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
    let token = common::credentials::token_for("ops", &["ops"], "api://auth-self-groups");
    assert!(
        [
            busbar_core_admin::verb::KernelVerb::PostConfigApply,
            busbar_core_admin::verb::KernelVerb::PostKeys,
            busbar_core_admin::verb::KernelVerb::GetKeys,
        ]
        .into_iter()
        .all(|verb| busbar_core_admin::verb::row_of(verb).is_some_and(|row| row.bound)),
        "the actual closed product table binds the named and unlisted verbs"
    );
    let router = busbar_kernel::build_router(app);
    let listed = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router.clone(),
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/admin/config/apply")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        ),
    )
    .await
    .expect("the real listed-verb request is bounded")
    .unwrap();
    assert_ne!(
        listed.status().as_u16(),
        401,
        "the actual named role authenticates"
    );
    assert_ne!(
        listed.status().as_u16(),
        403,
        "the actual named verb passes authorization"
    );
    for (method, needed) in [("POST", "full"), ("GET", "read-only")] {
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tower::ServiceExt::oneshot(
                router.clone(),
                axum::http::Request::builder()
                    .method(method)
                    .uri("/api/v1/admin/keys")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            ),
        )
        .await
        .expect("the real unlisted-verb request is bounded")
        .unwrap();
        assert_eq!(
            refused.status().as_u16(),
            403,
            "{method}: the actual role's list does not name this verb"
        );
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(refused.into_body(), 64 * 1024),
        )
        .await
        .expect("the real scope refusal body is bounded")
        .unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), format!(
            "{{\"error\":{{\"code\":\"forbidden\",\"message\":\"this endpoint requires the `{needed}` admin scope\"}}}}"),
            "the actual refusal keeps the existing scope envelope byte for byte");
    }
}

#[test]
fn actual_operator_requests_keep_credentials_out_of_core_logs() {
    use std::io::Write;
    use std::sync::Mutex;
    const EXPECTED: &str = "configured-operator-secret-46da";
    const BEARER: &str = "secret-bearer-value-7f3a";
    const HEADER: &str = "secret-header-value-91cc";
    // Test-local passive log sink. Only current-thread boot/request core events are claimed.
    #[derive(Clone, Default)]
    struct LogBytes(Arc<Mutex<Vec<u8>>>);
    impl Write for LogBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let logs = LogBytes::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime").block_on(async {
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
            let directory = plugins::scratch("auth-admin-logs");
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
            assert!(!operator.is_empty(), "the actual root registers its operator product");
            let credential = directory.join("operator-credential");
            std::fs::write(&credential, EXPECTED).expect("write the normal operator secret file");
            let signing = directory.join("signing-key");
            std::fs::write(&signing, hex::encode([9u8; 32]))
                .expect("write the actual configured signing key");
            let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                "providers": {},
                "models": {},
                "identity-providers": {
                    (operator): { "module": operator, "token": { "file": credential } }
                },
                "auth": {
                    "chain": [], "admin_auth": [operator], "signing_key": { "file": signing },
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
            for (bearer, header, expected_status) in [(EXPECTED, None, 200), (BEARER, Some(HEADER), 401)] {
                let mut request = axum::http::Request::builder()
                    .uri("/api/v1/admin/keys")
                    .header("authorization", format!("Bearer {bearer}"));
                if let Some(header) = header {
                    request = request.header("x-admin-token", header);
                }
                let response = tokio::time::timeout(std::time::Duration::from_secs(10),
                    tower::ServiceExt::oneshot(router.clone(), request.body(axum::body::Body::empty()).unwrap()))
                    .await.expect("the actual operator request is bounded").unwrap();
                assert_eq!(response.status().as_u16(), expected_status);
                tokio::time::timeout(std::time::Duration::from_secs(10),
                    axum::body::to_bytes(response.into_body(), 64 * 1024))
                    .await.expect("the actual operator response body is bounded").unwrap();
            }
            tracing::debug!("actual-operator-core-redaction-capture-live");
        });
    });
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("actual-operator-core-redaction-capture-live"),
        "{text}"
    );
    for secret in [EXPECTED, BEARER, HEADER] {
        assert!(
            !text.contains(secret),
            "a credential reached a core log line: {text}"
        );
    }
}
