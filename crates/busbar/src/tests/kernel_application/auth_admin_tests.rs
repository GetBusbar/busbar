// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use crate::test_common as common;
use std::sync::Arc;

#[tokio::test]
async fn admin_plugin_full_binding_allows_mutation() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-full");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
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
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-capped");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
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
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-readonly");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
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
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-roleless");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);

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
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-audit-window");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual boot registers the durable admin audit seam");
    let unique = format!(
        "unbound-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let principal_id = common::credentials::principal_id(&unique);
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
    assert!(
        (1..=2).contains(&n),
        "50 forbidden requests from one actual principal produce1..=2 window-bounded audit rows, got {n}"
    );
}

#[tokio::test]
async fn the_admin_gate_admits_only_the_listed_verbs() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-named");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
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
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            format!(
                "{{\"error\":{{\"code\":\"forbidden\",\"message\":\"this endpoint requires the `{needed}` admin scope\"}}}}"
            ),
            "the actual refusal keeps the existing scope envelope byte for byte"
        );
    }
}

#[test]
fn actual_operator_requests_keep_credentials_out_of_core_logs() {
    use std::io::Write;
    use std::sync::Mutex;
    const EXPECTED: &str = "configured-operator-secret-46da";
    const BEARER: &str = "secret-bearer-value-7f3a";
    const HEADER: &str = "secret-header-value-91cc";

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
            let library_path = crate::root::test_plugins::application_store_library();
            let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
                .expect("the actual store statement reads")
                .expect("the actual store exports its statement");
            let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                .expect("the actual store statement is valid")
                .name;
            let mut manifest = plugins::manifest(
                "store",
                &module,
                crate::root::test_plugins::FIXTURE_PUBLISHER,
            );
            manifest.statement = Some(hex::encode(statement));
            let library = std::fs::read(library_path).expect("the actual store library reads");
            let directory = plugins::scratch("auth-admin-logs");
            let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual store archive");
            let settings: serde_json::Value = crate::root::test_plugins::application_store_settings(&directory);
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
            let plugin_config = crate::root::test_plugins::trusted_config(&directory);
            let anchor = crate::root::real_store::core_over(busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config).await.expect("the actual Store bootstraps its config authority")).await;
            let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
                true,
            ).await
            .expect("the actual product builds the session deployment");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, &module).await
                .expect("the actual Store binds rate-card history and usage recovery before activation");
            limits.keep().await.expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate.await;
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

#[test]
fn a_slow_admin_door_does_not_stall_healthz() {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-pending");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let mut oidc_settings = common::credentials::settings("api://auth-admin-pending");
    // READY sees an empty (valid) key set. Only VERIFY's missing-key rotation
    // needs the second fetch, so a background refresh cannot satisfy this gate.
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let signing_key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &certificate.signing_key.serialize_der(),
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let point = signing_key.public_key().as_ref();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwks = serde_json::json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "held-verifier", "alg": "ES256", "use": "sig",
        "x": b64.encode(&point[1..33]), "y": b64.encode(&point[33..65]),
    }]})
    .to_string();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                certificate.signing_key.serialize_der(),
            )),
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the actual TLS issuer");
    listener.set_nonblocking(true).unwrap();
    oidc_settings.insert(
        "ca_cert_pem".into(),
        serde_json::json!(certificate.cert.pem()),
    );
    oidc_settings.insert("jwks_ttl_secs".into(), serde_json::json!(3600));
    oidc_settings.insert("jwks_min_refetch_secs".into(), serde_json::json!(1));
    oidc_settings.insert(
        "jwks_url".into(),
        serde_json::json!(format!("https://{}/jwks", listener.local_addr().unwrap())),
    );
    let valid = common::credentials::token_for("alice", &["minters"], "api://auth-admin-pending");
    let claims = valid.split('.').nth(1).unwrap();
    let header = b64.encode(br#"{"alg":"ES256","typ":"JWT","kid":"held-verifier"}"#);
    let signed = format!("{header}.{claims}");
    let mut signature = signing_key
        .sign(&ring::rand::SystemRandom::new(), signed.as_bytes())
        .unwrap()
        .as_ref()
        .to_vec();
    signature[0] ^= 1;
    let token = format!("{signed}.{}", b64.encode(signature));

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let peer_armed = armed.clone();

    std::thread::scope(|peers| {
        let wire = peers.spawn(move || {
            struct Wire {
                socket: std::net::TcpStream,
                read: u64,
                written: u64,
            }
            impl Read for Wire {
                fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                    let count = self.socket.read(bytes)?;
                    self.read += count as u64;
                    assert!(self.read < 64 * 1024, "client wire overflow is a failure");
                    Ok(count)
                }
            }
            impl Write for Wire {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    let count = self.socket.write(bytes)?;
                    self.written += count as u64;
                    assert!(self.written <= 64 * 1024, "issuer wire overflow is a failure");
                    Ok(count)
                }
                fn flush(&mut self) -> std::io::Result<()> { self.socket.flush() }
            }
            loop {
                let deadline = Instant::now() + Duration::from_secs(10);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "the actual verifier must connect");
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("actual issuer accept failed: {error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                let connection = rustls::ServerConnection::new(tls.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection,
                    Wire { socket, read: 0, written: 0 });
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).expect("read actual TLS JWKS request");
                    request.push(byte[0]);
                    assert!(request.len() <= 8192, "bounded actual JWKS request");
                }
                assert!(request.starts_with(b"GET /jwks HTTP/1.1\r\n"));
                let gated = peer_armed.load(std::sync::atomic::Ordering::Acquire);
                let held = if gated {
                    let entered = Instant::now();
                    entered_tx.send(entered).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10))
                        .expect("release actual pending VERIFY after the unrelated probe");
                    if let Some(remaining) = Duration::from_millis(800).checked_sub(entered.elapsed()) {
                        std::thread::sleep(remaining);
                    }
                    entered.elapsed()
                } else { Duration::ZERO };
                let body = if gated { jwks.as_str() } else { r#"{"keys":[]}"# };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                stream.flush().unwrap();
                stream.conn.send_close_notify();
                let _ = stream.flush();
                if gated { return (held, stream.sock.read, stream.sock.written); }
            }
        });
        let signing = directory.join("signing-key");
        std::fs::write(&signing, hex::encode([9u8; 32]))
            .expect("write the actual configured signing key");
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {},
            "models": {},
            "identity-providers": {
                "test-scope-module": { "module": oidc_module, "max_admin_scope": "full", "settings": oidc_settings }
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("the one-worker runtime");
        let (router, _book) = runtime.block_on(async {
            let config = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the product deployment resolves");
            let plugin_config = crate::root::test_plugins::trusted_config(&directory);
            let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
                &config,
                &plugin_config,
                &directory,
            )
            .await
            .expect("the actual Store bootstraps its config authority");
            let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
                true,
            )
            .await
            .expect("the actual product builds the session deployment");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, &module).await.expect(
                "the actual Store binds rate-card history and usage recovery before activation",
            );
            limits.keep().await.expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate.await;
            }
            let app = Arc::new(app);
            (busbar_kernel::build_router(app), _book)
        });
        armed.store(true, std::sync::atomic::Ordering::Release);

        std::thread::sleep(Duration::from_millis(1100));
        let admin_router = router.clone();
        let admin = runtime.spawn(async move {
            let response = tokio::time::timeout(
                Duration::from_secs(10),
                tower::ServiceExt::oneshot(
                    admin_router,
                    axum::http::Request::builder()
                        .uri("/api/v1/admin/keys")
                        .header("authorization", format!("Bearer {token}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .expect("the real admin request completes within its bound")
            .unwrap();
            let status = response.status().as_u16();
            tokio::time::timeout(
                Duration::from_secs(10),
                axum::body::to_bytes(response.into_body(), 64 * 1024),
            )
            .await
            .expect("the real admin response body is bounded")
            .unwrap();
            status
        });
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the actual admin verifier reaches its real TLS/JWKS need");
        let pending_before = !admin.is_finished();
        let (health_tx, health_rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        runtime.spawn(async move {
            let response = tokio::time::timeout(
                Duration::from_secs(10),
                tower::ServiceExt::oneshot(
                    router,
                    axum::http::Request::builder()
                        .uri("/healthz")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .expect("the actual health request is bounded")
            .unwrap();
            health_tx.send(response.status().as_u16()).unwrap();
        });
        let health = health_rx.recv_timeout(Duration::from_secs(2));
        let elapsed = start.elapsed();
        let pending_after = !admin.is_finished();
        release_tx
            .send(())
            .expect("release the owned external wire peer");
        let status = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), admin)
                .await
                .expect("the released real admin request finishes")
                .expect("the request task joins")
        });
        let (held, client_bytes, issuer_bytes) = wire.join().expect("the owned wire peer joins");
        assert!(
            matches!(health, Ok(200 | 503)),
            "/healthz returns a health verdict while actual admin verification awaits: {health:?}"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "/healthz stalled for {elapsed:?}"
        );
        assert_eq!(
            status, 401,
            "the genuine invalid signature is refused after JWKS completes"
        );
        assert!(
            pending_before && pending_after,
            "health must run during real verifier Pending"
        );
        assert!(
            held >= Duration::from_millis(800),
            "the actual network need stayed held"
        );
        assert!(
            client_bytes > 1 && issuer_bytes > 0,
            "actual TLS bytes crossed both directions"
        );
    });
}

#[tokio::test]
async fn external_admin_verifier_receives_bearer_and_admin_header_candidates() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-candidates");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    let token = common::credentials::token_for("alice", &["minters"], "api://auth-self-groups");
    let router = busbar_kernel::build_router(app);
    for header in ["authorization", "x-admin-token"] {
        for (candidate, expected) in [(token.as_str(), 200), ("not-a-jwt", 401)] {
            let value = if header == "authorization" {
                format!("Bearer {candidate}")
            } else {
                candidate.to_string()
            };
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tower::ServiceExt::oneshot(
                    router.clone(),
                    axum::http::Request::builder()
                        .uri("/api/v1/admin/keys")
                        .header(header, value)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .expect("the actual external verifier request is bounded")
            .unwrap();
            assert_eq!(
                response.status().as_u16(),
                expected,
                "{header}: actual external verifier judges the selected candidate"
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                axum::body::to_bytes(response.into_body(), 64 * 1024),
            )
            .await
            .expect("the actual verifier response body is bounded")
            .unwrap();
        }
    }
}

#[tokio::test]
async fn every_request_is_verified_by_the_door_and_the_kernel_caches_no_verdict() {
    use busbar_contract::auth::{BeginLogin, LoginKind};
    use busbar_contract::auth_calls::{
        AuthCalls, IssuedShape, LoginCall, LoginCallback, VerifyAnswer, VerifyRequest, Verifying,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountActualCalls {
        actual: Arc<dyn AuthCalls>,
        verifies: Arc<AtomicUsize>,
        probes: Arc<AtomicUsize>,
    }
    impl AuthCalls for CountActualCalls {
        fn name(&self) -> &str {
            self.actual.name()
        }
        fn facts(&self) -> u32 {
            self.actual.facts()
        }
        fn credential_kinds(&self) -> Vec<String> {
            self.actual.credential_kinds()
        }
        fn issued_shape(&self) -> Option<IssuedShape> {
            self.actual.issued_shape()
        }
        fn inbound_points(&self) -> busbar_contract::abi::auth::AuthPoints {
            self.actual.inbound_points()
        }
        fn carriers(&self) -> Vec<String> {
            self.actual.carriers()
        }
        fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            self.actual.verify_now(request)
        }
        fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
            self.verifies.fetch_add(1, Ordering::SeqCst);
            self.actual.verify(request)
        }
        fn refresh(&self) -> Result<u64, String> {
            self.actual.refresh()
        }
        fn login_kind(&self) -> Option<LoginKind> {
            self.actual.login_kind()
        }
        fn begin_login(&self, request: BeginLogin) -> Box<dyn LoginCall> {
            self.actual.begin_login(request)
        }
        fn complete_login(&self, request: LoginCallback) -> Box<dyn LoginCall> {
            self.actual.complete_login(request)
        }
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-admin-no-kernel-cache");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let mut app = Arc::new(app);
    let verifies = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(AtomicUsize::new(0));
    let module = Arc::get_mut(
        &mut Arc::get_mut(&mut app)
            .expect("ordinary new App is unshared")
            .admin_modules,
    )
    .expect("ordinary new admin chain is unshared")
    .modules
    .get_mut("test-scope-module")
    .expect("the configured actual OIDC instance exists");
    module.calls = Arc::new(CountActualCalls {
        actual: module.calls.clone(),
        verifies: verifies.clone(),
        probes: probes.clone(),
    });
    let token = common::credentials::token_for("alice", &["minters"], "api://auth-self-groups");
    let router = busbar_kernel::build_router(app);
    for _ in 0..2 {
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
        .expect("the actual repeated credential request is bounded")
        .unwrap();
        assert_eq!(
            response.status().as_u16(),
            200,
            "the real signed credential is accepted"
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), 64 * 1024),
        )
        .await
        .expect("the actual repeated response body is bounded")
        .unwrap();
    }
    assert_eq!(
        verifies.load(Ordering::SeqCst),
        2,
        "one actual door verify per identical request"
    );
    assert_eq!(
        probes.load(Ordering::SeqCst),
        0,
        "request paths use actual awaited verification"
    );
}
