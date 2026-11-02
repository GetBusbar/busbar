// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn without_an_authorization_server_a_dpop_presentation_is_no_credential() {
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
    let directory = plugins::scratch("auth-dpop-no-as");
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
    common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "corp": { "eng": { "group": "team" } } }
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
    assert!(
        app.oauth_as.is_none(),
        "precondition: no actual authorization server is configured"
    );
    let token = common::credentials::token_for("alice", &["eng"], "api://auth-self-groups");
    let router = busbar_kernel::build_router(app);
    let absent = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router.clone(),
            axum::http::Request::builder()
                .uri("/stats")
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the actual absent-credential request is bounded")
    .unwrap();
    let absent_status = absent.status().as_u16();
    let absent_body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(absent.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual refusal body is bounded")
    .unwrap();
    let presented = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router.clone(),
            axum::http::Request::builder()
                .uri("/stats")
                .header("authorization", format!("DPoP {token}"))
                .header("dpop", "a.b.c")
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the actual no-AS DPoP request is bounded")
    .unwrap();
    let presented_status = presented.status().as_u16();
    let presented_body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(presented.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual no-AS DPoP body is bounded")
    .unwrap();
    assert_eq!(absent_status, 401, "the actual chain requires a credential");
    assert_eq!(
        (presented_status, presented_body),
        (absent_status, absent_body),
        "the DPoP header is not a credential carrier with no authorization server"
    );
    let genuine = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router.clone(),
            axum::http::Request::builder()
                .uri("/stats")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the actual genuine OIDC bearer request is bounded")
    .unwrap();
    assert_eq!(
        genuine.status().as_u16(),
        200,
        "a genuinely signed OIDC bearer is admitted"
    );
    let anonymous_exchange = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router,
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/token")
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the actual anonymous exchange is bounded")
    .unwrap();
    let status = anonymous_exchange.status().as_u16();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(anonymous_exchange.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual anonymous exchange body is bounded")
    .unwrap();
    assert_eq!(
        (status, std::str::from_utf8(&bytes).unwrap()),
        (401, r#"{"error":"not authenticated"}"#)
    );
}
