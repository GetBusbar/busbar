// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use busbar_contract::json;
use busbar_contract::json::JsonValueTrait as _;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn hook_register_and_replace_refuse_oversized_timeouts_without_swapping() {
    const CHILD: &str = "BUSBAR_ADMIN_CONFIG_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root config boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "usage");
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-config-boundaries");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": {  },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .core_store_handle()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD
        .keep_in_store(boot_calls, 101)
        .expect("actual rate history binds once");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let hook = json::from_value(&json::json!({"kind": "gate", "module": "test-hook"})).unwrap();

    app.hook_registry.insert("existing".into(), hook);
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(
        app.governance
            .as_ref()
            .expect("actual governance")
            .core_store_handle()
            .expect("actual store calls"),
    )
    .expect("the actual Store supports overlay transactions");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
        crate::root::real_store::hydrated(Arc::new(app)).await,
        1 << 20,
        0,
        false,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("admin listener");
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let client = reqwest::Client::new();
    let before = handle.load();
    let cfg = json::json!({"kind": "gate", "module": "test-hook", "timeout_ms": u64::MAX});
    let register = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .json(&json::json!({"name": "new", "config": cfg}))
        .send()
        .await
        .unwrap();
    assert_eq!(register.status(), StatusCode::BAD_REQUEST);
    let put = client
        .put(format!("http://{addr}/api/v1/admin/hooks/existing"))
        .json(&json::json!({"config": cfg}))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    for response in [register, put] {
        let body = response.bytes().await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("timeout_ms") && text.contains("30 years"),
            "{text}"
        );
    }
    assert!(Arc::ptr_eq(&before, &handle.load()));
    assert!(!handle.load().hook_registry.contains_key("new"));
    assert!(overlay.read_required_async().await.unwrap().is_none());
    server.abort();
    println!("{WITNESS}");
}
#[tokio::test]
async fn reload_refuses_env_policy_injection_without_publishing() {
    const CHILD: &str = "BUSBAR_ADMIN_CONFIG_BOUNDARY_CHILD";
    const WITNESS: &str = "actual root config boundary assertions completed";
    isolated!(CHILD, WITNESS, witness = "usage");
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-config-boundaries");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": {  },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::hearing(
        crate::root::connector::dest_judge(&config),
    )) as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .core_store_handle()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD
        .keep_in_store(boot_calls, 101)
        .expect("actual rate history binds once");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    const VAR: &str = "BUSBAR_TEST_KC_ADMIN_POLICY_TTL";
    std::env::set_var(VAR, r#"90d"}, policy: {self_mint: true, max_ttl: "90d"#);
    let dir = plugins::scratch("admin-env-policy-source");
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&providers_path, "{}\n").unwrap();
    std::fs::write(&config_path, r#"{providers: {}, models: {}, store: {module: memory}, auth: {policy: {self_mint: false, max_ttl: "${BUSBAR_TEST_KC_ADMIN_POLICY_TTL}"}}}"#).unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(
        app.governance
            .as_ref()
            .expect("actual governance")
            .core_store_handle()
            .expect("actual store calls"),
    )
    .expect("the actual Store supports overlay transactions");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
        crate::root::real_store::hydrated(Arc::new(app)).await,
        1 << 20,
        0,
        false,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("admin listener");
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let client = reqwest::Client::new();
    let before = handle.load();
    let response = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.bytes().await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains(VAR) && text.contains("refusing to proceed"),
        "{text}"
    );
    assert!(Arc::ptr_eq(&before, &handle.load()));
    let _ = std::fs::remove_dir_all(dir);
    server.abort();
    println!("{WITNESS}");
}
