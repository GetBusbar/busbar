// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::{
    v1::service::{build_with_hook, build_without_hook},
    AppAdmin,
};
use busbar_kernel::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use std::path::PathBuf;
use std::sync::Arc;
use crate::root::test_plugins as plugins;

fn hook(module: &str, kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: module.to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::from_value(serde_json::json!({"url":"http://127.0.0.1:1/hook"}))
            .unwrap(),
        at: None,
        on_empty: None,
        global,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

#[tokio::test]
async fn hook_snapshot_builders_recompute_the_content_gate() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hook-probe-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let mut store_module = None;
    let mut hook_module = None;
    for (kind, variable) in [
        ("store", "BUSBAR_TEST_SQLITE_CDYLIB"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        let path = if kind == "store" {
            crate::root::test_plugins::application_store_library()
        } else {
            PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
                panic!(
                    "{variable} must name the actual built product cdylib; this test never skips"
                )
            }))
        };
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual product statement reads")
            .expect("the actual product exports its statement");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual product statement is valid");
        let mut manifest = plugins::manifest(
            kind,
            &facts.name,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(facts.name);
        } else {
            store_module = Some(facts.name);
        }
        let library = std::fs::read(&path).expect("the actual product library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join(format!("{kind}-product.tar.gz")), archive)
            .expect("stage the signed actual product archive");
    }
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").expect("write the operator token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the signing input");
    let operator = busbar_kernel::config::operator_provider();
    let store_module = store_module.expect("the actual Store was staged");
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": store_module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::new(calls)
            .expect("the actual Store supports its config overlay"),
    );
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    assert!(
        !app.any_content_hook,
        "a deployment with no hooks grants no content"
    );

    let mut granted = hook(&hook_module, HookKind::Tap, true);
    granted.prompt = PromptAccess::Ro;
    let registered = build_with_hook(&app, "screener", granted.clone()).expect("registers");
    assert!(
        registered.any_content_hook,
        "registering a `prompt: ro` hook must open the gate"
    );
    registered.record_version("operator", "retain the granted hook for config rollback");

    let deleted = build_without_hook(&registered, "screener").expect("deletes");
    assert!(
        !deleted.any_content_hook,
        "deleting the last granted hook must close the gate"
    );

    let (router, handle) = busbar_kernel::build_router_with_limits(
        Arc::new(deleted),
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        busbar_kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"version": registered.config_version}))
        .send()
        .await
        .expect("the actual rollback endpoint responds");
    let status = response.status();
    let body: serde_json::Value = response.json().await.expect("rollback returns JSON");
    assert_eq!(status.as_u16(), 200, "rollback: {body}");
    assert_eq!(body["restored_version"], registered.config_version);
    let rolled_back = handle.load();
    assert_eq!(
        serde_json::to_value(&rolled_back.hook_registry["screener"]).unwrap(),
        serde_json::to_value(granted).unwrap()
    );
    assert_eq!(rolled_back.global_hooks, vec!["screener".to_string()]);
    assert!(
        rolled_back.any_content_hook,
        "a rolled-back snapshot's gate must match the registry it installed"
    );
    server.abort();
}

#[tokio::test]
async fn hook_derived_fields_follow_the_registry() {
    fn assert_hook_derived(app: &busbar_kernel::state::App, ctx: &str) {
        assert_eq!(
            app.any_content_hook,
            busbar_kernel::hooks::any_content_hook(&app.hook_registry),
            "{ctx}: `any_content_hook` disagrees with the registry the snapshot installed"
        );
        assert_eq!(
            app.requested_signals,
            busbar_kernel::hooks::requested_signals(&app.hook_registry),
            "{ctx}: `requested_signals` disagrees with the registry the snapshot installed — a \
             hook's `signals:` declaration did not take effect on the snapshot that installed it"
        );
    }

    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hook-probe-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let mut store_module = None;
    let mut hook_module = None;
    for (kind, variable) in [
        ("store", "BUSBAR_TEST_SQLITE_CDYLIB"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        let path = if kind == "store" {
            crate::root::test_plugins::application_store_library()
        } else {
            PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
                panic!(
                    "{variable} must name the actual built product cdylib; this test never skips"
                )
            }))
        };
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual product statement reads")
            .expect("the actual product exports its statement");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual product statement is valid");
        let mut manifest = plugins::manifest(
            kind,
            &facts.name,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(facts.name);
        } else {
            store_module = Some(facts.name);
        }
        let library = std::fs::read(&path).expect("the actual product library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join(format!("{kind}-product.tar.gz")), archive)
            .expect("stage the signed actual product archive");
    }
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").expect("write the operator token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the signing input");
    let operator = busbar_kernel::config::operator_provider();
    let store_module = store_module.expect("the actual Store was staged");
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": store_module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::new(calls)
            .expect("the actual Store supports its config overlay"),
    );
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    assert_hook_derived(&app, "boot deployment");

    let mut declaring = hook(&hook_module, HookKind::Tap, true);
    declaring.prompt = PromptAccess::Ro;
    declaring.signals = vec![busbar_contract::signal::Signal::CandidateBreakerState];

    let registered = build_with_hook(&app, "declarer", declaring.clone()).expect("registers");
    assert_hook_derived(&registered, "after build_with_hook (POST/PUT /hooks)");
    assert!(
        registered
            .requested_signals
            .wants(busbar_contract::signal::Signal::CandidateBreakerState),
        "registering a hook that declares `candidate.breaker_state` must open the compute gate for \
         the very next request"
    );
    registered.record_version("operator", "retain the declaring hook for config rollback");

    let deleted = build_without_hook(&registered, "declarer").expect("deletes");
    assert_hook_derived(&deleted, "after build_without_hook (DELETE /hooks/{name})");
    assert!(
        deleted.requested_signals.is_empty(),
        "deleting the last declaring hook must close the compute gate again"
    );

    let (router, handle) = busbar_kernel::build_router_with_limits(
        Arc::new(deleted),
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        busbar_kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"version": registered.config_version}))
        .send()
        .await
        .expect("the actual rollback endpoint responds");
    let status = response.status();
    let body: serde_json::Value = response.json().await.expect("rollback returns JSON");
    assert_eq!(status.as_u16(), 200, "rollback: {body}");
    assert_eq!(body["restored_version"], registered.config_version);
    let rolled_back = handle.load();
    assert_eq!(
        serde_json::to_value(&rolled_back.hook_registry["declarer"]).unwrap(),
        serde_json::to_value(declaring).unwrap()
    );
    assert_eq!(rolled_back.global_hooks, vec!["declarer".to_string()]);
    assert_hook_derived(&rolled_back, "after build_with_registry (config rollback)");
    server.abort();
}

#[tokio::test]
async fn probe_transport_distinguishes_wrong_kind_from_unresolved() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hook-probe-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let mut store_module = None;
    let mut hook_module = None;
    for (kind, variable) in [
        ("store", "BUSBAR_TEST_SQLITE_CDYLIB"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        let path = if kind == "store" {
            crate::root::test_plugins::application_store_library()
        } else {
            PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
                panic!(
                    "{variable} must name the actual built product cdylib; this test never skips"
                )
            }))
        };
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual product statement reads")
            .expect("the actual product exports its statement");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual product statement is valid");
        let mut manifest = plugins::manifest(
            kind,
            &facts.name,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(facts.name);
        } else {
            store_module = Some(facts.name);
        }
        let library = std::fs::read(&path).expect("the actual product library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join(format!("{kind}-product.tar.gz")), archive)
            .expect("stage the signed actual product archive");
    }
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").expect("write the operator token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the signing input");
    let operator = busbar_kernel::config::operator_provider();
    let store_module = store_module.expect("the actual Store was staged");
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": store_module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::new(calls)
            .expect("the actual Store supports its config overlay"),
    );
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    let hook_cfg = hook(&hook_module, HookKind::Tap, false);
    let mut app = build_with_hook(&app, "wired", hook_cfg.clone())
        .expect("the actual hook transport registers");

    let mut wrong_kind = hook_cfg.clone();
    wrong_kind.plugin = store_module.clone();
    app.hook_registry.insert("wrong-kind".into(), wrong_kind);

    let mut missing = hook_cfg;
    missing.plugin = "totally-unregistered-plugin-name".to_string();
    app.hook_registry.insert("missing".into(), missing);

    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let response = client
        .get(format!("http://{addr}/api/v1/admin/hooks/wired/health"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let wired: serde_json::Value = response.json().await.unwrap();
    assert_eq!(wired["reachable"], true);
    assert_eq!(wired["detail"], serde_json::Value::Null);

    let response = client
        .get(format!(
            "http://{addr}/api/v1/admin/hooks/wrong-kind/health"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let wrong_kind: serde_json::Value = response.json().await.unwrap();
    assert_eq!(wrong_kind["reachable"], false);
    let detail = wrong_kind["detail"].as_str();
    assert!(
        detail.is_some_and(|d| d.contains(&store_module)
            && d.contains("store")
            && d.contains("hook")),
        "wrong-kind resolution must name both the resolved kind and the expected kind: {detail:?}"
    );

    let response = client
        .get(format!("http://{addr}/api/v1/admin/hooks/missing/health"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let missing: serde_json::Value = response.json().await.unwrap();
    assert_eq!(missing["reachable"], false);
    let detail = missing["detail"].as_str();
    assert!(
        detail.is_some_and(|d| d.contains("is not installed")),
        "unresolved plugin must say so distinctly: {detail:?}"
    );
    server.abort();
}
