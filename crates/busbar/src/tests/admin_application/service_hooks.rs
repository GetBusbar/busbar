// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_core_admin::v1::{
    contract::AdminError,
    service::{build_with_hook, build_without_hook},
};
use busbar_kernel::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use std::path::PathBuf;
use std::sync::Arc;

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
async fn build_with_hook_registers_and_wires_global_tap() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    assert_eq!(app.tap_hooks.len(), 0, "fixture starts with no taps");
    let next = build_with_hook(&app, "logger", hook(&hook_module, HookKind::Tap, true))
        .expect("a valid global tap registers");
    assert!(next.hook_registry.contains_key("logger"));
    assert!(
        next.global_hooks.iter().any(|n| n == "logger"),
        "global tap wired into global_hooks"
    );
    assert_eq!(
        next.tap_hooks.len(),
        1,
        "the global tap re-resolved into the fired tap transports (live after swap)"
    );

    assert!(
        std::sync::Arc::ptr_eq(&app.store, &next.store),
        "the store (live breaker state) is preserved across the apply, not re-indexed"
    );
}

#[tokio::test]
async fn build_with_hook_demotes_global_false_removes_wiring() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");

    let promoted = build_with_hook(&app, "logger", hook(&hook_module, HookKind::Tap, true))
        .expect("global tap registers");
    assert!(promoted.global_hooks.iter().any(|n| n == "logger"));
    assert_eq!(promoted.tap_hooks.len(), 1, "global tap is live");

    let demoted = build_with_hook(
        &promoted,
        "logger",
        hook(&hook_module, HookKind::Tap, false),
    )
    .expect("demotion to global: false is a valid same-grant replace");
    assert!(
        !demoted.global_hooks.iter().any(|n| n == "logger"),
        "a global: false PUT must REMOVE the hook from global_hooks, not leave it firing"
    );
    assert_eq!(
        demoted.tap_hooks.len(),
        0,
        "the demoted hook must drop out of the fired global tap transports"
    );
    assert!(
        demoted.hook_registry.contains_key("logger"),
        "the hook definition itself survives — only its global membership is dropped"
    );
}

#[tokio::test]
async fn build_with_hook_caps_oversized_name() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    let huge = "n".repeat(256 + 1);
    assert!(
        matches!(
            build_with_hook(&app, &huge, hook(&hook_module, HookKind::Tap, false)),
            Err(AdminError::Validation(_))
        ),
        "a name over the cap must reject"
    );

    let at_cap = "n".repeat(256);
    assert!(build_with_hook(&app, &at_cap, hook(&hook_module, HookKind::Tap, false)).is_ok());
}

#[tokio::test]
async fn build_with_hook_rejects_invalid_definitions() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    let mut rw_tap = hook(&hook_module, HookKind::Tap, false);
    rw_tap.prompt = PromptAccess::Rw;
    assert!(matches!(
        build_with_hook(&app, "t", rw_tap),
        Err(AdminError::Validation(_))
    ));

    let mut no_transport = hook(&hook_module, HookKind::Gate, false);
    no_transport.plugin = String::new();
    assert!(matches!(
        build_with_hook(&app, "x", no_transport),
        Err(AdminError::Validation(_))
    ));

    let empty_name = hook(&hook_module, HookKind::Gate, false);
    assert!(matches!(
        build_with_hook(&app, "  ", empty_name),
        Err(AdminError::Validation(_))
    ));
}

#[tokio::test]
async fn build_with_hook_enforces_grant_immutability() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");

    let after_first =
        build_with_hook(&app, "g", hook(&hook_module, HookKind::Gate, false)).unwrap();

    let mut escalated = hook(&hook_module, HookKind::Gate, false);
    escalated.prompt = PromptAccess::Rw;
    assert!(
        matches!(
            build_with_hook(&after_first, "g", escalated),
            Err(AdminError::Conflict(_))
        ),
        "widening a grant in place must be a conflict"
    );

    assert!(
        build_with_hook(&after_first, "g", hook(&hook_module, HookKind::Gate, false)).is_ok(),
        "re-registering with identical grants is allowed"
    );
}

#[tokio::test]
async fn build_with_hook_reregistering_same_global_hook_does_not_duplicate() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    let once = build_with_hook(&app, "logger", hook(&hook_module, HookKind::Tap, true))
        .expect("first global registration");
    assert_eq!(
        once.global_hooks.iter().filter(|n| *n == "logger").count(),
        1
    );

    let twice = build_with_hook(&once, "logger", hook(&hook_module, HookKind::Tap, true))
        .expect("idempotent re-register with identical grants");
    assert_eq!(
        twice.global_hooks.iter().filter(|n| *n == "logger").count(),
        1,
        "re-registering the same global hook must not duplicate its global_hooks entry"
    );
}

#[tokio::test]
async fn build_with_hook_demote_only_removes_the_target_hook() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    let mut other = hook(&hook_module, HookKind::Tap, true);
    other.plugin = hook_module.clone();
    let with_both = build_with_hook(&app, "logger", hook(&hook_module, HookKind::Tap, true))
        .and_then(|a| build_with_hook(&a, "other", other))
        .expect("two global taps register");
    assert_eq!(with_both.global_hooks.len(), 2);

    let demoted = build_with_hook(
        &with_both,
        "logger",
        hook(&hook_module, HookKind::Tap, false),
    )
    .expect("demoting one of the two is a valid same-grant replace");
    assert!(
        !demoted.global_hooks.iter().any(|n| n == "logger"),
        "the demoted hook must be removed"
    );
    assert!(
        demoted.global_hooks.iter().any(|n| n == "other"),
        "the OTHER global hook must survive the demotion untouched"
    );
}

#[tokio::test]
async fn build_without_hook_only_removes_the_target_from_global_wiring() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");
    let mut other = hook(&hook_module, HookKind::Tap, true);
    other.plugin = hook_module.clone();
    let with_both = build_with_hook(&app, "logger", hook(&hook_module, HookKind::Tap, true))
        .and_then(|a| build_with_hook(&a, "other", other))
        .expect("two global taps register");

    let next = build_without_hook(&with_both, "logger").expect("delete an existing hook");
    assert!(!next.hook_registry.contains_key("logger"));
    assert!(
        !next.global_hooks.iter().any(|n| n == "logger"),
        "the deleted hook must be removed from global wiring"
    );
    assert!(
        next.global_hooks.iter().any(|n| n == "other"),
        "the OTHER global hook must survive the deletion untouched"
    );
}

#[tokio::test]
async fn build_with_hook_caps_oversized_settings() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "admin-service-hooks-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": store_module.as_ref().expect("the actual Store was staged"), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(
        &app,
        store_module
            .as_deref()
            .expect("the actual Store was staged"),
    )
    .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let hook_module = hook_module.expect("the actual hook was staged");

    let mut too_many = hook(&hook_module, HookKind::Tap, false);
    for i in 0..=256 {
        too_many
            .settings
            .insert(format!("k{i}"), serde_json::json!(1));
    }
    assert!(
        matches!(
            build_with_hook(&app, "big", too_many),
            Err(AdminError::Validation(_))
        ),
        "a settings map over the key cap must reject at register/PUT, not just PATCH"
    );

    let mut too_big = hook(&hook_module, HookKind::Tap, false);
    too_big.settings.insert(
        "blob".to_string(),
        serde_json::json!("x".repeat((64 * 1024) + 1)),
    );
    assert!(matches!(
        build_with_hook(&app, "big", too_big),
        Err(AdminError::Validation(_))
    ));

    let mut ok = hook(&hook_module, HookKind::Tap, false);
    ok.settings.insert(
        "url".to_string(),
        serde_json::json!("http://127.0.0.1:1/hook"),
    );
    assert!(build_with_hook(&app, "fine", ok).is_ok());
}
